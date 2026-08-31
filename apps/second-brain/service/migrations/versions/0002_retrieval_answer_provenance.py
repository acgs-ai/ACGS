"""Persist selected retrieval evidence and validated answer provenance.

Revision ID: 0002_retrieval_answer_provenance
Revises: 0001_foundation
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002_retrieval_answer_provenance"
down_revision: str | None = "0001_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE retrieval_runs
            ADD COLUMN semantic_status text NOT NULL DEFAULT 'unavailable'
                CHECK (semantic_status IN ('available','unavailable')),
            ADD COLUMN request_fingerprint char(64),
            ADD COLUMN idempotency_key text;
        ALTER TABLE retrieval_runs
            ADD CONSTRAINT retrieval_runs_scoped_idempotency_unique
            UNIQUE (owner_id, workspace_id, idempotency_key);

        ALTER TABLE retrieval_results
            ADD COLUMN source_id uuid,
            ADD COLUMN source_version_id uuid,
            ADD COLUMN selected boolean NOT NULL DEFAULT false,
            ADD COLUMN evidence_ordinal integer,
            ADD COLUMN evidence_text text,
            ADD COLUMN evidence_char_start integer,
            ADD COLUMN evidence_char_end integer;

        UPDATE retrieval_results AS result
        SET source_version_id=chunk.source_version_id,
            source_id=version.source_id
        FROM chunks AS chunk
        JOIN source_versions AS version ON version.id=chunk.source_version_id
        WHERE chunk.id=result.chunk_id;

        WITH cited AS (
            SELECT DISTINCT result.id,result.retrieval_run_id,result.fused_rank,result.chunk_id,
                row_number() OVER (
                    PARTITION BY result.retrieval_run_id
                    ORDER BY result.fused_rank,result.chunk_id
                ) AS evidence_ordinal
            FROM retrieval_results AS result
            JOIN citations AS citation ON citation.retrieval_result_id=result.id
        )
        UPDATE retrieval_results AS result
        SET selected=true,
            evidence_ordinal=cited.evidence_ordinal,
            evidence_text=chunk.chunk_text,
            evidence_char_start=chunk.char_start,
            evidence_char_end=chunk.char_end
        FROM cited
        JOIN chunks AS chunk ON chunk.id=cited.chunk_id
        WHERE result.id=cited.id;

        ALTER TABLE chunks
            ADD CONSTRAINT chunks_id_version_scope_unique
            UNIQUE (id,source_version_id,owner_id,workspace_id);
        ALTER TABLE retrieval_results
            ALTER COLUMN source_id SET NOT NULL,
            ALTER COLUMN source_version_id SET NOT NULL,
            ADD CONSTRAINT retrieval_results_evidence_bounds CHECK (
                (selected = false AND evidence_text IS NULL
                    AND evidence_ordinal IS NULL AND evidence_char_start IS NULL
                    AND evidence_char_end IS NULL)
                OR (selected = true AND evidence_text IS NOT NULL
                    AND evidence_ordinal IS NOT NULL AND evidence_ordinal > 0
                    AND evidence_char_start IS NOT NULL
                    AND evidence_char_end IS NOT NULL
                    AND evidence_char_start >= 0
                    AND evidence_char_end >= evidence_char_start)
            ),
            ADD CONSTRAINT retrieval_results_source_version_fk
                FOREIGN KEY (source_version_id, source_id, owner_id, workspace_id)
                REFERENCES source_versions(id, source_id, owner_id, workspace_id)
                ON DELETE RESTRICT,
            ADD CONSTRAINT retrieval_results_chunk_version_fk
                FOREIGN KEY (chunk_id,source_version_id,owner_id,workspace_id)
                REFERENCES chunks(id,source_version_id,owner_id,workspace_id)
                ON DELETE RESTRICT,
            ADD CONSTRAINT retrieval_results_exact_evidence_unique
                UNIQUE (
                    id,retrieval_run_id,chunk_id,source_id,source_version_id,evidence_ordinal,
                    evidence_char_start,evidence_char_end,owner_id,workspace_id
                );
        CREATE UNIQUE INDEX retrieval_results_selected_ordinal_unique
            ON retrieval_results (retrieval_run_id,evidence_ordinal)
            WHERE selected=true;

        ALTER TABLE answers DROP CONSTRAINT answers_status_check;
        ALTER TABLE answers
            ADD CONSTRAINT answers_status_check CHECK (
                status IN (
                    'grounded','insufficient_evidence','validation_failed','provider_unavailable'
                )
            ),
            ADD COLUMN sufficiency jsonb NOT NULL
                DEFAULT jsonb_build_object(
                    'sufficient',false,'reason_code','not_evaluated'
                ),
            ADD COLUMN system_commentary text,
            ADD COLUMN extractive_fallback jsonb,
            ADD COLUMN provider_status text NOT NULL DEFAULT 'not_called'
                CHECK (provider_status IN ('available','unavailable','not_called'));

        ALTER TABLE citations
            ADD COLUMN source_id uuid,
            ADD COLUMN source_version_id uuid,
            ADD COLUMN statement_id uuid,
            ADD COLUMN statement_index integer,
            ADD COLUMN evidence_ordinal integer,
            ADD COLUMN char_start integer,
            ADD COLUMN char_end integer;

        UPDATE citations AS citation
        SET source_id=result.source_id,
            source_version_id=result.source_version_id,
            statement_id=gen_random_uuid(),
            statement_index=0,
            evidence_ordinal=result.evidence_ordinal,
            char_start=result.evidence_char_start,
            char_end=result.evidence_char_end,
            validated=true
        FROM retrieval_results AS result
        WHERE result.id=citation.retrieval_result_id;

        ALTER TABLE citations
            DROP CONSTRAINT citations_answer_id_chunk_id_key,
            ALTER COLUMN source_id SET NOT NULL,
            ALTER COLUMN source_version_id SET NOT NULL,
            ALTER COLUMN statement_id SET NOT NULL,
            ALTER COLUMN statement_index SET NOT NULL,
            ALTER COLUMN evidence_ordinal SET NOT NULL,
            ALTER COLUMN char_start SET NOT NULL,
            ALTER COLUMN char_end SET NOT NULL,
            ADD CONSTRAINT citations_bounds CHECK (
                char_start >= 0 AND char_end >= char_start
                AND statement_index >= 0 AND evidence_ordinal > 0
            ),
            ADD CONSTRAINT citations_validated_check CHECK (validated=true),
            ADD CONSTRAINT citations_answer_statement_chunk_unique
                UNIQUE (answer_id,statement_index,chunk_id),
            ADD CONSTRAINT citations_exact_retrieval_result_fk
                FOREIGN KEY (
                    retrieval_result_id,retrieval_run_id,chunk_id,source_id,source_version_id,
                    evidence_ordinal,char_start,char_end,owner_id,workspace_id
                ) REFERENCES retrieval_results(
                    id,retrieval_run_id,chunk_id,source_id,source_version_id,evidence_ordinal,
                    evidence_char_start,evidence_char_end,owner_id,workspace_id
                ) ON DELETE RESTRICT;

        CREATE FUNCTION public.enforce_selected_retrieval_result_current()
        RETURNS trigger LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF NEW.selected AND NOT EXISTS (
                SELECT 1
                FROM public.source_versions AS version
                JOIN public.sources AS source ON source.id=version.source_id
                    AND source.owner_id=version.owner_id
                    AND source.workspace_id=version.workspace_id
                WHERE version.id=NEW.source_version_id
                    AND version.source_id=NEW.source_id
                    AND version.owner_id=NEW.owner_id
                    AND version.workspace_id=NEW.workspace_id
                    AND source.processing_state='ready'
                    AND source.deleted_at IS NULL
                    AND version.id=(
                        SELECT current_version.id
                        FROM public.source_versions AS current_version
                        WHERE current_version.source_id=source.id
                        ORDER BY current_version.version_number DESC,current_version.id ASC
                        LIMIT 1
                    )
            ) THEN
                RAISE EXCEPTION 'selected evidence is not current and accessible'
                    USING ERRCODE='23503';
            END IF;
            RETURN NEW;
        END;
        $$;
        REVOKE ALL ON FUNCTION public.enforce_selected_retrieval_result_current()
            FROM PUBLIC;
        CREATE TRIGGER retrieval_results_current_guard
            BEFORE INSERT OR UPDATE ON public.retrieval_results
            FOR EACH ROW
            EXECUTE FUNCTION public.enforce_selected_retrieval_result_current();

        CREATE FUNCTION public.enforce_citation_current_evidence()
        RETURNS trigger LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM public.retrieval_results AS result
                JOIN public.source_versions AS version ON version.id=result.source_version_id
                    AND version.source_id=result.source_id
                    AND version.owner_id=result.owner_id
                    AND version.workspace_id=result.workspace_id
                JOIN public.sources AS source ON source.id=result.source_id
                    AND source.owner_id=result.owner_id
                    AND source.workspace_id=result.workspace_id
                WHERE result.id=NEW.retrieval_result_id
                    AND result.retrieval_run_id=NEW.retrieval_run_id
                    AND result.chunk_id=NEW.chunk_id
                    AND result.source_id=NEW.source_id
                    AND result.source_version_id=NEW.source_version_id
                    AND result.evidence_ordinal=NEW.evidence_ordinal
                    AND result.evidence_char_start=NEW.char_start
                    AND result.evidence_char_end=NEW.char_end
                    AND result.owner_id=NEW.owner_id
                    AND result.workspace_id=NEW.workspace_id
                    AND result.selected=true
                    AND source.processing_state='ready'
                    AND source.deleted_at IS NULL
                    AND version.id=(
                        SELECT current_version.id
                        FROM public.source_versions AS current_version
                        WHERE current_version.source_id=source.id
                        ORDER BY current_version.version_number DESC,current_version.id ASC
                        LIMIT 1
                    )
            ) THEN
                RAISE EXCEPTION 'citation evidence is not current and accessible'
                    USING ERRCODE='23503';
            END IF;
            RETURN NEW;
        END;
        $$;
        REVOKE ALL ON FUNCTION public.enforce_citation_current_evidence() FROM PUBLIC;
        CREATE TRIGGER citations_current_evidence_guard
            BEFORE INSERT OR UPDATE ON public.citations
            FOR EACH ROW EXECUTE FUNCTION public.enforce_citation_current_evidence();
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TRIGGER citations_current_evidence_guard ON public.citations;
        DROP FUNCTION public.enforce_citation_current_evidence();
        DROP TRIGGER retrieval_results_current_guard ON public.retrieval_results;
        DROP FUNCTION public.enforce_selected_retrieval_result_current();

        ALTER TABLE citations
            DROP CONSTRAINT citations_exact_retrieval_result_fk,
            DROP CONSTRAINT citations_answer_statement_chunk_unique,
            DROP CONSTRAINT citations_validated_check,
            DROP CONSTRAINT citations_bounds;
        DELETE FROM citations AS duplicate
        USING citations AS retained
        WHERE duplicate.answer_id=retained.answer_id
            AND duplicate.chunk_id=retained.chunk_id
            AND duplicate.id>retained.id;
        ALTER TABLE citations
            ADD CONSTRAINT citations_answer_id_chunk_id_key UNIQUE (answer_id,chunk_id),
            DROP COLUMN char_end,
            DROP COLUMN char_start,
            DROP COLUMN evidence_ordinal,
            DROP COLUMN statement_index,
            DROP COLUMN statement_id,
            DROP COLUMN source_version_id,
            DROP COLUMN source_id;

        UPDATE answers SET status='validation_failed' WHERE status='provider_unavailable';
        ALTER TABLE answers
            DROP CONSTRAINT answers_status_check,
            DROP CONSTRAINT answers_provider_status_check,
            DROP COLUMN provider_status,
            DROP COLUMN extractive_fallback,
            DROP COLUMN system_commentary,
            DROP COLUMN sufficiency;
        ALTER TABLE answers
            ADD CONSTRAINT answers_status_check CHECK (
                status IN ('grounded','insufficient_evidence','validation_failed')
            );

        DROP INDEX retrieval_results_selected_ordinal_unique;
        ALTER TABLE retrieval_results
            DROP CONSTRAINT retrieval_results_exact_evidence_unique,
            DROP CONSTRAINT retrieval_results_chunk_version_fk,
            DROP CONSTRAINT retrieval_results_source_version_fk,
            DROP CONSTRAINT retrieval_results_evidence_bounds,
            DROP COLUMN evidence_ordinal,
            DROP COLUMN evidence_char_end,
            DROP COLUMN evidence_char_start,
            DROP COLUMN evidence_text,
            DROP COLUMN selected,
            DROP COLUMN source_version_id,
            DROP COLUMN source_id;
        ALTER TABLE chunks DROP CONSTRAINT chunks_id_version_scope_unique;

        ALTER TABLE retrieval_runs
            DROP CONSTRAINT retrieval_runs_scoped_idempotency_unique,
            DROP COLUMN idempotency_key,
            DROP COLUMN request_fingerprint,
            DROP COLUMN semantic_status;
        """
    )
