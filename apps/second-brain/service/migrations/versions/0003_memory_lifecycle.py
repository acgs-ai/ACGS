"""Add explicit append-oriented memory lifecycle and exact evidence lineage.

Revision ID: 0003_memory_lifecycle
Revises: 0002_retrieval_answer_provenance
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003_memory_lifecycle"
down_revision: str | None = "0002_retrieval_answer_provenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE public.memory_proposals
            ADD COLUMN confidence double precision NOT NULL DEFAULT 0.5
                CHECK (confidence BETWEEN 0 AND 1),
            ADD COLUMN evidence_quality_label text NOT NULL DEFAULT 'medium'
                CHECK (evidence_quality_label IN ('low','medium','high')),
            ADD CONSTRAINT memory_proposals_statement_nonempty
                CHECK (length(btrim(normalized_statement)) BETWEEN 1 AND 4000),
            ADD CONSTRAINT memory_proposals_category_check CHECK (
                category IN (
                    'fact','preference','commitment','project_fact','person_fact','reference','other'
                )
            );

        ALTER TABLE public.memory_proposal_evidence
            ADD COLUMN source_id uuid,
            ADD COLUMN source_version_id uuid;
        UPDATE public.memory_proposal_evidence AS evidence
        SET source_version_id=chunk.source_version_id,
            source_id=version.source_id
        FROM public.chunks AS chunk
        JOIN public.source_versions AS version ON version.id=chunk.source_version_id
        WHERE chunk.id=evidence.chunk_id;
        ALTER TABLE public.memory_proposal_evidence
            ALTER COLUMN source_id SET NOT NULL,
            ALTER COLUMN source_version_id SET NOT NULL,
            ADD CONSTRAINT memory_proposal_evidence_source_version_fk
                FOREIGN KEY (source_version_id,source_id,owner_id,workspace_id)
                REFERENCES public.source_versions(id,source_id,owner_id,workspace_id)
                ON DELETE RESTRICT,
            ADD CONSTRAINT memory_proposal_evidence_exact_chunk_fk
                FOREIGN KEY (chunk_id,source_version_id,owner_id,workspace_id)
                REFERENCES public.chunks(id,source_version_id,owner_id,workspace_id)
                ON DELETE RESTRICT;

        ALTER TABLE public.memory_revisions
            ADD COLUMN category text,
            ADD COLUMN confidence double precision,
            ADD COLUMN evidence_quality_label text,
            ADD COLUMN created_by uuid;
        UPDATE public.memory_revisions AS revision
        SET category=proposal.category,
            confidence=proposal.confidence,
            evidence_quality_label=proposal.evidence_quality_label,
            created_by=revision.owner_id
        FROM public.approved_memories AS memory
        JOIN public.memory_proposals AS proposal ON proposal.id=memory.proposal_id
        WHERE memory.id=revision.memory_id;
        ALTER TABLE public.memory_revisions
            ALTER COLUMN category SET NOT NULL,
            ALTER COLUMN confidence SET NOT NULL,
            ALTER COLUMN evidence_quality_label SET NOT NULL,
            ALTER COLUMN created_by SET NOT NULL,
            ADD CONSTRAINT memory_revisions_statement_nonempty
                CHECK (length(btrim(normalized_statement)) BETWEEN 1 AND 4000),
            ADD CONSTRAINT memory_revisions_category_check CHECK (
                category IN (
                    'fact','preference','commitment','project_fact','person_fact','reference','other'
                )
            ),
            ADD CONSTRAINT memory_revisions_confidence_check
                CHECK (confidence BETWEEN 0 AND 1),
            ADD CONSTRAINT memory_revisions_evidence_quality_check
                CHECK (evidence_quality_label IN ('low','medium','high')),
            ADD CONSTRAINT memory_revisions_created_by_fk
                FOREIGN KEY (workspace_id,created_by)
                REFERENCES public.workspace_memberships(workspace_id,user_id)
                ON DELETE RESTRICT;

        ALTER TABLE public.memory_revision_evidence
            ADD COLUMN source_id uuid,
            ADD COLUMN source_version_id uuid;
        UPDATE public.memory_revision_evidence AS evidence
        SET source_version_id=chunk.source_version_id,
            source_id=version.source_id
        FROM public.chunks AS chunk
        JOIN public.source_versions AS version ON version.id=chunk.source_version_id
        WHERE chunk.id=evidence.chunk_id;
        ALTER TABLE public.memory_revision_evidence
            ALTER COLUMN source_id SET NOT NULL,
            ALTER COLUMN source_version_id SET NOT NULL,
            ADD CONSTRAINT memory_revision_evidence_source_version_fk
                FOREIGN KEY (source_version_id,source_id,owner_id,workspace_id)
                REFERENCES public.source_versions(id,source_id,owner_id,workspace_id)
                ON DELETE RESTRICT,
            ADD CONSTRAINT memory_revision_evidence_exact_chunk_fk
                FOREIGN KEY (chunk_id,source_version_id,owner_id,workspace_id)
                REFERENCES public.chunks(id,source_version_id,owner_id,workspace_id)
                ON DELETE RESTRICT;

        ALTER TABLE public.approved_memories
            ADD COLUMN supersedes_memory_id uuid,
            ADD CONSTRAINT approved_memories_supersedes_fk
                FOREIGN KEY (supersedes_memory_id,owner_id,workspace_id)
                REFERENCES public.approved_memories(id,owner_id,workspace_id)
                ON DELETE RESTRICT,
            ADD CONSTRAINT approved_memories_distinct_supersession
                CHECK (supersedes_memory_id IS NULL OR supersedes_memory_id <> id);

        CREATE FUNCTION public.derive_memory_revision_metadata()
        RETURNS trigger LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF NEW.category IS NULL OR NEW.confidence IS NULL
                OR NEW.evidence_quality_label IS NULL OR NEW.created_by IS NULL
            THEN
                SELECT COALESCE(NEW.category,proposal.category),
                    COALESCE(NEW.confidence,proposal.confidence),
                    COALESCE(NEW.evidence_quality_label,proposal.evidence_quality_label),
                    COALESCE(NEW.created_by,NEW.owner_id)
                INTO NEW.category,NEW.confidence,NEW.evidence_quality_label,NEW.created_by
                FROM public.approved_memories AS memory
                JOIN public.memory_proposals AS proposal ON proposal.id=memory.proposal_id
                WHERE memory.id=NEW.memory_id
                    AND memory.owner_id=NEW.owner_id
                    AND memory.workspace_id=NEW.workspace_id;
            END IF;
            RETURN NEW;
        END;
        $$;
        REVOKE ALL ON FUNCTION public.derive_memory_revision_metadata() FROM PUBLIC;
        CREATE TRIGGER memory_revisions_derive_metadata
            BEFORE INSERT ON public.memory_revisions
            FOR EACH ROW EXECUTE FUNCTION public.derive_memory_revision_metadata();

        CREATE TABLE public.memory_actions (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            proposal_id uuid,
            memory_id uuid,
            action text NOT NULL CHECK (
                action IN (
                    'propose','approve','reject','edit_and_approve','revise','supersede',
                    'archive','purge_requested'
                )
            ),
            idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 200),
            request_fingerprint char(64) NOT NULL,
            result_resource_id uuid NOT NULL,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (id,owner_id,workspace_id),
            UNIQUE (owner_id,workspace_id,idempotency_key),
            FOREIGN KEY (workspace_id,owner_id)
                REFERENCES public.workspace_memberships(workspace_id,user_id)
                ON DELETE RESTRICT
        );

        GRANT UPDATE (supersedes_memory_id) ON public.approved_memories
            TO second_brain_app;
        CREATE INDEX memory_actions_resource_history_idx
            ON public.memory_actions(owner_id,workspace_id,result_resource_id,created_at,id);

        CREATE FUNCTION public.enforce_memory_evidence_current()
        RETURNS trigger LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF NEW.source_id IS NULL AND NEW.source_version_id IS NULL THEN
                SELECT version.source_id,version.id
                INTO NEW.source_id,NEW.source_version_id
                FROM public.chunks AS chunk
                JOIN public.source_versions AS version
                    ON version.id=chunk.source_version_id
                    AND version.owner_id=chunk.owner_id
                    AND version.workspace_id=chunk.workspace_id
                WHERE chunk.id=NEW.chunk_id
                    AND chunk.owner_id=NEW.owner_id
                    AND chunk.workspace_id=NEW.workspace_id;
            ELSIF NEW.source_id IS NULL OR NEW.source_version_id IS NULL THEN
                RAISE EXCEPTION 'memory evidence lineage must be complete'
                    USING ERRCODE='23503';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM public.chunks AS chunk
                JOIN public.source_versions AS version
                    ON version.id=chunk.source_version_id
                    AND version.owner_id=chunk.owner_id
                    AND version.workspace_id=chunk.workspace_id
                JOIN public.sources AS source
                    ON source.id=version.source_id
                    AND source.owner_id=version.owner_id
                    AND source.workspace_id=version.workspace_id
                WHERE chunk.id=NEW.chunk_id
                    AND chunk.source_version_id=NEW.source_version_id
                    AND chunk.owner_id=NEW.owner_id
                    AND chunk.workspace_id=NEW.workspace_id
                    AND version.source_id=NEW.source_id
                    AND source.processing_state='ready'
                    AND source.deleted_at IS NULL
                    AND version.id=(
                        SELECT current_version.id
                        FROM public.source_versions AS current_version
                        WHERE current_version.source_id=source.id
                        ORDER BY current_version.version_number DESC,current_version.id ASC
                        LIMIT 1
                    )
                FOR UPDATE OF source
            ) THEN
                RAISE EXCEPTION 'memory evidence is not current and accessible'
                    USING ERRCODE='23503';
            END IF;
            RETURN NEW;
        END;
        $$;
        REVOKE ALL ON FUNCTION public.enforce_memory_evidence_current() FROM PUBLIC;

        CREATE TRIGGER memory_proposal_evidence_current_guard
            BEFORE INSERT OR UPDATE ON public.memory_proposal_evidence
            FOR EACH ROW EXECUTE FUNCTION public.enforce_memory_evidence_current();
        CREATE TRIGGER memory_revision_evidence_current_guard
            BEFORE INSERT OR UPDATE ON public.memory_revision_evidence
            FOR EACH ROW EXECUTE FUNCTION public.enforce_memory_evidence_current();
        CREATE TRIGGER memory_actions_append_only
            BEFORE UPDATE OR DELETE ON public.memory_actions
            FOR EACH ROW EXECUTE FUNCTION public.reject_append_only_mutation();

        ALTER TABLE public.memory_actions ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.memory_actions FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_scope ON public.memory_actions
            USING (
                owner_id=nullif(current_setting('app.owner_id',true),'')::uuid
                AND workspace_id=nullif(current_setting('app.workspace_id',true),'')::uuid
            )
            WITH CHECK (
                owner_id=nullif(current_setting('app.owner_id',true),'')::uuid
                AND workspace_id=nullif(current_setting('app.workspace_id',true),'')::uuid
            );
        GRANT SELECT,INSERT ON public.memory_actions TO second_brain_app;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE ALL ON public.memory_actions FROM second_brain_app;
        DROP TABLE public.memory_actions;
        REVOKE UPDATE (supersedes_memory_id) ON public.approved_memories
            FROM second_brain_app;

        DROP TRIGGER memory_revision_evidence_current_guard
            ON public.memory_revision_evidence;
        DROP TRIGGER memory_proposal_evidence_current_guard
            ON public.memory_proposal_evidence;
        DROP FUNCTION public.enforce_memory_evidence_current();
        DROP TRIGGER memory_revisions_derive_metadata ON public.memory_revisions;
        DROP FUNCTION public.derive_memory_revision_metadata();

        ALTER TABLE public.approved_memories
            DROP CONSTRAINT approved_memories_distinct_supersession,
            DROP CONSTRAINT approved_memories_supersedes_fk,
            DROP COLUMN supersedes_memory_id;

        ALTER TABLE public.memory_revision_evidence
            DROP CONSTRAINT memory_revision_evidence_exact_chunk_fk,
            DROP CONSTRAINT memory_revision_evidence_source_version_fk,
            DROP COLUMN source_version_id,
            DROP COLUMN source_id;
        ALTER TABLE public.memory_revisions
            DROP CONSTRAINT memory_revisions_created_by_fk,
            DROP CONSTRAINT memory_revisions_evidence_quality_check,
            DROP CONSTRAINT memory_revisions_confidence_check,
            DROP CONSTRAINT memory_revisions_category_check,
            DROP CONSTRAINT memory_revisions_statement_nonempty,
            DROP COLUMN created_by,
            DROP COLUMN evidence_quality_label,
            DROP COLUMN confidence,
            DROP COLUMN category;

        ALTER TABLE public.memory_proposal_evidence
            DROP CONSTRAINT memory_proposal_evidence_exact_chunk_fk,
            DROP CONSTRAINT memory_proposal_evidence_source_version_fk,
            DROP COLUMN source_version_id,
            DROP COLUMN source_id;
        ALTER TABLE public.memory_proposals
            DROP CONSTRAINT memory_proposals_category_check,
            DROP CONSTRAINT memory_proposals_statement_nonempty,
            DROP COLUMN evidence_quality_label,
            DROP COLUMN confidence;
        """
    )
