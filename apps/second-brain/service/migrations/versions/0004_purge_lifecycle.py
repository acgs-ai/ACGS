"""Add durable two-phase source and memory purge lifecycle.

Revision ID: 0004_purge_lifecycle
Revises: 0003_memory_lifecycle
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004_purge_lifecycle"
down_revision: str | None = "0003_memory_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE public.sources DROP CONSTRAINT sources_processing_state_check;
        ALTER TABLE public.sources ADD CONSTRAINT sources_processing_state_check CHECK (
            processing_state IN (
                'queued','processing','ready','failed','purge_pending','purged'
            )
        );
        ALTER TABLE public.approved_memories
            DROP CONSTRAINT approved_memories_status_check;
        ALTER TABLE public.approved_memories
            ADD CONSTRAINT approved_memories_status_check CHECK (
                status IN ('active','superseded','archived','purge_pending','purged')
            );

        CREATE TABLE public.purge_operations (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            resource_type text NOT NULL CHECK (resource_type IN ('source','memory')),
            resource_id uuid NOT NULL,
            reason_code text NOT NULL CHECK (
                reason_code IN ('user_requested','privacy_request','retention_expired')
            ),
            idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 200),
            request_fingerprint char(64) NOT NULL,
            state text NOT NULL DEFAULT 'queued'
                CHECK (state IN ('queued','processing','complete','dead')),
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            lease_owner text,
            lease_expires_at timestamptz,
            error_class text CHECK (error_class IS NULL OR length(error_class) <= 100),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            finished_at timestamptz,
            UNIQUE (id,owner_id,workspace_id),
            UNIQUE (owner_id,workspace_id,idempotency_key),
            UNIQUE (owner_id,workspace_id,resource_type,resource_id),
            FOREIGN KEY (workspace_id,owner_id)
                REFERENCES public.workspace_memberships(workspace_id,user_id)
                ON DELETE RESTRICT,
            CHECK (
                (state='queued' AND lease_owner IS NULL AND lease_expires_at IS NULL
                    AND finished_at IS NULL)
                OR (state='processing' AND lease_owner IS NOT NULL
                    AND lease_expires_at IS NOT NULL AND finished_at IS NULL)
                OR (state IN ('complete','dead') AND lease_owner IS NULL
                    AND lease_expires_at IS NULL AND finished_at IS NOT NULL)
            )
        );
        CREATE INDEX purge_operations_claim_idx
            ON public.purge_operations(state,available_at,lease_expires_at,created_at,id);

        CREATE TABLE public.purge_operation_events (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            operation_id uuid NOT NULL,
            attempt integer NOT NULL CHECK (attempt >= 0),
            from_state text,
            to_state text NOT NULL CHECK (
                to_state IN ('queued','processing','complete','dead')
            ),
            reason_class text NOT NULL CHECK (length(reason_class) BETWEEN 1 AND 100),
            lease_owner text,
            occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (id,owner_id,workspace_id),
            FOREIGN KEY (operation_id,owner_id,workspace_id)
                REFERENCES public.purge_operations(id,owner_id,workspace_id)
                ON DELETE RESTRICT
        );

        CREATE TABLE public.memory_evidence_tombstones (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            memory_id uuid,
            proposal_id uuid,
            revision_id uuid,
            source_tombstone_id uuid NOT NULL,
            purged_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (id,owner_id,workspace_id),
            FOREIGN KEY (workspace_id,owner_id)
                REFERENCES public.workspace_memberships(workspace_id,user_id)
                ON DELETE RESTRICT
        );

        ALTER TABLE public.purge_records
            ADD COLUMN operation_id uuid,
            ADD COLUMN resource_type text,
            ADD COLUMN resource_id uuid;
        ALTER TABLE public.purge_records DISABLE TRIGGER purge_records_append_only;
        UPDATE public.purge_records SET reason_code='user_requested'
        WHERE reason_code NOT IN ('user_requested','privacy_request','retention_expired');
        UPDATE public.purge_records
        SET operation_id=gen_random_uuid(),resource_type='source',
            resource_id=COALESCE(source_id,source_tombstone_id);
        INSERT INTO public.purge_operations (
            id,owner_id,workspace_id,resource_type,resource_id,reason_code,
            idempotency_key,request_fingerprint,state,attempts,available_at,
            created_at,finished_at
        )
        SELECT record.operation_id,record.owner_id,record.workspace_id,'source',
            record.resource_id,record.reason_code,'legacy-purge-record-'||record.id::text,
            encode(digest('legacy-purge-record-'||record.id::text,'sha256'),'hex'),
            'complete',0,record.purged_at,record.purged_at,record.purged_at
        FROM public.purge_records AS record;
        ALTER TABLE public.purge_records ENABLE TRIGGER purge_records_append_only;
        ALTER TABLE public.purge_records
            ALTER COLUMN operation_id SET NOT NULL,
            ALTER COLUMN resource_type SET NOT NULL,
            ALTER COLUMN resource_id SET NOT NULL,
            ADD CONSTRAINT purge_records_resource_type_check
                CHECK (resource_type IN ('source','memory')),
            ADD CONSTRAINT purge_records_reason_code_check CHECK (
                reason_code IN ('user_requested','privacy_request','retention_expired')
            ),
            ADD CONSTRAINT purge_records_operation_unique UNIQUE (operation_id),
            ADD CONSTRAINT purge_records_operation_fk
                FOREIGN KEY (operation_id,owner_id,workspace_id)
                REFERENCES public.purge_operations(id,owner_id,workspace_id)
                ON DELETE RESTRICT;

        CREATE TRIGGER purge_operation_events_append_only
            BEFORE UPDATE OR DELETE ON public.purge_operation_events
            FOR EACH ROW EXECUTE FUNCTION public.reject_append_only_mutation();
        CREATE TRIGGER memory_evidence_tombstones_append_only
            BEFORE UPDATE OR DELETE ON public.memory_evidence_tombstones
            FOR EACH ROW EXECUTE FUNCTION public.reject_append_only_mutation();

        ALTER TABLE public.purge_operations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.purge_operations FORCE ROW LEVEL SECURITY;
        ALTER TABLE public.purge_operation_events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.purge_operation_events FORCE ROW LEVEL SECURITY;
        ALTER TABLE public.memory_evidence_tombstones ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.memory_evidence_tombstones FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_scope ON public.purge_operations
            USING (
                owner_id=nullif(current_setting('app.owner_id',true),'')::uuid
                AND workspace_id=nullif(current_setting('app.workspace_id',true),'')::uuid
            )
            WITH CHECK (
                owner_id=nullif(current_setting('app.owner_id',true),'')::uuid
                AND workspace_id=nullif(current_setting('app.workspace_id',true),'')::uuid
            );
        CREATE POLICY tenant_scope ON public.purge_operation_events
            USING (
                owner_id=nullif(current_setting('app.owner_id',true),'')::uuid
                AND workspace_id=nullif(current_setting('app.workspace_id',true),'')::uuid
            )
            WITH CHECK (
                owner_id=nullif(current_setting('app.owner_id',true),'')::uuid
                AND workspace_id=nullif(current_setting('app.workspace_id',true),'')::uuid
            );
        CREATE POLICY tenant_scope ON public.memory_evidence_tombstones
            USING (
                owner_id=nullif(current_setting('app.owner_id',true),'')::uuid
                AND workspace_id=nullif(current_setting('app.workspace_id',true),'')::uuid
            )
            WITH CHECK (
                owner_id=nullif(current_setting('app.owner_id',true),'')::uuid
                AND workspace_id=nullif(current_setting('app.workspace_id',true),'')::uuid
            );

        GRANT SELECT,INSERT ON public.purge_operations TO second_brain_app;
        GRANT SELECT,INSERT ON public.purge_operation_events TO second_brain_app;
        GRANT SELECT ON public.memory_evidence_tombstones
            TO second_brain_app;

        CREATE OR REPLACE FUNCTION public.reject_append_only_mutation()
        RETURNS trigger LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF session_user='second_brain_worker'
                AND current_user<>session_user
                AND current_setting('app.authorized_purge_operation_id',true) IS NOT NULL
            THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION 'append-only records cannot be updated or deleted'
                USING ERRCODE='integrity_constraint_violation';
        END;
        $$;

        CREATE FUNCTION public.claim_purge_operation(p_worker text,p_lease_seconds integer)
        RETURNS TABLE (
            operation_id uuid,owner_id uuid,workspace_id uuid,resource_type text,
            resource_id uuid,reason_code text,attempts integer
        )
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE candidate public.purge_operations%ROWTYPE;
        BEGIN
            IF p_worker IS NULL OR length(p_worker) NOT BETWEEN 1 AND 200
                OR p_lease_seconds NOT BETWEEN 1 AND 3600 THEN
                RAISE EXCEPTION 'invalid purge claim arguments'
                    USING ERRCODE='invalid_parameter_value';
            END IF;
            SELECT operation.* INTO candidate
            FROM public.purge_operations AS operation
            WHERE operation.state IN ('queued','processing')
                AND operation.attempts < 3
                AND operation.available_at <= clock_timestamp()
                AND (
                    operation.state='queued'
                    OR operation.lease_expires_at <= clock_timestamp()
                )
            ORDER BY operation.available_at,operation.created_at,operation.id
            FOR UPDATE SKIP LOCKED LIMIT 1;
            IF NOT FOUND THEN RETURN; END IF;
            UPDATE public.purge_operations AS operation
            SET state='processing',attempts=operation.attempts+1,
                lease_owner=p_worker,
                lease_expires_at=clock_timestamp()+make_interval(secs=>p_lease_seconds),
                error_class=NULL
            WHERE operation.id=candidate.id;
            INSERT INTO public.purge_operation_events (
                owner_id,workspace_id,operation_id,attempt,from_state,to_state,
                reason_class,lease_owner
            ) VALUES (
                candidate.owner_id,candidate.workspace_id,candidate.id,candidate.attempts+1,
                candidate.state,'processing','claimed',p_worker
            );
            RETURN QUERY SELECT candidate.id,candidate.owner_id,candidate.workspace_id,
                candidate.resource_type,candidate.resource_id,candidate.reason_code,
                candidate.attempts+1;
        END;
        $$;
        REVOKE ALL ON FUNCTION public.claim_purge_operation(text,integer) FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.claim_purge_operation(text,integer)
            FROM second_brain_app;
        GRANT EXECUTE ON FUNCTION public.claim_purge_operation(text,integer)
            TO second_brain_worker;

        CREATE FUNCTION public.retry_purge_operation(
            p_operation uuid,p_worker text,p_error_class text,p_delay_seconds integer
        ) RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE operation public.purge_operations%ROWTYPE;
        DECLARE target_state text;
        BEGIN
            SELECT candidate.* INTO operation
            FROM public.purge_operations AS candidate
            WHERE candidate.id=p_operation AND candidate.state='processing'
                AND candidate.lease_owner=p_worker
            FOR UPDATE;
            IF NOT FOUND THEN RETURN false; END IF;
            target_state := CASE WHEN operation.attempts >= 3 THEN 'dead' ELSE 'queued' END;
            UPDATE public.purge_operations AS candidate
            SET state=target_state,lease_owner=NULL,lease_expires_at=NULL,
                available_at=clock_timestamp()+make_interval(secs=>greatest(p_delay_seconds,0)),
                error_class=left(p_error_class,100),
                finished_at=CASE WHEN target_state='dead' THEN clock_timestamp() ELSE NULL END
            WHERE candidate.id=p_operation;
            INSERT INTO public.purge_operation_events (
                owner_id,workspace_id,operation_id,attempt,from_state,to_state,reason_class
            ) VALUES (
                operation.owner_id,operation.workspace_id,operation.id,operation.attempts,
                'processing',target_state,left(p_error_class,100)
            );
            RETURN true;
        END;
        $$;
        REVOKE ALL ON FUNCTION public.retry_purge_operation(uuid,text,text,integer)
            FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.retry_purge_operation(uuid,text,text,integer)
            FROM second_brain_app;
        GRANT EXECUTE ON FUNCTION public.retry_purge_operation(uuid,text,text,integer)
            TO second_brain_worker;

        CREATE FUNCTION public.finalize_source_purge(p_operation uuid,p_worker text)
        RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE operation public.purge_operations%ROWTYPE;
        DECLARE source_tombstone uuid := gen_random_uuid();
        DECLARE run_ids uuid[];
        DECLARE orphan_tag_ids uuid[];
        BEGIN
            SELECT candidate.* INTO operation
            FROM public.purge_operations AS candidate
            WHERE candidate.id=p_operation AND candidate.resource_type='source'
                AND candidate.state='processing' AND candidate.lease_owner=p_worker
                AND candidate.lease_expires_at>clock_timestamp()
            FOR UPDATE;
            IF NOT FOUND THEN RETURN false; END IF;
            IF NOT EXISTS (
                SELECT 1 FROM public.sources AS source
                WHERE source.id=operation.resource_id
                    AND source.owner_id=operation.owner_id
                    AND source.workspace_id=operation.workspace_id
                    AND source.processing_state='purge_pending'
                    AND source.deleted_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'purge source is unavailable' USING ERRCODE='23503';
            END IF;
            PERFORM set_config('app.authorized_purge_operation_id',p_operation::text,true);

            INSERT INTO public.memory_evidence_tombstones (
                owner_id,workspace_id,memory_id,proposal_id,revision_id,source_tombstone_id
            )
            SELECT DISTINCT operation.owner_id,operation.workspace_id,memory.id,
                proposal_evidence.proposal_id,NULL::uuid,source_tombstone
            FROM public.memory_proposal_evidence AS proposal_evidence
            LEFT JOIN public.approved_memories AS memory
                ON memory.proposal_id=proposal_evidence.proposal_id
            WHERE proposal_evidence.source_id=operation.resource_id;
            INSERT INTO public.memory_evidence_tombstones (
                owner_id,workspace_id,memory_id,proposal_id,revision_id,source_tombstone_id
            )
            SELECT DISTINCT operation.owner_id,operation.workspace_id,revision.memory_id,
                memory.proposal_id,revision_evidence.revision_id,source_tombstone
            FROM public.memory_revision_evidence AS revision_evidence
            JOIN public.memory_revisions AS revision ON revision.id=revision_evidence.revision_id
            JOIN public.approved_memories AS memory ON memory.id=revision.memory_id
            WHERE revision_evidence.source_id=operation.resource_id;
            DELETE FROM public.memory_revision_evidence AS evidence
            WHERE evidence.source_id=operation.resource_id;
            DELETE FROM public.memory_proposal_evidence AS evidence
            WHERE evidence.source_id=operation.resource_id;

            SELECT array_agg(DISTINCT result.retrieval_run_id) INTO run_ids
            FROM public.retrieval_results AS result
            WHERE result.source_id=operation.resource_id;
            IF run_ids IS NOT NULL THEN
                DELETE FROM public.citations AS citation
                    WHERE citation.retrieval_run_id=ANY(run_ids);
                DELETE FROM public.answers AS answer
                    WHERE answer.retrieval_run_id=ANY(run_ids);
                DELETE FROM public.retrieval_results AS result
                    WHERE result.retrieval_run_id=ANY(run_ids);
                DELETE FROM public.retrieval_runs AS run WHERE run.id=ANY(run_ids);
            END IF;

            DELETE FROM public.embeddings AS embedding
            USING public.chunks AS chunk,public.source_versions AS version
            WHERE embedding.chunk_id=chunk.id AND chunk.source_version_id=version.id
                AND version.source_id=operation.resource_id;
            DELETE FROM public.chunks AS chunk
            USING public.source_versions AS version
            WHERE chunk.source_version_id=version.id
                AND version.source_id=operation.resource_id;
            DELETE FROM public.documents AS document
            USING public.source_versions AS version
            WHERE document.source_version_id=version.id
                AND version.source_id=operation.resource_id;
            DELETE FROM public.url_fetches AS url_fetch
                WHERE url_fetch.source_id=operation.resource_id;
            DELETE FROM public.capture_stages AS stage
                WHERE stage.source_id=operation.resource_id;
            DELETE FROM public.ingestion_job_events AS event
            USING public.ingestion_jobs AS job
            WHERE event.job_id=job.id AND job.source_id=operation.resource_id;
            DELETE FROM public.ingestion_jobs AS job
                WHERE job.source_id=operation.resource_id;
            SELECT array_agg(link.tag_id) INTO orphan_tag_ids
            FROM public.source_tags AS link WHERE link.source_id=operation.resource_id;
            DELETE FROM public.source_tags AS link
                WHERE link.source_id=operation.resource_id;
            IF orphan_tag_ids IS NOT NULL THEN
                DELETE FROM public.tags AS tag
                WHERE tag.id=ANY(orphan_tag_ids)
                    AND NOT EXISTS (
                        SELECT 1 FROM public.source_tags AS remaining
                        WHERE remaining.tag_id=tag.id
                    );
            END IF;
            DELETE FROM public.source_versions AS version
                WHERE version.source_id=operation.resource_id;
            DELETE FROM public.sources AS source WHERE source.id=operation.resource_id;

            INSERT INTO public.purge_records (
                owner_id,workspace_id,source_id,source_tombstone_id,reason_code,
                original_removed,searchable_content_removed,operation_id,resource_type,
                resource_id
            ) VALUES (
                operation.owner_id,operation.workspace_id,operation.resource_id,
                source_tombstone,operation.reason_code,true,true,operation.id,
                'source',operation.resource_id
            );
            UPDATE public.purge_operations AS candidate
            SET state='complete',lease_owner=NULL,lease_expires_at=NULL,
                finished_at=clock_timestamp(),error_class=NULL
            WHERE candidate.id=operation.id;
            INSERT INTO public.purge_operation_events (
                owner_id,workspace_id,operation_id,attempt,from_state,to_state,reason_class
            ) VALUES (
                operation.owner_id,operation.workspace_id,operation.id,operation.attempts,
                'processing','complete','purge_complete'
            );
            RETURN true;
        END;
        $$;
        REVOKE ALL ON FUNCTION public.finalize_source_purge(uuid,text) FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.finalize_source_purge(uuid,text)
            FROM second_brain_app;
        GRANT EXECUTE ON FUNCTION public.finalize_source_purge(uuid,text)
            TO second_brain_worker;

        CREATE FUNCTION public.finalize_memory_purge(p_operation uuid,p_worker text)
        RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE operation public.purge_operations%ROWTYPE;
        DECLARE proposal uuid;
        DECLARE memory_tombstone uuid := gen_random_uuid();
        BEGIN
            SELECT candidate.* INTO operation
            FROM public.purge_operations AS candidate
            WHERE candidate.id=p_operation AND candidate.resource_type='memory'
                AND candidate.state='processing' AND candidate.lease_owner=p_worker
                AND candidate.lease_expires_at>clock_timestamp()
            FOR UPDATE;
            IF NOT FOUND THEN RETURN false; END IF;
            SELECT memory.proposal_id INTO proposal
            FROM public.approved_memories AS memory
            WHERE memory.id=operation.resource_id
                AND memory.owner_id=operation.owner_id
                AND memory.workspace_id=operation.workspace_id
                AND memory.status='purge_pending';
            IF proposal IS NULL THEN
                RAISE EXCEPTION 'purge memory is unavailable' USING ERRCODE='23503';
            END IF;
            PERFORM set_config('app.authorized_purge_operation_id',p_operation::text,true);
            IF to_regclass('public.memory_resurfacing_events') IS NOT NULL THEN
                EXECUTE 'DELETE FROM public.memory_resurfacing_events '
                    'WHERE memory_id=$1 AND owner_id=$2 AND workspace_id=$3'
                    USING operation.resource_id,operation.owner_id,operation.workspace_id;
            END IF;
            UPDATE public.approved_memories AS memory
            SET superseded_by_id=NULL
            WHERE memory.superseded_by_id=operation.resource_id;
            UPDATE public.approved_memories AS memory
            SET supersedes_memory_id=NULL
            WHERE memory.supersedes_memory_id=operation.resource_id;
            DELETE FROM public.memory_revision_evidence AS evidence
            USING public.memory_revisions AS revision
            WHERE evidence.revision_id=revision.id
                AND revision.memory_id=operation.resource_id;
            DELETE FROM public.memory_revisions AS revision
                WHERE revision.memory_id=operation.resource_id;
            DELETE FROM public.approved_memories AS memory
                WHERE memory.id=operation.resource_id;
            DELETE FROM public.memory_proposal_evidence AS evidence
                WHERE evidence.proposal_id=proposal;
            DELETE FROM public.memory_proposals AS memory_proposal
                WHERE memory_proposal.id=proposal;
            INSERT INTO public.purge_records (
                owner_id,workspace_id,source_id,source_tombstone_id,reason_code,
                original_removed,searchable_content_removed,operation_id,resource_type,
                resource_id
            ) VALUES (
                operation.owner_id,operation.workspace_id,NULL,memory_tombstone,
                operation.reason_code,true,true,operation.id,'memory',operation.resource_id
            );
            UPDATE public.purge_operations AS candidate
            SET state='complete',lease_owner=NULL,lease_expires_at=NULL,
                finished_at=clock_timestamp(),error_class=NULL
            WHERE candidate.id=operation.id;
            INSERT INTO public.purge_operation_events (
                owner_id,workspace_id,operation_id,attempt,from_state,to_state,reason_class
            ) VALUES (
                operation.owner_id,operation.workspace_id,operation.id,operation.attempts,
                'processing','complete','purge_complete'
            );
            RETURN true;
        END;
        $$;
        REVOKE ALL ON FUNCTION public.finalize_memory_purge(uuid,text) FROM PUBLIC;
        REVOKE ALL ON FUNCTION public.finalize_memory_purge(uuid,text)
            FROM second_brain_app;
        GRANT EXECUTE ON FUNCTION public.finalize_memory_purge(uuid,text)
            TO second_brain_worker;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP FUNCTION public.finalize_memory_purge(uuid,text);
        DROP FUNCTION public.finalize_source_purge(uuid,text);
        DROP FUNCTION public.retry_purge_operation(uuid,text,text,integer);
        DROP FUNCTION public.claim_purge_operation(text,integer);

        CREATE OR REPLACE FUNCTION public.reject_append_only_mutation()
        RETURNS trigger LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            RAISE EXCEPTION 'append-only records cannot be updated or deleted'
                USING ERRCODE='integrity_constraint_violation';
        END;
        $$;

        ALTER TABLE public.purge_records
            DROP CONSTRAINT purge_records_operation_fk,
            DROP CONSTRAINT purge_records_operation_unique,
            DROP CONSTRAINT purge_records_resource_type_check,
            DROP CONSTRAINT purge_records_reason_code_check,
            DROP COLUMN resource_id,
            DROP COLUMN resource_type,
            DROP COLUMN operation_id;
        DROP TABLE public.memory_evidence_tombstones;
        DROP TABLE public.purge_operation_events;
        DROP TABLE public.purge_operations;

        UPDATE public.sources SET processing_state='purged'
            WHERE processing_state='purge_pending';
        ALTER TABLE public.sources DROP CONSTRAINT sources_processing_state_check;
        ALTER TABLE public.sources ADD CONSTRAINT sources_processing_state_check CHECK (
            processing_state IN ('queued','processing','ready','failed','purged')
        );
        UPDATE public.approved_memories SET status='archived'
            WHERE status IN ('purge_pending','purged');
        ALTER TABLE public.approved_memories
            DROP CONSTRAINT approved_memories_status_check;
        ALTER TABLE public.approved_memories
            ADD CONSTRAINT approved_memories_status_check CHECK (
                status IN ('active','superseded','archived')
            );
        """
    )
