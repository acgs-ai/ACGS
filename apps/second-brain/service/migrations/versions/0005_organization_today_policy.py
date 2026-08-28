"""Add scoped organization, deterministic Today, and policy audit support.

Revision ID: 0005_organization_today_policy
Revises: 0004_purge_lifecycle
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005_organization_today_policy"
down_revision: str | None = "0004_purge_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE projects
            ADD COLUMN updated_at timestamptz;
        UPDATE projects SET updated_at=created_at;
        ALTER TABLE projects
            ALTER COLUMN updated_at SET DEFAULT now(),
            ALTER COLUMN updated_at SET NOT NULL,
            ADD COLUMN normalized_name text GENERATED ALWAYS AS (
                lower(regexp_replace(btrim(name), '[[:space:]]+', ' ', 'g'))
            ) STORED,
            ADD CONSTRAINT projects_name_bounded CHECK (length(btrim(name)) BETWEEN 1 AND 200),
            ADD CONSTRAINT projects_normalized_name_bounded
                CHECK (length(normalized_name) BETWEEN 1 AND 200),
            ADD CONSTRAINT projects_scoped_normalized_name_unique
                UNIQUE (owner_id,workspace_id,normalized_name);

        ALTER TABLE tags
            ADD COLUMN normalized_name text GENERATED ALWAYS AS (
                lower(regexp_replace(btrim(name), '[[:space:]]+', ' ', 'g'))
            ) STORED,
            ADD CONSTRAINT tags_name_bounded CHECK (length(btrim(name)) BETWEEN 1 AND 200),
            ADD CONSTRAINT tags_normalized_name_bounded
                CHECK (length(normalized_name) BETWEEN 1 AND 200),
            ADD CONSTRAINT tags_scoped_normalized_name_unique
                UNIQUE (owner_id,workspace_id,normalized_name);

        ALTER TABLE ingestion_jobs ADD COLUMN finished_at timestamptz;
        UPDATE ingestion_jobs
        SET finished_at=updated_at
        WHERE state IN ('ready','failed','dead');
        ALTER TABLE ingestion_jobs ADD CONSTRAINT ingestion_jobs_finished_state CHECK (
            (state IN ('ready','failed','dead') AND finished_at IS NOT NULL)
            OR (state IN ('queued','processing') AND finished_at IS NULL)
        );
        CREATE INDEX ingestion_jobs_failed_finished_idx
            ON ingestion_jobs (owner_id,workspace_id,finished_at DESC,id)
            WHERE state IN ('failed','dead');

        CREATE TABLE memory_resurfacing_events (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            memory_id uuid NOT NULL,
            resurfaced_at timestamptz NOT NULL DEFAULT now(),
            reason_code text NOT NULL DEFAULT 'today.deterministic'
                CHECK (reason_code='today.deterministic'),
            UNIQUE (id,owner_id,workspace_id),
            FOREIGN KEY (workspace_id,owner_id)
                REFERENCES workspace_memberships(workspace_id,user_id) ON DELETE RESTRICT,
            FOREIGN KEY (memory_id,owner_id,workspace_id)
                REFERENCES approved_memories(id,owner_id,workspace_id) ON DELETE RESTRICT
        );
        CREATE UNIQUE INDEX memory_resurfacing_once_per_utc_day
            ON memory_resurfacing_events (
                memory_id,((resurfaced_at AT TIME ZONE 'UTC')::date)
            );
        CREATE INDEX memory_resurfacing_recency_idx
            ON memory_resurfacing_events (owner_id,workspace_id,memory_id,resurfaced_at DESC);

        CREATE TABLE policy_decisions (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            request_id uuid NOT NULL,
            action text NOT NULL CHECK (action IN (
                'capture_source','generate_answer','approve_memory','purge_source','purge_memory'
            )),
            actor_id uuid NOT NULL,
            resource_type text NOT NULL
                CHECK (resource_type IN ('source','answer','memory','workspace')),
            resource_id uuid,
            source_type text
                CHECK (
                    source_type IS NULL
                    OR source_type IN ('note','markdown','txt','pdf','docx','url')
                ),
            mime_type text CHECK (mime_type IS NULL OR length(mime_type) BETWEEN 1 AND 255),
            byte_count bigint CHECK (byte_count IS NULL OR byte_count >= 0),
            chunk_count integer CHECK (chunk_count IS NULL OR chunk_count >= 0),
            retrieval_result_count integer
                CHECK (retrieval_result_count IS NULL OR retrieval_result_count >= 0),
            citation_count integer CHECK (citation_count IS NULL OR citation_count >= 0),
            memory_category text CHECK (
                memory_category IS NULL OR memory_category IN (
                    'preference','commitment','project_fact','person_fact','reference','other'
                )
            ),
            native_checks text NOT NULL CHECK (native_checks IN ('pass','fail')),
            decision text NOT NULL CHECK (decision IN ('pass','veto','unavailable')),
            reason_code text NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
            policy_id text NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 128),
            policy_version text NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
            audit_id text NOT NULL CHECK (length(audit_id) BETWEEN 1 AND 128),
            obligations text[] NOT NULL DEFAULT '{}'::text[] CHECK (
                cardinality(obligations) <= 8
                AND obligations <@ ARRAY[
                    'record_audit','require_explicit_user_action'
                ]::text[]
            ),
            evaluated_at timestamptz NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id,owner_id,workspace_id),
            UNIQUE (owner_id,workspace_id,request_id),
            FOREIGN KEY (workspace_id,owner_id)
                REFERENCES workspace_memberships(workspace_id,user_id) ON DELETE RESTRICT,
            CHECK (actor_id=owner_id)
        );

        CREATE FUNCTION set_project_updated_at() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path=pg_catalog,public
        AS $$
        BEGIN
            IF ROW(NEW.name,NEW.is_active) IS DISTINCT FROM ROW(OLD.name,OLD.is_active) THEN
                NEW.updated_at=clock_timestamp();
            END IF;
            RETURN NEW;
        END;
        $$;
        REVOKE ALL ON FUNCTION public.set_project_updated_at() FROM PUBLIC;
        CREATE TRIGGER projects_updated_at
            BEFORE UPDATE ON public.projects
            FOR EACH ROW EXECUTE FUNCTION public.set_project_updated_at();

        CREATE FUNCTION set_ingestion_finished_at() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path=pg_catalog,public
        AS $$
        BEGIN
            IF NEW.state IN ('ready','failed','dead') THEN
                IF TG_OP='INSERT' OR OLD.state IS DISTINCT FROM NEW.state THEN
                    NEW.finished_at=clock_timestamp();
                END IF;
            ELSE
                NEW.finished_at=NULL;
            END IF;
            RETURN NEW;
        END;
        $$;
        REVOKE ALL ON FUNCTION public.set_ingestion_finished_at() FROM PUBLIC;
        CREATE TRIGGER ingestion_jobs_finished_at
            BEFORE INSERT OR UPDATE OF state ON public.ingestion_jobs
            FOR EACH ROW EXECUTE FUNCTION public.set_ingestion_finished_at();

        CREATE TRIGGER memory_resurfacing_events_append_only
            BEFORE UPDATE OR DELETE ON public.memory_resurfacing_events
            FOR EACH ROW EXECUTE FUNCTION public.reject_append_only_mutation();
        CREATE TRIGGER policy_decisions_append_only
            BEFORE UPDATE OR DELETE ON public.policy_decisions
            FOR EACH ROW EXECUTE FUNCTION public.reject_append_only_mutation();

        ALTER TABLE memory_resurfacing_events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE memory_resurfacing_events FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_scope ON memory_resurfacing_events
            USING (
                owner_id=nullif(current_setting('app.owner_id',true),'')::uuid
                AND workspace_id=nullif(current_setting('app.workspace_id',true),'')::uuid
            )
            WITH CHECK (
                owner_id=nullif(current_setting('app.owner_id',true),'')::uuid
                AND workspace_id=nullif(current_setting('app.workspace_id',true),'')::uuid
            );
        ALTER TABLE policy_decisions ENABLE ROW LEVEL SECURITY;
        ALTER TABLE policy_decisions FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_scope ON policy_decisions
            USING (
                owner_id=nullif(current_setting('app.owner_id',true),'')::uuid
                AND workspace_id=nullif(current_setting('app.workspace_id',true),'')::uuid
            )
            WITH CHECK (
                owner_id=nullif(current_setting('app.owner_id',true),'')::uuid
                AND workspace_id=nullif(current_setting('app.workspace_id',true),'')::uuid
            );

        GRANT SELECT,INSERT ON memory_resurfacing_events,policy_decisions TO second_brain_app;
        GRANT UPDATE (name,is_active) ON projects TO second_brain_app;
        GRANT DELETE ON projects TO second_brain_app;
        GRANT UPDATE (name) ON tags TO second_brain_app;
        GRANT DELETE ON tags TO second_brain_app;
        GRANT UPDATE (project_id) ON sources TO second_brain_app;
        GRANT DELETE ON source_tags TO second_brain_app;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE DELETE ON source_tags FROM second_brain_app;
        REVOKE UPDATE (project_id) ON sources FROM second_brain_app;
        REVOKE DELETE ON tags FROM second_brain_app;
        REVOKE UPDATE (name) ON tags FROM second_brain_app;
        REVOKE DELETE ON projects FROM second_brain_app;
        REVOKE UPDATE (name,is_active) ON projects FROM second_brain_app;

        DROP TABLE policy_decisions;
        DROP TABLE memory_resurfacing_events;

        DROP TRIGGER ingestion_jobs_finished_at ON public.ingestion_jobs;
        DROP FUNCTION public.set_ingestion_finished_at();
        DROP INDEX ingestion_jobs_failed_finished_idx;
        ALTER TABLE ingestion_jobs
            DROP CONSTRAINT ingestion_jobs_finished_state,
            DROP COLUMN finished_at;

        DROP TRIGGER projects_updated_at ON public.projects;
        DROP FUNCTION public.set_project_updated_at();
        ALTER TABLE tags
            DROP CONSTRAINT tags_scoped_normalized_name_unique,
            DROP CONSTRAINT tags_normalized_name_bounded,
            DROP CONSTRAINT tags_name_bounded,
            DROP COLUMN normalized_name;
        ALTER TABLE projects
            DROP CONSTRAINT projects_scoped_normalized_name_unique,
            DROP CONSTRAINT projects_normalized_name_bounded,
            DROP CONSTRAINT projects_name_bounded,
            DROP COLUMN normalized_name,
            DROP COLUMN updated_at;
        """
    )
