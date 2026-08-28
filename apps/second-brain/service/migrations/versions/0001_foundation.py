"""Create provenance, retrieval, memory, and tenant isolation foundation.

Revision ID: 0001_foundation
Revises:
Create Date: 2026-08-27
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0001_foundation"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_TABLES = (
    "workspaces",
    "workspace_memberships",
    "sessions",
    "used_assertion_nonces",
    "projects",
    "sources",
    "source_versions",
    "capture_stages",
    "ingestion_jobs",
    "ingestion_job_events",
    "url_fetches",
    "documents",
    "chunks",
    "embedding_profiles",
    "embeddings",
    "tags",
    "source_tags",
    "conversations",
    "messages",
    "retrieval_runs",
    "retrieval_results",
    "answers",
    "citations",
    "memory_proposals",
    "memory_proposal_evidence",
    "approved_memories",
    "memory_revisions",
    "memory_revision_evidence",
    "purge_records",
)

APPEND_ONLY_TABLES = (
    "source_versions",
    "ingestion_job_events",
    "url_fetches",
    "documents",
    "chunks",
    "embeddings",
    "messages",
    "retrieval_runs",
    "retrieval_results",
    "answers",
    "citations",
    "memory_proposal_evidence",
    "memory_revisions",
    "memory_revision_evidence",
    "purge_records",
    "used_assertion_nonces",
)

OWNED_FUNCTION_SIGNATURES = (
    "enforce_embedding_profile_dimensions()",
    "reject_append_only_mutation()",
    "protect_source_provenance()",
    "enforce_capture_stage_transition()",
    "record_initial_ingestion_job_event()",
    "enforce_ingestion_job_state_event()",
    "protect_ingestion_job_lineage()",
    "reject_late_memory_proposal_evidence()",
    "enforce_memory_proposal_invariants()",
    "enforce_approved_memory_invariants()",
    "enforce_memory_revision_invariants()",
    "reject_late_initial_revision_evidence()",
    "resolve_second_brain_session(text)",
    "consume_trusted_exchange_attempt(inet,text,uuid,uuid,integer,integer)",
    "claim_ingestion_job(text,integer)",
    "heartbeat_ingestion_job(uuid,text,integer)",
    "list_stale_capture_stages(integer,integer)",
    "transition_ingestion_job(uuid,text,text,text,text,text,integer)",
    "abandon_capture_stage(uuid,text)",
)


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute(
        """
        DO $$
        BEGIN
            EXECUTE format(
                'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database()
            );
            EXECUTE format(
                'REVOKE TEMPORARY ON DATABASE %I FROM second_brain_app', current_database()
            );
            EXECUTE format(
                'REVOKE TEMPORARY ON DATABASE %I FROM second_brain_worker', current_database()
            );
        END;
        $$;
        """
    )

    op.execute(
        """
        CREATE TABLE users (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            email text NOT NULL UNIQUE,
            created_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE TABLE workspaces (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            name text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id)
        );

        CREATE TABLE workspace_memberships (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            workspace_id uuid NOT NULL,
            user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            role text NOT NULL CHECK (role IN ('owner', 'member')),
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (workspace_id, user_id),
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
        );

        CREATE TABLE sessions (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            token_hash char(64) NOT NULL UNIQUE,
            csrf_token_hash char(64) NOT NULL,
            issued_at timestamptz NOT NULL,
            absolute_expires_at timestamptz NOT NULL,
            idle_expires_at timestamptz NOT NULL,
            idle_timeout_seconds integer NOT NULL CHECK (idle_timeout_seconds >= 60),
            last_seen_at timestamptz NOT NULL,
            revoked_at timestamptz,
            UNIQUE (id, owner_id, workspace_id),
            CHECK (idle_expires_at <= absolute_expires_at),
            CHECK (issued_at <= last_seen_at),
            FOREIGN KEY (workspace_id, owner_id)
                REFERENCES workspace_memberships(workspace_id, user_id) ON DELETE RESTRICT
        );
        CREATE INDEX sessions_active_token_idx ON sessions (token_hash)
            WHERE revoked_at IS NULL;

        CREATE TABLE used_assertion_nonces (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            issuer text NOT NULL,
            nonce uuid NOT NULL,
            assertion_expires_at timestamptz NOT NULL,
            used_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (issuer, nonce),
            FOREIGN KEY (workspace_id, owner_id)
                REFERENCES workspace_memberships(workspace_id, user_id) ON DELETE RESTRICT
        );

        CREATE TABLE trusted_exchange_rate_limits (
            peer_address inet NOT NULL,
            issuer text NOT NULL,
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            window_started_at timestamptz NOT NULL,
            attempts integer NOT NULL CHECK (attempts > 0),
            PRIMARY KEY (peer_address, issuer, owner_id, workspace_id)
        );

        CREATE TABLE projects (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            name text NOT NULL,
            is_active boolean NOT NULL DEFAULT true,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            FOREIGN KEY (workspace_id, owner_id)
                REFERENCES workspace_memberships(workspace_id, user_id) ON DELETE CASCADE
        );

        CREATE TABLE sources (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            project_id uuid,
            source_type text NOT NULL
                CHECK (source_type IN ('note','markdown','txt','pdf','docx','url')),
            display_title text NOT NULL,
            original_uri text,
            object_key text,
            original_filename text,
            source_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
            idempotency_key text,
            content_sha256 char(64),
            normalized_dedup_sha256 char(64) NOT NULL,
            mime_type text NOT NULL,
            processing_state text NOT NULL DEFAULT 'queued'
                CHECK (processing_state IN ('queued','processing','ready','failed','purged')),
            semantic_state text NOT NULL DEFAULT 'pending'
                CHECK (semantic_state IN ('pending','available','unavailable')),
            processing_error_code text,
            processing_error_message text,
            ingested_at timestamptz NOT NULL DEFAULT now(),
            deleted_at timestamptz,
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (owner_id, workspace_id, normalized_dedup_sha256),
            UNIQUE (owner_id, workspace_id, idempotency_key),
            CHECK (
                (source_type = 'url' AND content_sha256 IS NULL AND object_key IS NULL)
                OR (source_type <> 'url' AND content_sha256 IS NOT NULL)
            ),
            FOREIGN KEY (workspace_id, owner_id)
                REFERENCES workspace_memberships(workspace_id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY (project_id, owner_id, workspace_id)
                REFERENCES projects(id, owner_id, workspace_id) ON DELETE RESTRICT
        );

        CREATE TABLE source_versions (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            source_id uuid NOT NULL,
            version_number integer NOT NULL CHECK (version_number > 0),
            parser_name text NOT NULL,
            parser_version text NOT NULL,
            fetcher_version text,
            parser_mime_type text,
            chunker_version text NOT NULL,
            content_sha256 char(64) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (id, source_id, owner_id, workspace_id),
            UNIQUE (source_id, version_number),
            FOREIGN KEY (source_id, owner_id, workspace_id)
                REFERENCES sources(id, owner_id, workspace_id) ON DELETE RESTRICT
        );

        CREATE TABLE capture_stages (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            object_key text NOT NULL,
            kind text NOT NULL CHECK (kind IN ('note','markdown','txt','pdf','docx','url')),
            intended_content_sha256 char(64),
            intended_size bigint CHECK (intended_size >= 0),
            state text NOT NULL DEFAULT 'pending'
                CHECK (state IN ('pending','stored','finalized','abandoned')),
            source_id uuid NOT NULL,
            job_id uuid NOT NULL,
            source_version_id uuid,
            error_class text CHECK (error_class IS NULL OR length(error_class) BETWEEN 1 AND 100),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            stored_at timestamptz,
            finalized_at timestamptz,
            abandoned_at timestamptz,
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (owner_id, workspace_id, object_key),
            CHECK (intended_content_sha256 IS NOT NULL AND intended_size IS NOT NULL),
            CHECK (
                (state = 'pending' AND stored_at IS NULL AND finalized_at IS NULL
                    AND abandoned_at IS NULL AND source_version_id IS NULL
                    AND error_class IS NULL)
                OR (state = 'stored' AND stored_at IS NOT NULL AND finalized_at IS NULL
                    AND abandoned_at IS NULL AND source_version_id IS NULL
                    AND error_class IS NULL)
                OR (state = 'finalized' AND stored_at IS NOT NULL AND finalized_at IS NOT NULL
                    AND abandoned_at IS NULL AND source_id IS NOT NULL
                    AND source_version_id IS NOT NULL AND error_class IS NULL)
                OR (state = 'abandoned' AND finalized_at IS NULL AND abandoned_at IS NOT NULL
                    AND source_version_id IS NULL AND error_class IS NOT NULL)
            ),
            FOREIGN KEY (workspace_id, owner_id)
                REFERENCES workspace_memberships(workspace_id, user_id) ON DELETE RESTRICT,
            FOREIGN KEY (source_id, owner_id, workspace_id)
                REFERENCES sources(id, owner_id, workspace_id) ON DELETE RESTRICT,
            FOREIGN KEY (source_version_id, source_id, owner_id, workspace_id)
                REFERENCES source_versions(id, source_id, owner_id, workspace_id)
                ON DELETE RESTRICT
        );
        CREATE INDEX capture_stages_source_history_idx
            ON capture_stages (owner_id, workspace_id, source_id, created_at);

        CREATE TABLE ingestion_jobs (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            source_id uuid NOT NULL,
            source_version_id uuid,
            requested_uri text,
            state text NOT NULL DEFAULT 'queued'
                CHECK (state IN ('queued','processing','ready','failed','dead')),
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            available_at timestamptz NOT NULL DEFAULT now(),
            lease_owner text,
            lease_expires_at timestamptz,
            heartbeat_at timestamptz,
            pipeline_checkpoint text NOT NULL DEFAULT 'captured'
                CHECK (pipeline_checkpoint IN ('captured','lexical_committed')),
            semantic_state text NOT NULL DEFAULT 'pending'
                CHECK (semantic_state IN ('pending','available','unavailable')),
            semantic_error_class text
                CHECK (semantic_error_class IS NULL OR length(semantic_error_class) <= 100),
            error_code text,
            error_message text,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (id, owner_id, workspace_id, source_id),
            CHECK (source_version_id IS NOT NULL OR requested_uri IS NOT NULL),
            FOREIGN KEY (source_id, owner_id, workspace_id)
                REFERENCES sources(id, owner_id, workspace_id) ON DELETE RESTRICT,
            FOREIGN KEY (source_version_id, source_id, owner_id, workspace_id)
                REFERENCES source_versions(id, source_id, owner_id, workspace_id)
                ON DELETE RESTRICT
        );

        CREATE INDEX ingestion_jobs_claim_idx
            ON ingestion_jobs (state, available_at, lease_expires_at);

        ALTER TABLE capture_stages
            ADD CONSTRAINT capture_stages_job_lineage_fk
            FOREIGN KEY (job_id, owner_id, workspace_id, source_id)
            REFERENCES ingestion_jobs(id, owner_id, workspace_id, source_id)
            ON DELETE RESTRICT;

        CREATE TABLE ingestion_job_events (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            job_id uuid NOT NULL,
            attempt integer NOT NULL CHECK (attempt >= 0),
            from_state text CHECK (
                from_state IS NULL OR from_state IN ('queued','processing','ready','failed','dead')
            ),
            to_state text NOT NULL
                CHECK (to_state IN ('queued','processing','ready','failed','dead')),
            reason_class text NOT NULL CHECK (length(reason_class) BETWEEN 1 AND 100),
            occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            lease_owner text,
            lease_expires_at timestamptz,
            transaction_id bigint NOT NULL DEFAULT txid_current(),
            UNIQUE (id, owner_id, workspace_id),
            FOREIGN KEY (job_id, owner_id, workspace_id)
                REFERENCES ingestion_jobs(id, owner_id, workspace_id) ON DELETE RESTRICT
        );
        CREATE INDEX ingestion_job_events_job_history_idx
            ON ingestion_job_events (job_id, occurred_at, id);

        CREATE TABLE url_fetches (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            job_id uuid NOT NULL,
            source_id uuid NOT NULL,
            source_version_id uuid NOT NULL,
            submitted_uri text NOT NULL,
            final_uri text NOT NULL,
            redirect_lineage jsonb NOT NULL,
            chosen_peer inet NOT NULL,
            actual_peer inet NOT NULL,
            mime_type text NOT NULL,
            byte_count bigint NOT NULL CHECK (byte_count >= 0),
            content_sha256 char(64) NOT NULL,
            object_key text NOT NULL,
            fetcher_version text NOT NULL,
            parser_version text NOT NULL,
            fetched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (job_id),
            FOREIGN KEY (job_id, owner_id, workspace_id)
                REFERENCES ingestion_jobs(id, owner_id, workspace_id) ON DELETE RESTRICT,
            FOREIGN KEY (source_version_id, source_id, owner_id, workspace_id)
                REFERENCES source_versions(id, source_id, owner_id, workspace_id)
                ON DELETE RESTRICT
        );
        CREATE INDEX url_fetches_source_history_idx
            ON url_fetches (owner_id, workspace_id, source_id, fetched_at);

        CREATE TABLE documents (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            source_version_id uuid NOT NULL,
            extracted_text text NOT NULL,
            character_count integer NOT NULL CHECK (character_count >= 0),
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (id, source_version_id, owner_id, workspace_id),
            UNIQUE (source_version_id),
            FOREIGN KEY (source_version_id, owner_id, workspace_id)
                REFERENCES source_versions(id, owner_id, workspace_id) ON DELETE RESTRICT
        );

        CREATE TABLE chunks (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            document_id uuid NOT NULL,
            source_version_id uuid NOT NULL,
            ordinal integer NOT NULL CHECK (ordinal >= 0),
            chunk_text text NOT NULL,
            char_start integer NOT NULL CHECK (char_start >= 0),
            char_end integer NOT NULL CHECK (char_end >= char_start),
            page_number integer CHECK (page_number > 0),
            section text,
            paragraph_number integer CHECK (paragraph_number > 0),
            location jsonb NOT NULL DEFAULT '{}'::jsonb,
            chunker_version text NOT NULL,
            search_vector tsvector GENERATED ALWAYS AS
                (to_tsvector('english', coalesce(chunk_text, ''))) STORED,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (document_id, ordinal),
            FOREIGN KEY (document_id, source_version_id, owner_id, workspace_id)
                REFERENCES documents(id, source_version_id, owner_id, workspace_id)
                ON DELETE RESTRICT
        );
        CREATE INDEX chunks_search_vector_gin ON chunks USING gin (search_vector);

        CREATE TABLE embedding_profiles (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            provider text NOT NULL,
            model_identifier text NOT NULL,
            profile_version integer NOT NULL CHECK (profile_version > 0),
            dimensions integer NOT NULL CHECK (dimensions > 0),
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (owner_id, workspace_id, provider, model_identifier, profile_version),
            FOREIGN KEY (workspace_id, owner_id)
                REFERENCES workspace_memberships(workspace_id, user_id) ON DELETE RESTRICT
        );

        CREATE TABLE embeddings (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            chunk_id uuid NOT NULL,
            profile_id uuid NOT NULL,
            embedding vector NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (chunk_id, profile_id),
            FOREIGN KEY (chunk_id, owner_id, workspace_id)
                REFERENCES chunks(id, owner_id, workspace_id) ON DELETE RESTRICT,
            FOREIGN KEY (profile_id, owner_id, workspace_id)
                REFERENCES embedding_profiles(id, owner_id, workspace_id) ON DELETE RESTRICT
        );

        CREATE TABLE tags (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            name text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (owner_id, workspace_id, name),
            FOREIGN KEY (workspace_id, owner_id)
                REFERENCES workspace_memberships(workspace_id, user_id) ON DELETE CASCADE
        );

        CREATE TABLE source_tags (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            source_id uuid NOT NULL,
            tag_id uuid NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (source_id, tag_id),
            FOREIGN KEY (source_id, owner_id, workspace_id)
                REFERENCES sources(id, owner_id, workspace_id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id, owner_id, workspace_id)
                REFERENCES tags(id, owner_id, workspace_id) ON DELETE CASCADE
        );

        CREATE TABLE conversations (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            title text,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            FOREIGN KEY (workspace_id, owner_id)
                REFERENCES workspace_memberships(workspace_id, user_id) ON DELETE CASCADE
        );

        CREATE TABLE messages (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            conversation_id uuid NOT NULL,
            role text NOT NULL CHECK (role IN ('user','assistant','system')),
            content text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            FOREIGN KEY (conversation_id, owner_id, workspace_id)
                REFERENCES conversations(id, owner_id, workspace_id) ON DELETE CASCADE
        );

        CREATE TABLE retrieval_runs (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            conversation_id uuid,
            query text NOT NULL,
            configuration jsonb NOT NULL,
            prompt_template_version text,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            FOREIGN KEY (workspace_id, owner_id)
                REFERENCES workspace_memberships(workspace_id, user_id) ON DELETE CASCADE,
            FOREIGN KEY (conversation_id, owner_id, workspace_id)
                REFERENCES conversations(id, owner_id, workspace_id) ON DELETE RESTRICT
        );

        CREATE TABLE retrieval_results (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            retrieval_run_id uuid NOT NULL,
            chunk_id uuid NOT NULL,
            lexical_rank integer CHECK (lexical_rank > 0),
            lexical_score double precision,
            semantic_rank integer CHECK (semantic_rank > 0),
            semantic_score double precision,
            fused_rank integer NOT NULL CHECK (fused_rank > 0),
            fused_score double precision NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (id, retrieval_run_id, chunk_id, owner_id, workspace_id),
            UNIQUE (retrieval_run_id, chunk_id),
            FOREIGN KEY (retrieval_run_id, owner_id, workspace_id)
                REFERENCES retrieval_runs(id, owner_id, workspace_id) ON DELETE CASCADE,
            FOREIGN KEY (chunk_id, owner_id, workspace_id)
                REFERENCES chunks(id, owner_id, workspace_id) ON DELETE RESTRICT
        );

        CREATE TABLE answers (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            retrieval_run_id uuid NOT NULL,
            model_provider text NOT NULL,
            model_identifier text NOT NULL,
            prompt_template_version text NOT NULL,
            generated_answer text,
            status text NOT NULL
                CHECK (status IN ('grounded','insufficient_evidence','validation_failed')),
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (id, retrieval_run_id, owner_id, workspace_id),
            UNIQUE (retrieval_run_id),
            FOREIGN KEY (retrieval_run_id, owner_id, workspace_id)
                REFERENCES retrieval_runs(id, owner_id, workspace_id) ON DELETE RESTRICT
        );

        CREATE TABLE citations (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            answer_id uuid NOT NULL,
            retrieval_run_id uuid NOT NULL,
            retrieval_result_id uuid NOT NULL,
            chunk_id uuid NOT NULL,
            validated boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (answer_id, chunk_id),
            FOREIGN KEY (answer_id, retrieval_run_id, owner_id, workspace_id)
                REFERENCES answers(id, retrieval_run_id, owner_id, workspace_id)
                ON DELETE RESTRICT,
            FOREIGN KEY (
                retrieval_result_id, retrieval_run_id, chunk_id, owner_id, workspace_id
            ) REFERENCES retrieval_results(
                id, retrieval_run_id, chunk_id, owner_id, workspace_id
            ) ON DELETE RESTRICT
        );

        CREATE TABLE memory_proposals (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            normalized_statement text NOT NULL,
            category text NOT NULL,
            evidence_quality double precision NOT NULL CHECK (evidence_quality BETWEEN 0 AND 1),
            status text NOT NULL DEFAULT 'proposed'
                CHECK (status IN ('proposed','rejected','approved')),
            proposed_at timestamptz NOT NULL DEFAULT now(),
            decided_at timestamptz,
            UNIQUE (id, owner_id, workspace_id),
            FOREIGN KEY (workspace_id, owner_id)
                REFERENCES workspace_memberships(workspace_id, user_id) ON DELETE CASCADE
        );

        CREATE TABLE memory_proposal_evidence (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            proposal_id uuid NOT NULL,
            chunk_id uuid NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (proposal_id, chunk_id),
            FOREIGN KEY (proposal_id, owner_id, workspace_id)
                REFERENCES memory_proposals(id, owner_id, workspace_id) ON DELETE RESTRICT,
            FOREIGN KEY (chunk_id, owner_id, workspace_id)
                REFERENCES chunks(id, owner_id, workspace_id) ON DELETE RESTRICT
        );

        CREATE TABLE approved_memories (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            proposal_id uuid NOT NULL,
            current_revision_id uuid,
            status text NOT NULL DEFAULT 'active'
                CHECK (status IN ('active','superseded','archived')),
            approved_at timestamptz NOT NULL,
            superseded_by_id uuid,
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (proposal_id),
            FOREIGN KEY (proposal_id, owner_id, workspace_id)
                REFERENCES memory_proposals(id, owner_id, workspace_id) ON DELETE RESTRICT,
            FOREIGN KEY (superseded_by_id, owner_id, workspace_id)
                REFERENCES approved_memories(id, owner_id, workspace_id) ON DELETE RESTRICT
        );

        CREATE TABLE memory_revisions (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            memory_id uuid NOT NULL,
            revision_number integer NOT NULL CHECK (revision_number > 0),
            normalized_statement text NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (id, memory_id, owner_id, workspace_id),
            UNIQUE (memory_id, revision_number),
            FOREIGN KEY (memory_id, owner_id, workspace_id)
                REFERENCES approved_memories(id, owner_id, workspace_id) ON DELETE RESTRICT
        );

        ALTER TABLE approved_memories
            ADD CONSTRAINT approved_current_revision_fk
            FOREIGN KEY (current_revision_id, id, owner_id, workspace_id)
            REFERENCES memory_revisions(id, memory_id, owner_id, workspace_id)
            DEFERRABLE INITIALLY DEFERRED;

        CREATE TABLE memory_revision_evidence (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            revision_id uuid NOT NULL,
            chunk_id uuid NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (id, owner_id, workspace_id),
            UNIQUE (revision_id, chunk_id),
            FOREIGN KEY (revision_id, owner_id, workspace_id)
                REFERENCES memory_revisions(id, owner_id, workspace_id) ON DELETE RESTRICT,
            FOREIGN KEY (chunk_id, owner_id, workspace_id)
                REFERENCES chunks(id, owner_id, workspace_id) ON DELETE RESTRICT
        );

        CREATE TABLE purge_records (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_id uuid NOT NULL,
            workspace_id uuid NOT NULL,
            source_id uuid,
            source_tombstone_id uuid NOT NULL,
            reason_code text NOT NULL,
            purged_at timestamptz NOT NULL DEFAULT now(),
            original_removed boolean NOT NULL,
            searchable_content_removed boolean NOT NULL,
            UNIQUE (id, owner_id, workspace_id),
            FOREIGN KEY (workspace_id, owner_id)
                REFERENCES workspace_memberships(workspace_id, user_id) ON DELETE RESTRICT
        );

        CREATE FUNCTION enforce_embedding_profile_dimensions() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        DECLARE expected_dimensions integer;
        BEGIN
            SELECT dimensions INTO expected_dimensions
            FROM public.embedding_profiles
            WHERE id = NEW.profile_id
              AND owner_id = NEW.owner_id
              AND workspace_id = NEW.workspace_id;
            IF expected_dimensions IS NULL
               OR vector_dims(NEW.embedding) <> expected_dimensions THEN
                RAISE EXCEPTION 'embedding dimension does not match its profile'
                    USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER embeddings_profile_dimensions
            BEFORE INSERT OR UPDATE ON public.embeddings
            FOR EACH ROW EXECUTE FUNCTION public.enforce_embedding_profile_dimensions();

        CREATE FUNCTION reject_append_only_mutation() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            RAISE EXCEPTION 'append-only records cannot be updated or deleted'
                USING ERRCODE = 'integrity_constraint_violation';
        END;
        $$;
        COMMENT ON FUNCTION reject_append_only_mutation() IS
            'Future purge must use a narrowly scoped SECURITY DEFINER function and transaction; '
            'arbitrary runtime UPDATE and DELETE remain forbidden.';

        CREATE FUNCTION enforce_capture_stage_transition() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF ROW(
                NEW.owner_id, NEW.workspace_id, NEW.object_key, NEW.kind,
                NEW.intended_content_sha256, NEW.intended_size, NEW.source_id,
                NEW.job_id, NEW.created_at
            ) IS DISTINCT FROM ROW(
                OLD.owner_id, OLD.workspace_id, OLD.object_key, OLD.kind,
                OLD.intended_content_sha256, OLD.intended_size, OLD.source_id,
                OLD.job_id, OLD.created_at
            ) THEN
                RAISE EXCEPTION 'capture stage lineage is immutable'
                    USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            IF NOT (
                (OLD.state = 'pending' AND NEW.state IN ('stored','abandoned'))
                OR (OLD.state = 'stored' AND NEW.state IN ('finalized','abandoned'))
                OR OLD.state = NEW.state
            ) THEN
                RAISE EXCEPTION 'invalid capture stage transition'
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER capture_stages_state_machine
            BEFORE UPDATE ON public.capture_stages
            FOR EACH ROW EXECUTE FUNCTION public.enforce_capture_stage_transition();

        CREATE FUNCTION record_initial_ingestion_job_event() RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF NEW.state <> 'queued' OR NEW.attempts <> 0 THEN
                RAISE EXCEPTION 'new ingestion jobs must begin queued at attempt zero'
                    USING ERRCODE = 'check_violation';
            END IF;
            INSERT INTO public.ingestion_job_events (
                owner_id, workspace_id, job_id, attempt, from_state, to_state,
                reason_class, lease_owner, lease_expires_at
            ) VALUES (
                NEW.owner_id, NEW.workspace_id, NEW.id, 0, NULL, 'queued',
                'capture_queued', NULL, NULL
            );
            RETURN NULL;
        END;
        $$;
        CREATE TRIGGER ingestion_jobs_initial_event
            AFTER INSERT ON public.ingestion_jobs
            FOR EACH ROW EXECUTE FUNCTION public.record_initial_ingestion_job_event();

        CREATE FUNCTION enforce_ingestion_job_state_event() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF ROW(NEW.state, NEW.attempts) IS DISTINCT FROM ROW(OLD.state, OLD.attempts)
               AND NOT EXISTS (
                    SELECT 1
                    FROM public.ingestion_job_events AS event
                    WHERE event.job_id = NEW.id
                      AND event.owner_id = NEW.owner_id
                      AND event.workspace_id = NEW.workspace_id
                      AND event.attempt = NEW.attempts
                      AND event.from_state = OLD.state
                      AND event.to_state = NEW.state
                      AND event.transaction_id = txid_current()
               ) THEN
                RAISE EXCEPTION 'ingestion job state transition requires a paired event'
                    USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN NULL;
        END;
        $$;
        CREATE CONSTRAINT TRIGGER ingestion_jobs_state_event_required
            AFTER UPDATE OF state, attempts ON public.ingestion_jobs
            DEFERRABLE INITIALLY IMMEDIATE
            FOR EACH ROW EXECUTE FUNCTION public.enforce_ingestion_job_state_event();

        CREATE FUNCTION protect_ingestion_job_lineage() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF ROW(NEW.owner_id,NEW.workspace_id,NEW.source_id,NEW.requested_uri,NEW.created_at)
               IS DISTINCT FROM
               ROW(OLD.owner_id,OLD.workspace_id,OLD.source_id,OLD.requested_uri,OLD.created_at)
               OR (OLD.source_version_id IS NOT NULL
                   AND NEW.source_version_id IS DISTINCT FROM OLD.source_version_id)
               OR (OLD.source_version_id IS NULL AND NEW.source_version_id IS NULL
                   AND NEW.requested_uri IS NULL) THEN
                RAISE EXCEPTION 'ingestion job lineage is immutable'
                    USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER ingestion_jobs_lineage_immutable
            BEFORE UPDATE ON public.ingestion_jobs
            FOR EACH ROW EXECUTE FUNCTION public.protect_ingestion_job_lineage();

        CREATE FUNCTION protect_source_provenance() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF ROW(
                NEW.owner_id, NEW.workspace_id, NEW.source_type, NEW.original_uri,
                NEW.object_key, NEW.content_sha256, NEW.normalized_dedup_sha256,
                NEW.mime_type, NEW.ingested_at
            ) IS DISTINCT FROM ROW(
                OLD.owner_id, OLD.workspace_id, OLD.source_type, OLD.original_uri,
                OLD.object_key, OLD.content_sha256, OLD.normalized_dedup_sha256,
                OLD.mime_type, OLD.ingested_at
            ) THEN
                RAISE EXCEPTION 'source provenance is immutable'
                    USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER sources_provenance_immutable
            BEFORE UPDATE ON public.sources
            FOR EACH ROW EXECUTE FUNCTION public.protect_source_provenance();

        CREATE FUNCTION reject_late_memory_proposal_evidence() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        DECLARE proposal_status text;
        BEGIN
            SELECT status INTO proposal_status
            FROM public.memory_proposals
            WHERE id = NEW.proposal_id
              AND owner_id = NEW.owner_id
              AND workspace_id = NEW.workspace_id
            FOR SHARE;
            IF proposal_status IS DISTINCT FROM 'proposed' THEN
                RAISE EXCEPTION 'proposal evidence is frozen after decision'
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER memory_proposal_evidence_freeze
            BEFORE INSERT ON public.memory_proposal_evidence
            FOR EACH ROW EXECUTE FUNCTION public.reject_late_memory_proposal_evidence();

        CREATE FUNCTION enforce_memory_proposal_invariants() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        DECLARE proposal_status text;
        BEGIN
            SELECT status INTO proposal_status
            FROM public.memory_proposals
            WHERE id = NEW.id;
            IF NOT EXISTS (
                SELECT 1 FROM public.memory_proposal_evidence WHERE proposal_id = NEW.id
            ) THEN
                RAISE EXCEPTION 'memory proposal requires evidence'
                    USING ERRCODE = 'check_violation';
            END IF;
            IF proposal_status <> 'approved' AND EXISTS (
                SELECT 1 FROM public.approved_memories WHERE proposal_id = NEW.id
            ) THEN
                RAISE EXCEPTION 'active memory requires an explicitly approved proposal'
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NULL;
        END;
        $$;
        CREATE CONSTRAINT TRIGGER memory_proposals_commit_invariants
            AFTER INSERT OR UPDATE ON public.memory_proposals
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION public.enforce_memory_proposal_invariants();

        CREATE FUNCTION enforce_approved_memory_invariants() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        DECLARE proposal_status text;
        DECLARE proposal uuid;
        DECLARE initial_revision uuid;
        DECLARE current_revision uuid;
        BEGIN
            SELECT proposal_row.status, memory.proposal_id, memory.current_revision_id
            INTO proposal_status, proposal, current_revision
            FROM public.approved_memories AS memory
            JOIN public.memory_proposals AS proposal_row ON proposal_row.id = memory.proposal_id
            WHERE memory.id = NEW.id;
            IF proposal_status IS DISTINCT FROM 'approved' THEN
                RAISE EXCEPTION 'active memory requires an explicitly approved proposal'
                    USING ERRCODE = 'check_violation';
            END IF;
            SELECT id INTO initial_revision
            FROM public.memory_revisions
            WHERE memory_id = NEW.id
              AND owner_id = NEW.owner_id
              AND workspace_id = NEW.workspace_id
              AND revision_number = 1;
            IF initial_revision IS NULL THEN
                RAISE EXCEPTION 'approved memory requires an initial revision'
                    USING ERRCODE = 'check_violation';
            END IF;
            IF current_revision IS NULL OR NOT EXISTS (
                SELECT 1
                FROM public.memory_revisions AS revision
                WHERE revision.id = current_revision
                  AND revision.memory_id = NEW.id
                  AND revision.owner_id = NEW.owner_id
                  AND revision.workspace_id = NEW.workspace_id
                  AND EXISTS (
                      SELECT 1 FROM public.memory_revision_evidence
                      WHERE revision_id = revision.id
                  )
            ) THEN
                RAISE EXCEPTION 'approved memory requires its own evidenced current revision'
                    USING ERRCODE = 'check_violation';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM public.memory_proposal_evidence AS proposal_evidence
                WHERE proposal_evidence.proposal_id = proposal
                  AND NOT EXISTS (
                      SELECT 1
                      FROM public.memory_revision_evidence AS revision_evidence
                      WHERE revision_evidence.revision_id = initial_revision
                        AND revision_evidence.chunk_id = proposal_evidence.chunk_id
                  )
            ) THEN
                RAISE EXCEPTION 'initial memory revision must preserve proposal evidence'
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NULL;
        END;
        $$;
        CREATE CONSTRAINT TRIGGER approved_memories_commit_invariants
            AFTER INSERT OR UPDATE ON public.approved_memories
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION public.enforce_approved_memory_invariants();

        CREATE FUNCTION enforce_memory_revision_invariants() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM public.memory_revision_evidence WHERE revision_id = NEW.id
            ) THEN
                RAISE EXCEPTION 'memory revision requires evidence'
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NULL;
        END;
        $$;
        CREATE CONSTRAINT TRIGGER memory_revisions_commit_invariants
            AFTER INSERT OR UPDATE ON public.memory_revisions
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION public.enforce_memory_revision_invariants();

        CREATE FUNCTION reject_late_initial_revision_evidence() RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        DECLARE initial_revision_is_activated boolean;
        BEGIN
            SELECT revision.revision_number = 1 AND memory.current_revision_id IS NOT NULL
            INTO initial_revision_is_activated
            FROM public.memory_revisions AS revision
            JOIN public.approved_memories AS memory ON memory.id = revision.memory_id
            WHERE revision.id = NEW.revision_id;
            IF initial_revision_is_activated THEN
                RAISE EXCEPTION 'initial revision evidence is frozen after activation'
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER memory_initial_revision_evidence_freeze
            BEFORE INSERT ON public.memory_revision_evidence
            FOR EACH ROW EXECUTE FUNCTION public.reject_late_initial_revision_evidence();

        CREATE FUNCTION resolve_second_brain_session(p_token_hash text)
        RETURNS TABLE (
            session_id uuid,
            owner_id uuid,
            workspace_id uuid,
            csrf_token_hash char(64),
            absolute_expires_at timestamptz,
            idle_expires_at timestamptz
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            RETURN QUERY
            UPDATE public.sessions AS session
            SET last_seen_at = clock_timestamp(),
                idle_expires_at = LEAST(
                    session.absolute_expires_at,
                    clock_timestamp() + make_interval(secs => session.idle_timeout_seconds)
                )
            WHERE session.token_hash = p_token_hash
              AND session.revoked_at IS NULL
              AND session.absolute_expires_at > clock_timestamp()
              AND session.idle_expires_at > clock_timestamp()
            RETURNING session.id, session.owner_id, session.workspace_id,
                session.csrf_token_hash, session.absolute_expires_at, session.idle_expires_at;
        END;
        $$;
        REVOKE ALL ON FUNCTION resolve_second_brain_session(text) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION resolve_second_brain_session(text) TO second_brain_app;

        CREATE FUNCTION consume_trusted_exchange_attempt(
            p_peer_address inet,
            p_issuer text,
            p_owner_id uuid,
            p_workspace_id uuid,
            p_limit integer,
            p_window_seconds integer
        ) RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE allowed boolean;
        BEGIN
            IF p_limit < 1 OR p_window_seconds < 1 THEN
                RETURN false;
            END IF;
            INSERT INTO public.trusted_exchange_rate_limits AS rate_limit (
                peer_address, issuer, owner_id, workspace_id, window_started_at, attempts
            ) VALUES (
                p_peer_address, p_issuer, p_owner_id, p_workspace_id, clock_timestamp(), 1
            )
            ON CONFLICT (peer_address, issuer, owner_id, workspace_id) DO UPDATE
            SET attempts = CASE
                    WHEN rate_limit.window_started_at
                        + make_interval(secs => p_window_seconds) <= clock_timestamp()
                    THEN 1 ELSE rate_limit.attempts + 1 END,
                window_started_at = CASE
                    WHEN rate_limit.window_started_at
                        + make_interval(secs => p_window_seconds) <= clock_timestamp()
                    THEN clock_timestamp() ELSE rate_limit.window_started_at END
            RETURNING attempts <= p_limit INTO allowed;
            RETURN allowed;
        END;
        $$;
        REVOKE ALL ON FUNCTION consume_trusted_exchange_attempt(
            inet, text, uuid, uuid, integer, integer
        ) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION consume_trusted_exchange_attempt(
            inet, text, uuid, uuid, integer, integer
        ) TO second_brain_app;

        CREATE FUNCTION claim_ingestion_job(p_worker text, p_lease_seconds integer)
        RETURNS TABLE (
            job_id uuid, owner_id uuid, workspace_id uuid,
            source_id uuid, source_version_id uuid, attempts integer
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE
            candidate public.ingestion_jobs%ROWTYPE;
            exhausted public.ingestion_jobs%ROWTYPE;
        BEGIN
            IF p_worker IS NULL OR length(p_worker) NOT BETWEEN 1 AND 200
               OR p_lease_seconds NOT BETWEEN 1 AND 3600 THEN
                RAISE EXCEPTION 'invalid dispatcher claim arguments'
                    USING ERRCODE = 'invalid_parameter_value';
            END IF;

            SELECT job.* INTO exhausted
            FROM public.ingestion_jobs AS job
            WHERE job.state IN ('queued','processing')
              AND job.attempts >= 3
              AND (job.lease_expires_at IS NULL OR job.lease_expires_at <= clock_timestamp())
            ORDER BY job.available_at,job.id
            FOR UPDATE SKIP LOCKED LIMIT 1;
            IF FOUND THEN
                INSERT INTO public.ingestion_job_events (
                    owner_id, workspace_id, job_id, attempt, from_state, to_state,
                    reason_class, lease_owner, lease_expires_at
                ) VALUES (
                    exhausted.owner_id, exhausted.workspace_id, exhausted.id,
                    exhausted.attempts, exhausted.state, 'dead', 'attempts_exhausted',
                    exhausted.lease_owner, exhausted.lease_expires_at
                );
                UPDATE public.sources AS source
                SET processing_state='failed', processing_error_code='attempts_exhausted',
                    processing_error_message='Ingestion retry limit exhausted.'
                WHERE source.id=exhausted.source_id;
                UPDATE public.ingestion_jobs AS job
                SET state='dead', lease_owner=NULL, lease_expires_at=NULL,
                    updated_at=clock_timestamp(), error_code='attempts_exhausted',
                    error_message='Ingestion retry limit exhausted.'
                WHERE job.id=exhausted.id;
            END IF;

            SELECT job.* INTO candidate
            FROM public.ingestion_jobs AS job
            WHERE job.state IN ('queued','processing')
              AND job.attempts < 3
              AND job.available_at <= clock_timestamp()
              AND (job.state='queued' OR job.lease_expires_at <= clock_timestamp())
            ORDER BY job.available_at,job.id
            FOR UPDATE SKIP LOCKED LIMIT 1;
            IF NOT FOUND THEN
                RETURN;
            END IF;

            INSERT INTO public.ingestion_job_events (
                owner_id, workspace_id, job_id, attempt, from_state, to_state,
                reason_class, lease_owner, lease_expires_at
            ) VALUES (
                candidate.owner_id, candidate.workspace_id, candidate.id,
                candidate.attempts + 1, candidate.state, 'processing',
                CASE WHEN candidate.state = 'processing' THEN 'lease_reclaimed' ELSE 'claimed' END,
                p_worker, clock_timestamp()+make_interval(secs => p_lease_seconds)
            );
            UPDATE public.ingestion_jobs AS job
            SET state='processing', attempts=job.attempts+1, lease_owner=p_worker,
                lease_expires_at=clock_timestamp()+make_interval(secs => p_lease_seconds),
                heartbeat_at=clock_timestamp(), updated_at=clock_timestamp()
            WHERE job.id=candidate.id;
            UPDATE public.sources AS source
            SET processing_state='processing'
            WHERE source.id=candidate.source_id;
            RETURN QUERY SELECT candidate.id, candidate.owner_id, candidate.workspace_id,
                candidate.source_id, candidate.source_version_id, candidate.attempts + 1;
        END;
        $$;
        REVOKE ALL ON FUNCTION claim_ingestion_job(text, integer) FROM PUBLIC;
        REVOKE ALL ON FUNCTION claim_ingestion_job(text, integer) FROM second_brain_app;
        GRANT EXECUTE ON FUNCTION claim_ingestion_job(text, integer) TO second_brain_worker;

        CREATE FUNCTION heartbeat_ingestion_job(
            p_job_id uuid, p_worker text, p_lease_seconds integer
        ) RETURNS boolean
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            UPDATE public.ingestion_jobs AS job
            SET heartbeat_at=clock_timestamp(),
                lease_expires_at=clock_timestamp()+make_interval(secs => p_lease_seconds),
                updated_at=clock_timestamp()
            WHERE p_lease_seconds BETWEEN 1 AND 3600
              AND job.id=p_job_id AND job.state='processing'
              AND job.lease_owner=p_worker AND job.lease_expires_at>clock_timestamp()
            RETURNING true;
        $$;
        REVOKE ALL ON FUNCTION heartbeat_ingestion_job(uuid, text, integer) FROM PUBLIC;
        REVOKE ALL ON FUNCTION heartbeat_ingestion_job(uuid, text, integer)
            FROM second_brain_app;
        GRANT EXECUTE ON FUNCTION heartbeat_ingestion_job(uuid, text, integer)
            TO second_brain_worker;

        CREATE FUNCTION list_stale_capture_stages(
            p_age_seconds integer, p_limit integer
        ) RETURNS TABLE (
            stage_id uuid, job_id uuid, owner_id uuid, workspace_id uuid, source_id uuid,
            source_version_id uuid, object_key text, intended_content_sha256 char(64),
            intended_size bigint, stage_state text
        )
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT stage.id, stage.job_id, stage.owner_id, stage.workspace_id, stage.source_id,
                job.source_version_id,
                stage.object_key, stage.intended_content_sha256,
                stage.intended_size, stage.state
            FROM public.capture_stages AS stage
            JOIN public.ingestion_jobs AS job
              ON job.id=stage.job_id
             AND job.owner_id=stage.owner_id
             AND job.workspace_id=stage.workspace_id
             AND job.source_id=stage.source_id
            WHERE p_age_seconds BETWEEN 1 AND 86400
              AND p_limit BETWEEN 1 AND 1000
              AND stage.state IN ('pending','stored')
              AND stage.created_at <= clock_timestamp()
                    - make_interval(secs => p_age_seconds)
              AND NOT (
                  job.state='processing'
                  AND job.lease_expires_at>clock_timestamp()
              )
            ORDER BY stage.created_at,stage.id
            LIMIT p_limit;
        $$;
        REVOKE ALL ON FUNCTION list_stale_capture_stages(integer,integer) FROM PUBLIC;
        REVOKE ALL ON FUNCTION list_stale_capture_stages(integer,integer)
            FROM second_brain_app;
        GRANT EXECUTE ON FUNCTION list_stale_capture_stages(integer,integer)
            TO second_brain_worker;

        CREATE FUNCTION transition_ingestion_job(
            p_job_id uuid,
            p_worker text,
            p_to_state text,
            p_reason_class text,
            p_error_code text,
            p_safe_message text,
            p_available_delay_seconds integer
        ) RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE job public.ingestion_jobs%ROWTYPE;
        DECLARE source_state text;
        BEGIN
            IF p_to_state NOT IN ('queued','ready','failed','dead')
               OR p_reason_class IS NULL OR length(p_reason_class) NOT BETWEEN 1 AND 100
               OR p_available_delay_seconds NOT BETWEEN 0 AND 3600
               OR length(coalesce(p_error_code, '')) > 100
               OR length(coalesce(p_safe_message, '')) > 200 THEN
                RAISE EXCEPTION 'invalid dispatcher transition arguments'
                    USING ERRCODE = 'invalid_parameter_value';
            END IF;
            SELECT candidate.* INTO job
            FROM public.ingestion_jobs AS candidate
            WHERE candidate.id=p_job_id AND candidate.state='processing'
              AND candidate.lease_owner=p_worker
              AND candidate.lease_expires_at>clock_timestamp()
            FOR UPDATE;
            IF NOT FOUND THEN
                RETURN false;
            END IF;
            INSERT INTO public.ingestion_job_events (
                owner_id, workspace_id, job_id, attempt, from_state, to_state,
                reason_class, lease_owner, lease_expires_at
            ) VALUES (
                job.owner_id, job.workspace_id, job.id, job.attempts, job.state,
                p_to_state, p_reason_class, job.lease_owner, job.lease_expires_at
            );
            UPDATE public.ingestion_jobs AS target
            SET state=p_to_state,
                available_at=CASE WHEN p_to_state='queued'
                    THEN clock_timestamp()+make_interval(secs => p_available_delay_seconds)
                    ELSE target.available_at END,
                lease_owner=NULL, lease_expires_at=NULL,
                error_code=CASE WHEN p_to_state='ready' THEN NULL ELSE p_error_code END,
                error_message=CASE WHEN p_to_state='ready' THEN NULL ELSE p_safe_message END,
                updated_at=clock_timestamp()
            WHERE target.id=job.id;
            source_state := CASE
                WHEN p_to_state='ready' THEN 'ready'
                WHEN p_to_state='queued' THEN 'queued'
                ELSE 'failed'
            END;
            UPDATE public.sources AS source
            SET processing_state=source_state,
                processing_error_code=CASE WHEN p_to_state='ready' THEN NULL ELSE p_error_code END,
                processing_error_message=CASE
                    WHEN p_to_state='ready' THEN NULL ELSE p_safe_message END
            WHERE source.id=job.source_id;
            RETURN true;
        END;
        $$;
        REVOKE ALL ON FUNCTION transition_ingestion_job(
            uuid, text, text, text, text, text, integer
        ) FROM PUBLIC;
        REVOKE ALL ON FUNCTION transition_ingestion_job(
            uuid, text, text, text, text, text, integer
        ) FROM second_brain_app;
        GRANT EXECUTE ON FUNCTION transition_ingestion_job(
            uuid, text, text, text, text, text, integer
        ) TO second_brain_worker;

        CREATE FUNCTION abandon_capture_stage(p_stage_id uuid, p_reason_class text)
        RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        DECLARE stage public.capture_stages%ROWTYPE;
        DECLARE job public.ingestion_jobs%ROWTYPE;
        DECLARE scoped_owner uuid;
        DECLARE scoped_workspace uuid;
        BEGIN
            scoped_owner := nullif(current_setting('app.owner_id', true), '')::uuid;
            scoped_workspace := nullif(current_setting('app.workspace_id', true), '')::uuid;
            IF scoped_owner IS NULL OR scoped_workspace IS NULL
               OR p_reason_class IS NULL OR length(p_reason_class) NOT BETWEEN 1 AND 100 THEN
                RETURN false;
            END IF;
            SELECT candidate.* INTO stage
            FROM public.capture_stages AS candidate
            WHERE candidate.id=p_stage_id
              AND candidate.owner_id=scoped_owner
              AND candidate.workspace_id=scoped_workspace
              AND candidate.state IN ('pending','stored')
            FOR UPDATE;
            IF NOT FOUND THEN
                RETURN false;
            END IF;
            SELECT candidate.* INTO job
            FROM public.ingestion_jobs AS candidate
            WHERE candidate.id=stage.job_id
              AND candidate.source_id=stage.source_id
              AND candidate.owner_id=stage.owner_id
              AND candidate.workspace_id=stage.workspace_id
              AND (
                  candidate.state='queued'
                  OR (
                      candidate.state='processing'
                      AND candidate.lease_expires_at<=clock_timestamp()
                  )
                  OR candidate.state IN ('failed','dead')
              )
            FOR UPDATE;
            IF NOT FOUND THEN
                RETURN false;
            END IF;
            UPDATE public.capture_stages AS target
            SET state='abandoned', abandoned_at=clock_timestamp(),
                error_class=p_reason_class
            WHERE target.id=stage.id;
            IF job.state IN ('failed','dead') THEN
                RETURN true;
            END IF;
            INSERT INTO public.ingestion_job_events (
                owner_id,workspace_id,job_id,attempt,from_state,to_state,reason_class
            ) VALUES (
                job.owner_id,job.workspace_id,job.id,job.attempts,job.state,
                'failed',p_reason_class
            );
            UPDATE public.ingestion_jobs AS target
            SET state='failed',error_code=p_reason_class,
                error_message='Capture storage reconciliation failed.',
                lease_owner=NULL,lease_expires_at=NULL,
                updated_at=clock_timestamp()
            WHERE target.id=job.id;
            UPDATE public.sources AS source
            SET processing_state='failed',processing_error_code=p_reason_class,
                processing_error_message='Capture storage reconciliation failed.'
            WHERE source.id=job.source_id;
            RETURN true;
        END;
        $$;
        REVOKE ALL ON FUNCTION abandon_capture_stage(uuid,text) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION abandon_capture_stage(uuid,text) TO second_brain_app;
        """
    )

    for signature in OWNED_FUNCTION_SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC")

    for table in APPEND_ONLY_TABLES:
        op.execute(
            f'CREATE TRIGGER "{table}_append_only" '
            f'BEFORE UPDATE OR DELETE ON public."{table}" '
            "FOR EACH ROW EXECUTE FUNCTION public.reject_append_only_mutation()"
        )

    for table in TENANT_TABLES:
        if table == "workspaces":
            using = (
                "owner_id = nullif(current_setting('app.owner_id', true), '')::uuid "
                "AND id = nullif(current_setting('app.workspace_id', true), '')::uuid"
            )
        elif table == "workspace_memberships":
            using = (
                "user_id = nullif(current_setting('app.owner_id', true), '')::uuid "
                "AND workspace_id = nullif(current_setting('app.workspace_id', true), '')::uuid"
            )
        else:
            using = (
                "owner_id = nullif(current_setting('app.owner_id', true), '')::uuid "
                "AND workspace_id = nullif(current_setting('app.workspace_id', true), '')::uuid"
            )
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(f'CREATE POLICY tenant_scope ON "{table}" USING ({using}) WITH CHECK ({using})')

    op.execute("ALTER TABLE users ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE users FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY owner_scope ON users "
        "USING (id = nullif(current_setting('app.owner_id', true), '')::uuid) "
        "WITH CHECK (id = nullif(current_setting('app.owner_id', true), '')::uuid)"
    )
    op.execute("ALTER TABLE trusted_exchange_rate_limits ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE trusted_exchange_rate_limits FORCE ROW LEVEL SECURITY")
    op.execute("REVOKE ALL ON trusted_exchange_rate_limits FROM second_brain_app")
    op.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA public TO second_brain_app")
    op.execute("GRANT USAGE ON SCHEMA public TO second_brain_worker")
    op.execute(
        "GRANT SELECT ON users, workspaces, workspace_memberships, sessions, "
        "used_assertion_nonces, projects, sources, "
        "source_versions, capture_stages, ingestion_jobs, ingestion_job_events, url_fetches, "
        "documents, "
        "chunks, embedding_profiles, embeddings, "
        "tags, source_tags, conversations, messages, retrieval_runs, retrieval_results, answers, "
        "citations, memory_proposals, memory_proposal_evidence, approved_memories, "
        "memory_revisions, memory_revision_evidence, purge_records TO second_brain_app"
    )
    op.execute(
        "GRANT INSERT ON sessions, used_assertion_nonces, projects, sources, source_versions, "
        "ingestion_jobs, capture_stages, url_fetches, documents, chunks, "
        "embedding_profiles, embeddings, tags, source_tags, conversations, messages, "
        "retrieval_runs, retrieval_results, answers, citations, memory_proposals, "
        "memory_proposal_evidence, approved_memories, memory_revisions, "
        "memory_revision_evidence, purge_records TO second_brain_app"
    )
    op.execute(
        "GRANT UPDATE (is_active) ON projects TO second_brain_app; "
        "GRANT UPDATE (last_seen_at, idle_expires_at, revoked_at) ON sessions "
        "TO second_brain_app; "
        "GRANT UPDATE (processing_state, processing_error_code, processing_error_message, "
        "semantic_state, deleted_at) "
        "ON sources TO second_brain_app; "
        "GRANT UPDATE (state, stored_at, finalized_at, abandoned_at, error_class, "
        "source_version_id) ON capture_stages TO second_brain_app; "
        "GRANT UPDATE (source_version_id, pipeline_checkpoint, semantic_state, "
        "semantic_error_class) ON ingestion_jobs TO second_brain_app; "
        "GRANT UPDATE (status, decided_at) ON memory_proposals TO second_brain_app; "
        "GRANT UPDATE (current_revision_id, status, superseded_by_id) "
        "ON approved_memories TO second_brain_app"
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS purge_records CASCADE;
        DROP TABLE IF EXISTS memory_revision_evidence CASCADE;
        DROP TABLE IF EXISTS memory_revisions CASCADE;
        DROP TABLE IF EXISTS approved_memories CASCADE;
        DROP TABLE IF EXISTS memory_proposal_evidence CASCADE;
        DROP TABLE IF EXISTS memory_proposals CASCADE;
        DROP TABLE IF EXISTS citations CASCADE;
        DROP TABLE IF EXISTS answers CASCADE;
        DROP TABLE IF EXISTS retrieval_results CASCADE;
        DROP TABLE IF EXISTS retrieval_runs CASCADE;
        DROP TABLE IF EXISTS messages CASCADE;
        DROP TABLE IF EXISTS conversations CASCADE;
        DROP TABLE IF EXISTS source_tags CASCADE;
        DROP TABLE IF EXISTS tags CASCADE;
        DROP TABLE IF EXISTS embeddings CASCADE;
        DROP TABLE IF EXISTS embedding_profiles CASCADE;
        DROP TABLE IF EXISTS chunks CASCADE;
        DROP TABLE IF EXISTS documents CASCADE;
        DROP TABLE IF EXISTS ingestion_job_events CASCADE;
        DROP TABLE IF EXISTS url_fetches CASCADE;
        DROP TABLE IF EXISTS ingestion_jobs CASCADE;
        DROP TABLE IF EXISTS capture_stages CASCADE;
        DROP TABLE IF EXISTS source_versions CASCADE;
        DROP TABLE IF EXISTS sources CASCADE;
        DROP TABLE IF EXISTS projects CASCADE;
        DROP FUNCTION IF EXISTS claim_ingestion_job(text, integer);
        DROP FUNCTION IF EXISTS heartbeat_ingestion_job(uuid, text, integer);
        DROP FUNCTION IF EXISTS list_stale_capture_stages(integer, integer);
        DROP FUNCTION IF EXISTS transition_ingestion_job(
            uuid, text, text, text, text, text, integer
        );
        DROP FUNCTION IF EXISTS abandon_capture_stage(uuid, text);
        DROP FUNCTION IF EXISTS consume_trusted_exchange_attempt(
            inet, text, uuid, uuid, integer, integer
        );
        DROP TABLE IF EXISTS trusted_exchange_rate_limits CASCADE;
        DROP FUNCTION IF EXISTS resolve_second_brain_session(text);
        DROP TABLE IF EXISTS used_assertion_nonces CASCADE;
        DROP TABLE IF EXISTS sessions CASCADE;
        DROP TABLE IF EXISTS workspace_memberships CASCADE;
        DROP TABLE IF EXISTS workspaces CASCADE;
        DROP TABLE IF EXISTS users CASCADE;
        DROP FUNCTION IF EXISTS protect_source_provenance();
        DROP FUNCTION IF EXISTS protect_ingestion_job_lineage();
        DROP FUNCTION IF EXISTS enforce_capture_stage_transition();
        DROP FUNCTION IF EXISTS record_initial_ingestion_job_event();
        DROP FUNCTION IF EXISTS enforce_ingestion_job_state_event();
        DROP FUNCTION IF EXISTS enforce_memory_revision_invariants();
        DROP FUNCTION IF EXISTS reject_late_initial_revision_evidence();
        DROP FUNCTION IF EXISTS enforce_approved_memory_invariants();
        DROP FUNCTION IF EXISTS enforce_memory_proposal_invariants();
        DROP FUNCTION IF EXISTS reject_late_memory_proposal_evidence();
        DROP FUNCTION IF EXISTS reject_append_only_mutation();
        DROP FUNCTION IF EXISTS enforce_embedding_profile_dimensions();
        DO $$
        BEGIN
            EXECUTE format(
                'GRANT TEMPORARY ON DATABASE %I TO PUBLIC', current_database()
            );
        END;
        $$;
        """
    )
