import re
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import DBAPIError

ADMIN_SERVER_URL = (
    "postgresql+psycopg://second_brain_owner:second_brain_owner_dev@127.0.0.1:55439/postgres"
)
EXPECTED_TABLES = {
    "alembic_version",
    "users",
    "workspaces",
    "workspace_memberships",
    "sessions",
    "used_assertion_nonces",
    "trusted_exchange_rate_limits",
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
    "memory_actions",
    "purge_operations",
    "purge_operation_events",
    "memory_evidence_tombstones",
    "memory_resurfacing_events",
    "policy_decisions",
    "purge_records",
}
RLS_TABLES = EXPECTED_TABLES - {
    "alembic_version",
    "users",
    "trusted_exchange_rate_limits",
}
EXPECTED_POLICIES = {(table, "tenant_scope") for table in RLS_TABLES} | {("users", "owner_scope")}
APPEND_ONLY_TABLES = {
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
    "memory_actions",
    "purge_operation_events",
    "memory_evidence_tombstones",
    "memory_resurfacing_events",
    "policy_decisions",
}
APPLICATION_FUNCTIONS = {
    "abandon_capture_stage",
    "claim_ingestion_job",
    "heartbeat_ingestion_job",
    "list_stale_capture_stages",
    "transition_ingestion_job",
    "enforce_capture_stage_transition",
    "record_initial_ingestion_job_event",
    "enforce_ingestion_job_state_event",
    "consume_trusted_exchange_attempt",
    "enforce_citation_current_evidence",
    "enforce_approved_memory_invariants",
    "enforce_embedding_profile_dimensions",
    "enforce_memory_proposal_invariants",
    "enforce_memory_revision_invariants",
    "enforce_selected_retrieval_result_current",
    "protect_source_provenance",
    "protect_ingestion_job_lineage",
    "reject_append_only_mutation",
    "reject_late_initial_revision_evidence",
    "reject_late_memory_proposal_evidence",
    "resolve_second_brain_session",
    "derive_memory_revision_metadata",
    "enforce_memory_evidence_current",
    "claim_purge_operation",
    "retry_purge_operation",
    "finalize_source_purge",
    "finalize_memory_purge",
    "set_project_updated_at",
    "set_ingestion_finished_at",
}

APP_ROLE_DELETE_TABLES = {"projects", "tags", "source_tags"}
WORKER_FUNCTIONS = {
    "claim_ingestion_job",
    "heartbeat_ingestion_job",
    "transition_ingestion_job",
    "list_stale_capture_stages",
    "claim_purge_operation",
    "retry_purge_operation",
    "finalize_source_purge",
    "finalize_memory_purge",
}


def guarded_test_database_url() -> URL:
    base = make_url(ADMIN_SERVER_URL)
    assert base.host in {"127.0.0.1", "localhost"}
    database = f"second_brain_test_{uuid4().hex}"
    assert re.fullmatch(r"second_brain_test_[0-9a-f]{32}", database)
    return base.set(database=database)


def alembic_config(database_url: URL) -> Config:
    root = Path(__file__).parents[1]
    config = Config(root / "alembic.ini")
    config.set_main_option("script_location", str(root / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.render_as_string(hide_password=False))
    return config


def create_test_database(database_url: URL) -> None:
    assert database_url.database is not None
    assert re.fullmatch(r"second_brain_test_[0-9a-f]{32}", database_url.database)
    engine = create_engine(ADMIN_SERVER_URL, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database_url.database}"')
    finally:
        engine.dispose()


def drop_test_database(database_url: URL) -> None:
    assert database_url.database is not None
    assert re.fullmatch(r"second_brain_test_[0-9a-f]{32}", database_url.database)
    engine = create_engine(ADMIN_SERVER_URL, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :database AND pid <> pg_backend_pid()"
                ),
                {"database": database_url.database},
            )
            connection.exec_driver_sql(f'DROP DATABASE "{database_url.database}"')
    finally:
        engine.dispose()


def assert_schema(database_url: URL) -> None:
    engine = create_engine(database_url)
    try:
        schema_inspector = inspect(engine)
        assert set(schema_inspector.get_table_names()) == EXPECTED_TABLES
        with engine.connect() as connection:
            extensions = set(connection.scalars(text("SELECT extname FROM pg_extension")))
            assert extensions == {"pgcrypto", "plpgsql", "vector"}
            policies = {
                (row[0], row[1])
                for row in connection.execute(
                    text("SELECT tablename, policyname FROM pg_policies ORDER BY tablename")
                )
            }
            assert policies == EXPECTED_POLICIES
            forced = {
                row[0]
                for row in connection.execute(
                    text(
                        "SELECT relname FROM pg_class "
                        "WHERE relname = ANY(:tables) AND relforcerowsecurity"
                    ),
                    {"tables": sorted(EXPECTED_TABLES - {"alembic_version"})},
                )
            }
            assert forced == EXPECTED_TABLES - {"alembic_version"}
            source_columns = {column["name"] for column in schema_inspector.get_columns("sources")}
            assert source_columns >= {
                "content_sha256",
                "normalized_dedup_sha256",
                "original_filename",
                "source_metadata",
                "idempotency_key",
                "processing_error_message",
                "semantic_state",
            }
            job_columns = {
                column["name"] for column in schema_inspector.get_columns("ingestion_jobs")
            }
            assert job_columns >= {
                "available_at",
                "lease_owner",
                "lease_expires_at",
                "heartbeat_at",
                "attempts",
                "error_code",
                "error_message",
                "requested_uri",
                "pipeline_checkpoint",
                "semantic_state",
                "semantic_error_class",
                "finished_at",
            }
            job_column_map = {
                column["name"]: column for column in schema_inspector.get_columns("ingestion_jobs")
            }
            assert job_column_map["source_version_id"]["nullable"] is True
            stage_column_map = {
                column["name"]: column for column in schema_inspector.get_columns("capture_stages")
            }
            assert stage_column_map["job_id"]["nullable"] is False
            stage_job_foreign_keys = [
                foreign_key
                for foreign_key in schema_inspector.get_foreign_keys("capture_stages")
                if foreign_key["referred_table"] == "ingestion_jobs"
            ]
            assert len(stage_job_foreign_keys) == 1
            assert stage_job_foreign_keys[0]["constrained_columns"] == [
                "job_id",
                "owner_id",
                "workspace_id",
                "source_id",
            ]
            assert stage_job_foreign_keys[0]["referred_columns"] == [
                "id",
                "owner_id",
                "workspace_id",
                "source_id",
            ]
            retrieval_run_columns = {
                column["name"] for column in schema_inspector.get_columns("retrieval_runs")
            }
            assert retrieval_run_columns >= {
                "semantic_status",
                "request_fingerprint",
                "idempotency_key",
            }
            retrieval_result_columns = {
                column["name"] for column in schema_inspector.get_columns("retrieval_results")
            }
            assert retrieval_result_columns >= {
                "source_id",
                "source_version_id",
                "selected",
                "evidence_ordinal",
                "evidence_text",
                "evidence_char_start",
                "evidence_char_end",
            }
            retrieval_result_column_map = {
                column["name"]: column
                for column in schema_inspector.get_columns("retrieval_results")
            }
            assert retrieval_result_column_map["source_id"]["nullable"] is False
            assert retrieval_result_column_map["source_version_id"]["nullable"] is False
            citation_column_map = {
                column["name"]: column for column in schema_inspector.get_columns("citations")
            }
            assert citation_column_map.keys() >= {
                "source_id",
                "source_version_id",
                "statement_id",
                "statement_index",
                "evidence_ordinal",
                "char_start",
                "char_end",
            }
            for required_column in (
                "source_id",
                "source_version_id",
                "statement_id",
                "statement_index",
                "evidence_ordinal",
                "char_start",
                "char_end",
            ):
                assert citation_column_map[required_column]["nullable"] is False
            answer_columns = {column["name"] for column in schema_inspector.get_columns("answers")}
            assert answer_columns >= {
                "sufficiency",
                "system_commentary",
                "extractive_fallback",
                "provider_status",
            }
            embedding_profile_column_map = {
                column["name"]: column
                for column in schema_inspector.get_columns("embedding_profiles")
            }
            assert embedding_profile_column_map["answer_min_similarity"]["nullable"] is True
            embedding_profile_constraints = " ".join(
                str(item[0])
                for item in connection.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conrelid='public.embedding_profiles'::regclass"
                    )
                )
            )
            assert "answer_min_similarity" in embedding_profile_constraints
            assert "-1" in embedding_profile_constraints and "1" in (embedding_profile_constraints)
            assert connection.scalar(
                text(
                    "SELECT count(*)=1 FROM information_schema.triggers "
                    "WHERE event_object_schema='public' "
                    "AND event_object_table='embedding_profiles' "
                    "AND trigger_name='embedding_profiles_threshold_immutable' "
                    "AND event_manipulation='UPDATE'"
                )
            )
            assert not connection.scalar(
                text(
                    "SELECT has_column_privilege('second_brain_app',"
                    "'public.embedding_profiles','answer_min_similarity','UPDATE')"
                )
            )
            proposal_columns = {
                column["name"] for column in schema_inspector.get_columns("memory_proposals")
            }
            assert proposal_columns >= {"confidence", "evidence_quality_label"}
            proposal_evidence_columns = {
                column["name"]
                for column in schema_inspector.get_columns("memory_proposal_evidence")
            }
            revision_columns = {
                column["name"] for column in schema_inspector.get_columns("memory_revisions")
            }
            revision_evidence_columns = {
                column["name"]
                for column in schema_inspector.get_columns("memory_revision_evidence")
            }
            assert proposal_evidence_columns >= {"source_id", "source_version_id"}
            assert revision_columns >= {
                "category",
                "confidence",
                "evidence_quality_label",
                "created_by",
            }
            assert revision_evidence_columns >= {"source_id", "source_version_id"}
            approved_memory_columns = {
                column["name"] for column in schema_inspector.get_columns("approved_memories")
            }
            assert approved_memory_columns >= {"supersedes_memory_id", "superseded_by_id"}
            assert {column["name"] for column in schema_inspector.get_columns("projects")} >= {
                "updated_at",
                "normalized_name",
            }
            assert {column["name"] for column in schema_inspector.get_columns("tags")} >= {
                "normalized_name"
            }
            purge_record_columns = {
                column["name"] for column in schema_inspector.get_columns("purge_records")
            }
            assert purge_record_columns >= {"operation_id", "resource_type", "resource_id"}
            purge_constraints = " ".join(
                str(item[0])
                for item in connection.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conrelid='public.purge_operations'::regclass"
                    )
                )
            )
            for reason_code in ("user_requested", "privacy_request", "retention_expired"):
                assert reason_code in purge_constraints
            purge_record_constraints = " ".join(
                str(item[0])
                for item in connection.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                        "WHERE conrelid='public.purge_records'::regclass"
                    )
                )
            )
            for reason_code in ("user_requested", "privacy_request", "retention_expired"):
                assert reason_code in purge_record_constraints
            chunk_indexes = {
                index["name"]: index for index in schema_inspector.get_indexes("chunks")
            }
            dialect_options = chunk_indexes["chunks_search_vector_gin"].get("dialect_options")
            assert dialect_options is not None
            assert dialect_options["postgresql_using"] == "gin"
            app_role = connection.execute(
                text(
                    "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls "
                    "FROM pg_roles WHERE rolname = 'second_brain_app'"
                )
            ).one()
            assert tuple(app_role) == (False, False, False, False)
            worker_role = connection.execute(
                text(
                    "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls "
                    "FROM pg_roles WHERE rolname = 'second_brain_worker'"
                )
            ).one()
            assert tuple(worker_role) == (False, False, False, False)
            for table in APPEND_ONLY_TABLES:
                assert not connection.scalar(
                    text("SELECT has_table_privilege('second_brain_app', :table, 'UPDATE')"),
                    {"table": table},
                )
                assert not connection.scalar(
                    text("SELECT has_table_privilege('second_brain_app', :table, 'DELETE')"),
                    {"table": table},
                )
            append_only_triggers = {
                row[0]
                for row in connection.execute(
                    text(
                        "SELECT event_object_table FROM information_schema.triggers "
                        "WHERE trigger_name LIKE '%_append_only'"
                    )
                )
            }
            assert append_only_triggers == APPEND_ONLY_TABLES
            app_delete_tables = set(
                connection.scalars(
                    text(
                        "SELECT table_name FROM information_schema.role_table_grants "
                        "WHERE grantee='second_brain_app' AND table_schema='public' "
                        "AND privilege_type='DELETE'"
                    )
                )
            )
            assert app_delete_tables == APP_ROLE_DELETE_TABLES
            for role in ("second_brain_app", "second_brain_worker"):
                assert not connection.scalar(
                    text("SELECT has_database_privilege(:role,current_database(),'TEMPORARY')"),
                    {"role": role},
                )
            for table in ("sources", "chunks", "ingestion_jobs", "ingestion_job_events"):
                assert not connection.scalar(
                    text(
                        "SELECT has_table_privilege('second_brain_worker', :table, "
                        "'SELECT,INSERT,UPDATE,DELETE')"
                    ),
                    {"table": table},
                )
            assert not connection.scalar(
                text(
                    "SELECT has_function_privilege('second_brain_app',"
                    "'public.claim_ingestion_job(text,integer)','EXECUTE')"
                )
            )
            assert connection.scalar(
                text(
                    "SELECT has_function_privilege('second_brain_app',"
                    "'public.abandon_capture_stage(uuid,text)','EXECUTE')"
                )
            )
            assert not connection.scalar(
                text(
                    "SELECT has_function_privilege('second_brain_worker',"
                    "'public.abandon_capture_stage(uuid,text)','EXECUTE')"
                )
            )
            for signature in (
                "public.claim_ingestion_job(text,integer)",
                "public.heartbeat_ingestion_job(uuid,text,integer)",
                "public.transition_ingestion_job(uuid,text,text,text,text,text,integer)",
                "public.list_stale_capture_stages(integer,integer)",
            ):
                assert connection.scalar(
                    text("SELECT has_function_privilege('second_brain_worker',:fn,'EXECUTE')"),
                    {"fn": signature},
                )
            for signature in (
                "public.claim_purge_operation(text,integer)",
                "public.retry_purge_operation(uuid,text,text,integer)",
                "public.finalize_source_purge(uuid,text)",
                "public.finalize_memory_purge(uuid,text)",
            ):
                assert connection.scalar(
                    text("SELECT has_function_privilege('second_brain_worker',:fn,'EXECUTE')"),
                    {"fn": signature},
                )
                assert not connection.scalar(
                    text("SELECT has_function_privilege('second_brain_app',:fn,'EXECUTE')"),
                    {"fn": signature},
                )
            assert not connection.scalar(
                text(
                    "SELECT has_table_privilege("
                    "'second_brain_app','trusted_exchange_rate_limits','SELECT')"
                )
            )
            assert "evidence_chunk_ids" not in {
                column["name"] for column in schema_inspector.get_columns("memory_proposals")
            }
            assert not connection.scalar(
                text(
                    "SELECT has_database_privilege("
                    "'second_brain_app',current_database(),'TEMPORARY')"
                )
            )
            functions = {
                row.proname: row
                for row in connection.execute(
                    text(
                        "SELECT procedure.proname,procedure.proconfig,"
                        "pg_get_functiondef(procedure.oid) AS definition "
                        "FROM pg_proc AS procedure "
                        "JOIN pg_namespace AS namespace "
                        "ON namespace.oid=procedure.pronamespace "
                        "WHERE namespace.nspname='public' "
                        "AND procedure.proname = ANY(:names)"
                    ),
                    {"names": sorted(APPLICATION_FUNCTIONS)},
                )
            }
            assert set(functions) == APPLICATION_FUNCTIONS
            evidence_guard = functions["enforce_memory_evidence_current"].definition
            assert re.search(r"source\.processing_state\s*=\s*'ready'(?:::text)?", evidence_guard)
            assert "source.deleted_at IS NULL" in evidence_guard
            assert "FOR UPDATE OF source" in evidence_guard
            assert not connection.scalar(
                text(
                    "SELECT has_function_privilege('public',"
                    "'public.enforce_memory_evidence_current()','EXECUTE')"
                )
            )
            for function in functions.values():
                assert function.proconfig == ["search_path=pg_catalog, public"]
                for relation in EXPECTED_TABLES - {"alembic_version"}:
                    assert not re.search(
                        rf"\b(?:FROM|JOIN|UPDATE|INSERT\s+INTO|DELETE\s+FROM)\s+{relation}\b",
                        function.definition,
                        re.IGNORECASE,
                    )
            worker_executable = {
                row[0]
                for row in connection.execute(
                    text(
                        "SELECT procedure.proname FROM pg_proc AS procedure "
                        "JOIN pg_namespace AS namespace ON namespace.oid=procedure.pronamespace "
                        "WHERE namespace.nspname='public' "
                        "AND procedure.proname = ANY(:names) "
                        "AND has_function_privilege('second_brain_worker',procedure.oid,'EXECUTE')"
                    ),
                    {"names": sorted(APPLICATION_FUNCTIONS)},
                )
            }
            assert worker_executable == WORKER_FUNCTIONS
    finally:
        engine.dispose()

    profile_owner, profile_workspace, profile_id = uuid4(), uuid4(), uuid4()
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:owner,:email)"),
                {"owner": profile_owner, "email": f"{profile_owner}@example.test"},
            )
            connection.execute(
                text(
                    "INSERT INTO workspaces (id,owner_id,name) "
                    "VALUES (:workspace,:owner,'profile calibration')"
                ),
                {"workspace": profile_workspace, "owner": profile_owner},
            )
            connection.execute(
                text(
                    "INSERT INTO workspace_memberships (workspace_id,user_id,role) "
                    "VALUES (:workspace,:owner,'owner')"
                ),
                {"workspace": profile_workspace, "owner": profile_owner},
            )
            for profile_version, threshold in ((100, None), (101, -1.0), (102, 1.0)):
                connection.execute(
                    text(
                        "INSERT INTO embedding_profiles "
                        "(id,owner_id,workspace_id,provider,model_identifier,profile_version,"
                        "dimensions,answer_min_similarity) VALUES "
                        "(:id,:owner,:workspace,'migration-test','model',:version,8,:threshold)"
                    ),
                    {
                        "id": profile_id if threshold is None else uuid4(),
                        "owner": profile_owner,
                        "workspace": profile_workspace,
                        "version": profile_version,
                        "threshold": threshold,
                    },
                )
        for profile_version, threshold in enumerate(
            (-1.0001, 1.0001, float("nan"), float("inf"), float("-inf")), start=200
        ):
            with pytest.raises(DBAPIError), engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO embedding_profiles "
                        "(id,owner_id,workspace_id,provider,model_identifier,profile_version,"
                        "dimensions,answer_min_similarity) VALUES "
                        "(:id,:owner,:workspace,'migration-test','model',:version,8,:threshold)"
                    ),
                    {
                        "id": uuid4(),
                        "owner": profile_owner,
                        "workspace": profile_workspace,
                        "version": profile_version,
                        "threshold": threshold,
                    },
                )
        with pytest.raises(DBAPIError), engine.begin() as connection:
            connection.execute(
                text("UPDATE embedding_profiles SET answer_min_similarity=0.2 WHERE id=:profile"),
                {"profile": profile_id},
            )
    finally:
        engine.dispose()

    app_url = database_url.set(username="second_brain_app", password="second_brain_app_dev")
    app_engine = create_engine(app_url)
    try:
        with pytest.raises(DBAPIError), app_engine.begin() as connection:
            connection.execute(text("CREATE TEMP TABLE memory_proposals (status text)"))
        with pytest.raises(DBAPIError), app_engine.begin() as connection:
            connection.execute(text("SELECT * FROM claim_ingestion_job('api',30)"))
        with pytest.raises(DBAPIError), app_engine.begin() as connection:
            connection.execute(text("SELECT * FROM claim_purge_operation('api',30)"))
    finally:
        app_engine.dispose()

    worker_url = database_url.set(
        username="second_brain_worker", password="second_brain_worker_dev"
    )
    worker_engine = create_engine(worker_url)
    try:
        with pytest.raises(DBAPIError), worker_engine.begin() as connection:
            connection.execute(text("SELECT id FROM sources LIMIT 1"))
        with pytest.raises(DBAPIError), worker_engine.begin() as connection:
            connection.execute(text("SELECT id FROM chunks LIMIT 1"))
        with worker_engine.begin() as connection:
            assert (
                connection.execute(
                    text("SELECT * FROM claim_ingestion_job('migration-check',30)")
                ).one_or_none()
                is None
            )
            assert (
                connection.execute(
                    text("SELECT * FROM claim_purge_operation('migration-check',30)")
                ).one_or_none()
                is None
            )
    finally:
        worker_engine.dispose()


def test_fresh_disposable_database_migrates_up_down_up() -> None:
    database_url = guarded_test_database_url()
    create_test_database(database_url)
    try:
        config = alembic_config(database_url)
        command.upgrade(config, "head")
        assert_schema(database_url)
        command.downgrade(config, "base")
        engine = create_engine(database_url)
        try:
            assert set(inspect(engine).get_table_names()) == {"alembic_version"}
            with engine.connect() as connection:
                assert connection.scalar(
                    text(
                        "SELECT has_database_privilege("
                        "'second_brain_app',current_database(),'TEMPORARY')"
                    )
                )
        finally:
            engine.dispose()
        command.upgrade(config, "head")
        assert_schema(database_url)
    finally:
        drop_test_database(database_url)


def test_legacy_purge_reason_is_safely_normalized_before_allowlist_constraint() -> None:
    database_url = guarded_test_database_url()
    create_test_database(database_url)
    try:
        config = alembic_config(database_url)
        command.upgrade(config, "0003_memory_lifecycle")
        owner, workspace, source, record = uuid4(), uuid4(), uuid4(), uuid4()
        engine = create_engine(database_url)
        try:
            with engine.begin() as connection:
                connection.execute(
                    text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                    {"id": owner, "email": f"{owner}@example.test"},
                )
                connection.execute(
                    text(
                        "INSERT INTO workspaces (id,owner_id,name) "
                        "VALUES (:workspace,:owner,'legacy')"
                    ),
                    {"workspace": workspace, "owner": owner},
                )
                connection.execute(
                    text(
                        "INSERT INTO workspace_memberships (workspace_id,user_id,role) "
                        "VALUES (:workspace,:owner,'owner')"
                    ),
                    {"workspace": workspace, "owner": owner},
                )
                connection.execute(
                    text(
                        "INSERT INTO purge_records "
                        "(id,owner_id,workspace_id,source_id,source_tombstone_id,reason_code,"
                        "original_removed,searchable_content_removed) VALUES "
                        "(:record,:owner,:workspace,:source,:source,'legacy free text',true,true)"
                    ),
                    {
                        "record": record,
                        "owner": owner,
                        "workspace": workspace,
                        "source": source,
                    },
                )
        finally:
            engine.dispose()
        command.upgrade(config, "head")
        engine = create_engine(database_url)
        try:
            with engine.connect() as connection:
                row = connection.execute(
                    text(
                        "SELECT record.reason_code,operation.state "
                        "FROM purge_records AS record JOIN purge_operations AS operation "
                        "ON operation.id=record.operation_id WHERE record.id=:record"
                    ),
                    {"record": record},
                ).one()
                assert row == ("user_requested", "complete")
        finally:
            engine.dispose()
        command.downgrade(config, "base")
    finally:
        drop_test_database(database_url)
