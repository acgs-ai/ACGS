import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pytest import mark, raises
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from second_brain.config import Settings
from second_brain.db import create_database_engine, create_session_factory, scoped_session
from second_brain.ingestion import (
    CaptureResult,
    CrashPoint,
    InjectedCaptureCrash,
    capture_source,
)
from second_brain.providers import FakeEmbeddingProvider
from second_brain.storage import FilesystemStorage
from second_brain.worker import IngestionWorker


def seed_workspace(admin_url: str) -> tuple[UUID, UUID]:
    owner_id, workspace_id = uuid4(), uuid4()
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                {"id": owner_id, "email": f"{owner_id}@example.test"},
            )
            connection.execute(
                text("INSERT INTO workspaces (id,owner_id,name) VALUES (:id,:owner,'capture')"),
                {"id": workspace_id, "owner": owner_id},
            )
            connection.execute(
                text(
                    "INSERT INTO workspace_memberships (workspace_id,user_id,role) "
                    "VALUES (:workspace,:owner,'owner')"
                ),
                {"workspace": workspace_id, "owner": owner_id},
            )
    finally:
        engine.dispose()
    return owner_id, workspace_id


def capture(
    sessions: sessionmaker[Session],
    storage: FilesystemStorage,
    owner_id: UUID,
    workspace_id: UUID,
    crash_after: CrashPoint | None = None,
) -> CaptureResult:
    return capture_source(
        sessions,
        storage,
        owner_id=owner_id,
        workspace_id=workspace_id,
        source_type="note",
        title="Crash-safe capture",
        mime_type="text/plain",
        data=b"line one\r\nline two",
        idempotency_key="capture-crash-001",
        crash_after=crash_after,
    )


def retire_queued_jobs(admin_url: str, owner_id: UUID) -> None:
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ingestion_job_events "
                    "(owner_id,workspace_id,job_id,attempt,from_state,to_state,reason_class) "
                    "SELECT owner_id,workspace_id,id,attempts,'queued','failed','test_cleanup' "
                    "FROM ingestion_jobs WHERE owner_id=:owner AND state='queued'"
                ),
                {"owner": owner_id},
            )
            connection.execute(
                text(
                    "UPDATE ingestion_jobs SET state='failed',error_code='test_cleanup',"
                    "error_message='Test fixture retired.',updated_at=clock_timestamp() "
                    "WHERE owner_id=:owner AND state='queued'"
                ),
                {"owner": owner_id},
            )
    finally:
        engine.dispose()


@mark.parametrize(
    "point",
    ["after_lineage", "after_partial", "after_stored", "after_promotion", "before_final_db"],
)
def test_capture_retry_recovers_each_durable_crash_boundary(
    database_urls: Any, tmp_path: Path, point: CrashPoint
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    engine = create_database_engine(
        Settings(database_url=database_urls.app, storage_root=tmp_path / "objects")
    )
    sessions = create_session_factory(engine)
    storage = FilesystemStorage(tmp_path / "objects", 1024)
    try:
        with raises(InjectedCaptureCrash, match=point):
            capture(sessions, storage, owner_id, workspace_id, point)
        recovered = capture(sessions, storage, owner_id, workspace_id)
    finally:
        engine.dispose()

    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT (SELECT count(*) FROM sources WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM source_versions WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM ingestion_jobs WHERE owner_id=:owner),"
                    "(SELECT count(*) FROM capture_stages WHERE owner_id=:owner),"
                    "(SELECT state FROM capture_stages WHERE owner_id=:owner)"
                ),
                {"owner": owner_id},
            ).one()
    finally:
        admin.dispose()
    assert recovered.duplicate is True
    assert row == (1, 1, 1, 1, "finalized")
    assert len(list((tmp_path / "objects").rglob("original"))) == 1
    assert not list((tmp_path / "objects").rglob("*.partial"))
    retire_queued_jobs(database_urls.admin, owner_id)


def test_concurrent_capture_has_one_lineage_and_one_final_object(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = Settings(database_url=database_urls.app, storage_root=tmp_path / "objects")
    engine = create_database_engine(settings)
    sessions = create_session_factory(engine)
    storage = FilesystemStorage(settings.storage_root, 1024)

    def run() -> CaptureResult:
        return capture(sessions, storage, owner_id, workspace_id)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: run(), range(2)))
    finally:
        engine.dispose()
    assert results[0].source_id == results[1].source_id
    assert sorted(result.duplicate for result in results) == [False, True]
    assert len(list(settings.storage_root.rglob("original"))) == 1
    assert not list(settings.storage_root.rglob("*.partial"))
    retire_queued_jobs(database_urls.admin, owner_id)


def test_mismatched_regular_partial_is_rewritten_from_exact_lineage(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    settings = Settings(database_url=database_urls.app, storage_root=tmp_path / "objects")
    engine = create_database_engine(settings)
    sessions = create_session_factory(engine)
    storage = FilesystemStorage(settings.storage_root, 1024)
    try:
        with raises(InjectedCaptureCrash):
            capture(sessions, storage, owner_id, workspace_id, "after_partial")
        partial = next(settings.storage_root.rglob("*.partial"))
        partial.write_bytes(b"tampered")
        recovered = capture(sessions, storage, owner_id, workspace_id)
    finally:
        engine.dispose()

    admin = create_engine(database_urls.admin)
    try:
        with admin.connect() as connection:
            states = connection.execute(
                text(
                    "SELECT stage.state,job.state,count(event.id) "
                    "FROM capture_stages AS stage "
                    "JOIN ingestion_jobs AS job ON job.source_id=stage.source_id "
                    "LEFT JOIN ingestion_job_events AS event ON event.job_id=job.id "
                    "AND event.to_state='failed' WHERE stage.owner_id=:owner "
                    "GROUP BY stage.state,job.state"
                ),
                {"owner": owner_id},
            ).one()
    finally:
        admin.dispose()
    assert recovered.duplicate is True
    assert states == ("finalized", "queued", 0)
    assert len(list(settings.storage_root.rglob("original"))) == 1
    assert not list(settings.storage_root.rglob("*.partial"))
    retire_queued_jobs(database_urls.admin, owner_id)


def test_worker_sweeper_promotes_valid_partial_and_abandons_missing_stage(
    database_urls: Any, tmp_path: Path
) -> None:
    first_owner, first_workspace = seed_workspace(database_urls.admin)
    second_owner, second_workspace = seed_workspace(database_urls.admin)
    settings = Settings(database_url=database_urls.app, storage_root=tmp_path / "objects")
    engine = create_database_engine(settings)
    sessions = create_session_factory(engine)
    storage = FilesystemStorage(settings.storage_root, 1024)
    try:
        with raises(InjectedCaptureCrash):
            capture(sessions, storage, first_owner, first_workspace, "after_partial")
        with raises(InjectedCaptureCrash):
            capture(sessions, storage, second_owner, second_workspace, "after_lineage")
        admin = create_engine(database_urls.admin)
        try:
            time.sleep(1.1)
            worker = IngestionWorker(
                sessions,
                storage,
                FakeEmbeddingProvider(8),
                settings,
                "stage-sweeper",
                dispatcher_session_factory=database_urls.worker_sessions,
            )
            assert worker.sweep_stale_stages(1, 10) == 2
            with admin.connect() as connection:
                states = connection.execute(
                    text(
                        "SELECT owner_id,state FROM capture_stages "
                        "WHERE owner_id IN (:first,:second) ORDER BY owner_id"
                    ),
                    {"first": first_owner, "second": second_owner},
                ).all()
                jobs: dict[UUID, str] = {
                    row.owner_id: row.state
                    for row in connection.execute(
                        text(
                            "SELECT owner_id,state FROM ingestion_jobs "
                            "WHERE owner_id IN (:first,:second)"
                        ),
                        {"first": first_owner, "second": second_owner},
                    )
                }
        finally:
            admin.dispose()
    finally:
        engine.dispose()
    state_by_owner: dict[UUID, str] = {row.owner_id: row.state for row in states}
    assert state_by_owner[first_owner] == "finalized"
    assert state_by_owner[second_owner] == "abandoned"
    assert jobs[first_owner] == "queued"
    assert jobs[second_owner] == "failed"
    assert len(list(settings.storage_root.rglob("original"))) == 1
    assert not list(settings.storage_root.rglob("*.partial"))
    retire_queued_jobs(database_urls.admin, first_owner)


def test_terminal_stages_are_abandoned_once_without_starving_later_work(
    database_urls: Any, tmp_path: Path
) -> None:
    memberships = [seed_workspace(database_urls.admin) for _ in range(5)]
    owners = [owner for owner, _ in memberships]
    terminal_owners = {owner for owner, _ in memberships[:3]}
    recoverable_owner = memberships[3][0]
    active_owner = memberships[4][0]
    settings = Settings(database_url=database_urls.app, storage_root=tmp_path / "objects")
    engine = create_database_engine(settings)
    sessions = create_session_factory(engine)
    storage = FilesystemStorage(settings.storage_root, 1024)
    admin = create_engine(database_urls.admin)
    try:
        for owner_id, workspace_id in memberships:
            with raises(InjectedCaptureCrash):
                capture(sessions, storage, owner_id, workspace_id, "after_lineage")
        with admin.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ingestion_job_events "
                    "(owner_id,workspace_id,job_id,attempt,from_state,to_state,reason_class) "
                    "SELECT owner_id,workspace_id,id,attempts,'queued','failed','fixture_terminal' "
                    "FROM ingestion_jobs WHERE owner_id = ANY(:owners) AND state='queued'"
                ),
                {"owners": list(terminal_owners)},
            )
            connection.execute(
                text(
                    "UPDATE ingestion_jobs SET state='failed',error_code='fixture_terminal',"
                    "error_message='Fixture terminal state.',updated_at=clock_timestamp() "
                    "WHERE owner_id = ANY(:owners) AND state='queued'"
                ),
                {"owners": list(terminal_owners)},
            )
            connection.execute(
                text(
                    "UPDATE sources SET processing_state='failed',"
                    "processing_error_code='fixture_terminal',"
                    "processing_error_message='Fixture terminal state.' "
                    "WHERE owner_id = ANY(:owners)"
                ),
                {"owners": list(terminal_owners)},
            )
            connection.execute(
                text(
                    "INSERT INTO ingestion_job_events "
                    "(owner_id,workspace_id,job_id,attempt,from_state,to_state,reason_class,"
                    "lease_owner,lease_expires_at) "
                    "SELECT owner_id,workspace_id,id,1,'queued','processing','fixture_active',"
                    "'active-worker',clock_timestamp()+interval '30 seconds' "
                    "FROM ingestion_jobs WHERE owner_id=:owner AND state='queued'"
                ),
                {"owner": active_owner},
            )
            connection.execute(
                text("UPDATE sources SET processing_state='processing' WHERE owner_id=:owner"),
                {"owner": active_owner},
            )
            connection.execute(
                text(
                    "UPDATE ingestion_jobs SET state='processing',attempts=1,"
                    "lease_owner='active-worker',"
                    "lease_expires_at=clock_timestamp()+interval '30 seconds',"
                    "heartbeat_at=clock_timestamp(),updated_at=clock_timestamp() "
                    "WHERE owner_id=:owner AND state='queued'"
                ),
                {"owner": active_owner},
            )
        time.sleep(1.1)
        worker = IngestionWorker(
            sessions,
            storage,
            FakeEmbeddingProvider(8),
            settings,
            "bounded-stage-sweeper",
            dispatcher_session_factory=database_urls.worker_sessions,
        )
        assert worker.sweep_stale_stages(1, 2) == 2
        assert worker.sweep_stale_stages(1, 2) == 2
        assert worker.sweep_stale_stages(1, 2) == 0
        with admin.connect() as connection:
            stage_states: dict[UUID, str] = {
                row.owner_id: row.state
                for row in connection.execute(
                    text("SELECT owner_id,state FROM capture_stages WHERE owner_id = ANY(:owners)"),
                    {"owners": owners},
                )
            }
            job_states: dict[UUID, str] = {
                row.owner_id: row.state
                for row in connection.execute(
                    text("SELECT owner_id,state FROM ingestion_jobs WHERE owner_id = ANY(:owners)"),
                    {"owners": owners},
                )
            }
            terminal_event_counts: dict[UUID, int] = {
                row.owner_id: row.event_count
                for row in connection.execute(
                    text(
                        "SELECT owner_id,count(*) AS event_count FROM ingestion_job_events "
                        "WHERE reason_class='fixture_terminal' GROUP BY owner_id"
                    )
                )
            }
        assert all(stage_states[owner] == "abandoned" for owner in terminal_owners)
        assert stage_states[recoverable_owner] == "abandoned"
        assert stage_states[active_owner] == "pending"
        assert all(job_states[owner] == "failed" for owner in terminal_owners)
        assert job_states[recoverable_owner] == "failed"
        assert job_states[active_owner] == "processing"
        assert terminal_event_counts == {owner: 1 for owner in terminal_owners}
    finally:
        with admin.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ingestion_job_events "
                    "(owner_id,workspace_id,job_id,attempt,from_state,to_state,reason_class) "
                    "SELECT owner_id,workspace_id,id,attempts,state,'failed','test_cleanup' "
                    "FROM ingestion_jobs WHERE owner_id = ANY(:owners) "
                    "AND state IN ('queued','processing')"
                ),
                {"owners": owners},
            )
            connection.execute(
                text(
                    "UPDATE sources SET processing_state='failed',"
                    "processing_error_code='test_cleanup',"
                    "processing_error_message='Test fixture retired.' "
                    "WHERE owner_id = ANY(:owners) AND processing_state IN ('queued','processing')"
                ),
                {"owners": owners},
            )
            connection.execute(
                text(
                    "UPDATE ingestion_jobs SET state='failed',error_code='test_cleanup',"
                    "error_message='Test fixture retired.',lease_owner=NULL,"
                    "lease_expires_at=NULL,updated_at=clock_timestamp() "
                    "WHERE owner_id = ANY(:owners) AND state IN ('queued','processing')"
                ),
                {"owners": owners},
            )
        admin.dispose()
        engine.dispose()


def test_abandon_old_terminal_stage_does_not_mutate_newer_refetch_job(
    database_urls: Any, tmp_path: Path
) -> None:
    owner_id, workspace_id = seed_workspace(database_urls.admin)
    source_id, version_id, old_job_id, new_job_id, stage_id = (uuid4() for _ in range(5))
    admin = create_engine(database_urls.admin)
    try:
        with admin.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO sources "
                    "(id,owner_id,workspace_id,source_type,display_title,original_uri,"
                    "normalized_dedup_sha256,mime_type) VALUES "
                    "(:source,:owner,:workspace,'url','Refetched source','https://public.test/x',"
                    ":hash,'text/uri-list')"
                ),
                {
                    "source": source_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "hash": uuid4().hex * 2,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO source_versions "
                    "(id,owner_id,workspace_id,source_id,version_number,parser_name,"
                    "parser_version,fetcher_version,parser_mime_type,chunker_version,"
                    "content_sha256) VALUES "
                    "(:version,:owner,:workspace,:source,1,'txt','1','http-v1','text/plain',"
                    "'chars-v1',:hash)"
                ),
                {
                    "version": version_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "source": source_id,
                    "hash": uuid4().hex * 2,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO ingestion_jobs "
                    "(id,owner_id,workspace_id,source_id,source_version_id) VALUES "
                    "(:old,:owner,:workspace,:source,:version)"
                ),
                {
                    "old": old_job_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "source": source_id,
                    "version": version_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO capture_stages "
                    "(id,owner_id,workspace_id,object_key,kind,intended_content_sha256,"
                    "intended_size,source_id,job_id) VALUES "
                    "(:stage,:owner,:workspace,:key,'url',:hash,8,:source,:job)"
                ),
                {
                    "stage": stage_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "key": f"{owner_id.hex}/{workspace_id.hex}/{source_id.hex}/{old_job_id.hex}",
                    "hash": uuid4().hex * 2,
                    "source": source_id,
                    "job": old_job_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO ingestion_job_events "
                    "(owner_id,workspace_id,job_id,attempt,from_state,to_state,reason_class) "
                    "VALUES (:owner,:workspace,:job,0,'queued','failed','old_fetch_failed')"
                ),
                {"owner": owner_id, "workspace": workspace_id, "job": old_job_id},
            )
            connection.execute(
                text(
                    "UPDATE ingestion_jobs SET state='failed',error_code='old_fetch_failed',"
                    "error_message='Old fetch failed.' WHERE id=:job"
                ),
                {"job": old_job_id},
            )
            connection.execute(
                text(
                    "INSERT INTO ingestion_jobs "
                    "(id,owner_id,workspace_id,source_id,requested_uri) VALUES "
                    "(:new,:owner,:workspace,:source,'https://public.test/x')"
                ),
                {
                    "new": new_job_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "source": source_id,
                },
            )
        settings = Settings(database_url=database_urls.app, storage_root=tmp_path / "objects")
        engine = create_database_engine(settings)
        sessions = create_session_factory(engine)
        try:
            with scoped_session(sessions, owner_id, workspace_id) as session:
                assert session.scalar(
                    text("SELECT abandon_capture_stage(:stage,:reason)"),
                    {"stage": stage_id, "reason": "stale_capture_object_unavailable"},
                )
        finally:
            engine.dispose()
        with admin.connect() as connection:
            assert connection.execute(
                text(
                    "SELECT stage.state,old_job.state,new_job.state,"
                    "(SELECT count(*) FROM ingestion_job_events "
                    "WHERE job_id=:old AND reason_class='old_fetch_failed'),"
                    "(SELECT count(*) FROM ingestion_job_events WHERE job_id=:new) "
                    "FROM capture_stages AS stage "
                    "JOIN ingestion_jobs AS old_job ON old_job.id=stage.job_id "
                    "JOIN ingestion_jobs AS new_job ON new_job.id=:new "
                    "WHERE stage.id=:stage"
                ),
                {"stage": stage_id, "old": old_job_id, "new": new_job_id},
            ).one() == ("abandoned", "failed", "queued", 1, 1)
    finally:
        retire_queued_jobs(database_urls.admin, owner_id)
        admin.dispose()
