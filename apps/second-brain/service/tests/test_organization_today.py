import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from second_brain.db import create_session_factory, scoped_session
from second_brain.memory import approve_memory, propose_memory
from second_brain.organization import (
    OrganizationNotFound,
    create_project,
    create_tag,
    list_projects,
    list_tags,
    normalize_name,
    organize_source,
    update_project,
    update_tag,
)
from second_brain.today import EMPTY_MESSAGES, today_view


def seed_workspace(admin_url: str, owner_id: UUID, workspace_id: UUID) -> None:
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                {"id": owner_id, "email": f"{owner_id}@example.test"},
            )
            connection.execute(
                text("INSERT INTO workspaces (id,owner_id,name) VALUES (:id,:owner,'today')"),
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


def seed_source(
    admin_url: str,
    owner_id: UUID,
    workspace_id: UUID,
    *,
    source_id: UUID | None = None,
    title: str = "source",
    state: str = "ready",
    project_id: UUID | None = None,
    ingested_at: datetime | None = None,
) -> UUID:
    resolved_id = source_id or uuid4()
    digest = resolved_id.hex * 2
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO sources "
                    "(id,owner_id,workspace_id,project_id,source_type,display_title,object_key,"
                    "content_sha256,normalized_dedup_sha256,mime_type,processing_state,"
                    "semantic_state,ingested_at) VALUES "
                    "(:id,:owner,:workspace,:project,'note',:title,:object_key,:digest,:digest,"
                    "'text/plain',:state,'unavailable',:ingested_at)"
                ),
                {
                    "id": resolved_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "project": project_id,
                    "title": title,
                    "object_key": f"objects/{resolved_id}",
                    "digest": digest,
                    "state": state,
                    "ingested_at": ingested_at or datetime.now(UTC),
                },
            )
    finally:
        engine.dispose()
    return resolved_id


def seed_ready_chunk(admin_url: str, owner_id: UUID, workspace_id: UUID, content: str) -> UUID:
    source_id = seed_source(admin_url, owner_id, workspace_id, title="memory evidence")
    version_id, document_id, chunk_id = uuid4(), uuid4(), uuid4()
    digest = source_id.hex * 2
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO source_versions "
                    "(id,owner_id,workspace_id,source_id,version_number,parser_name,"
                    "parser_version,parser_mime_type,chunker_version,content_sha256) "
                    "VALUES (:id,:owner,:workspace,:source,1,'text','1','text/plain',"
                    "'chars-v1',:digest)"
                ),
                {
                    "id": version_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "source": source_id,
                    "digest": digest,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO documents "
                    "(id,owner_id,workspace_id,source_version_id,extracted_text,character_count) "
                    "VALUES (:id,:owner,:workspace,:version,:content,:count)"
                ),
                {
                    "id": document_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "version": version_id,
                    "content": content,
                    "count": len(content),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO chunks "
                    "(id,owner_id,workspace_id,document_id,source_version_id,ordinal,"
                    "chunk_text,char_start,char_end,location,chunker_version) "
                    "VALUES (:id,:owner,:workspace,:document,:version,0,:content,0,:count,"
                    "CAST(:location AS jsonb),'chars-v1')"
                ),
                {
                    "id": chunk_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "document": document_id,
                    "version": version_id,
                    "content": content,
                    "count": len(content),
                    "location": json.dumps({"section": "memory"}),
                },
            )
    finally:
        engine.dispose()
    return chunk_id


def test_scoped_normalized_project_tag_crud_and_source_organization(database_urls: Any) -> None:
    owner_a, workspace_a, owner_b, workspace_b = uuid4(), uuid4(), uuid4(), uuid4()
    seed_workspace(database_urls.admin, owner_a, workspace_a)
    seed_workspace(database_urls.admin, owner_b, workspace_b)
    source_a = seed_source(database_urls.admin, owner_a, workspace_a)
    source_b = seed_source(database_urls.admin, owner_b, workspace_b)
    app_engine = create_engine(database_urls.app)
    sessions = create_session_factory(app_engine)
    try:
        with scoped_session(sessions, owner_a, workspace_a) as session:
            project_a = create_project(session, "  Road\t Map  ")
            tag_a = create_tag(session, "  Evidence   Review ")
        assert project_a["name"] == "Road Map"
        assert project_a["normalized_name"] == "road map"
        assert tag_a["normalized_name"] == "evidence review"

        with (
            pytest.raises(IntegrityError),
            scoped_session(sessions, owner_a, workspace_a) as session,
        ):
            create_project(session, "road map")

        with scoped_session(sessions, owner_b, workspace_b) as session:
            project_b = create_project(session, "road map")
            tag_b = create_tag(session, "evidence review")
        assert project_b["project_id"] != project_a["project_id"]

        with scoped_session(sessions, owner_a, workspace_a) as session:
            organized = organize_source(
                session,
                source_a,
                project_id=project_a["project_id"],
                tag_ids=[tag_a["tag_id"], tag_a["tag_id"]],
            )
            assert organized["tag_ids"] == [tag_a["tag_id"]]
            assert [row["project_id"] for row in list_projects(session)] == [
                project_a["project_id"]
            ]
            assert [row["tag_id"] for row in list_tags(session)] == [tag_a["tag_id"]]
            renamed_project = update_project(
                session, project_a["project_id"], name="Research Roadmap"
            )
            renamed_tag = update_tag(session, tag_a["tag_id"], name="Primary Evidence")
            assert renamed_project["normalized_name"] == "research roadmap"
            assert renamed_tag["normalized_name"] == "primary evidence"
            with pytest.raises(OrganizationNotFound):
                organize_source(
                    session,
                    source_b,
                    project_id=project_a["project_id"],
                    tag_ids=[],
                )
            with pytest.raises(OrganizationNotFound):
                organize_source(
                    session,
                    source_a,
                    project_id=project_a["project_id"],
                    tag_ids=[tag_b["tag_id"]],
                )

        with scoped_session(sessions, owner_b, workspace_b) as session:
            assert [row["project_id"] for row in list_projects(session)] == [
                project_b["project_id"]
            ]
    finally:
        app_engine.dispose()


def test_normalize_name_is_nfkc_whitespace_stable_and_bounded() -> None:
    fullwidth = "  \uff32\uff45\uff53\uff45\uff41\uff52\uff43\uff48\n Plan  "
    assert normalize_name(fullwidth) == ("Research Plan", "research plan")
    with pytest.raises(ValueError):
        normalize_name(" \t ")


def test_today_empty_sections_are_stable_scoped_and_read_only(database_urls: Any) -> None:
    owner_a, workspace_a, owner_b, workspace_b = uuid4(), uuid4(), uuid4(), uuid4()
    seed_workspace(database_urls.admin, owner_a, workspace_a)
    seed_workspace(database_urls.admin, owner_b, workspace_b)
    seed_source(database_urls.admin, owner_b, workspace_b, title="private-other-workspace")
    as_of = datetime(2026, 8, 27, 12, tzinfo=UTC)
    app_engine = create_engine(database_urls.app)
    sessions = create_session_factory(app_engine)
    admin_engine = create_engine(database_urls.admin)
    try:
        with admin_engine.connect() as connection:
            before = tuple(
                connection.execute(
                    text(
                        "SELECT (SELECT count(*) FROM memory_resurfacing_events),"
                        "(SELECT count(*) FROM policy_decisions)"
                    )
                ).one()
            )
        with scoped_session(sessions, owner_a, workspace_a) as session:
            first = today_view(session, as_of=as_of)
            second = today_view(session, as_of=as_of)
        assert first == second
        for name, message in EMPTY_MESSAGES.items():
            assert first[name] == {"items": [], "empty_message": message}
        with admin_engine.connect() as connection:
            after = tuple(
                connection.execute(
                    text(
                        "SELECT (SELECT count(*) FROM memory_resurfacing_events),"
                        "(SELECT count(*) FROM policy_decisions)"
                    )
                ).one()
            )
        assert after == before
    finally:
        admin_engine.dispose()
        app_engine.dispose()


def test_today_capture_failure_and_active_project_ordering(database_urls: Any) -> None:
    owner, workspace = uuid4(), uuid4()
    seed_workspace(database_urls.admin, owner, workspace)
    as_of = datetime(2026, 8, 27, 12, tzinfo=UTC)
    project_new, project_old = uuid4(), uuid4()
    admin_engine = create_engine(database_urls.admin)
    try:
        with admin_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO projects (id,owner_id,workspace_id,name,updated_at) VALUES "
                    "(:new,:owner,:workspace,'new project',:new_time),"
                    "(:old,:owner,:workspace,'old project',:old_time)"
                ),
                {
                    "new": project_new,
                    "old": project_old,
                    "owner": owner,
                    "workspace": workspace,
                    "new_time": as_of - timedelta(hours=1),
                    "old_time": as_of - timedelta(days=1),
                },
            )
        source_ids = sorted((uuid4() for _ in range(6)), key=str)
        for index, source_id in enumerate(source_ids):
            seed_source(
                database_urls.admin,
                owner,
                workspace,
                source_id=source_id,
                title=f"capture-{index}",
                state="failed" if index < 2 else "ready",
                project_id=project_new if index < 3 else project_old,
                ingested_at=as_of - timedelta(hours=2),
            )
        with admin_engine.begin() as connection:
            for index, source_id in enumerate(source_ids[:2]):
                job_id = uuid4()
                connection.execute(
                    text(
                        "INSERT INTO ingestion_jobs "
                        "(id,owner_id,workspace_id,source_id,requested_uri) "
                        "VALUES (:id,:owner,:workspace,:source,'https://example.test')"
                    ),
                    {
                        "id": job_id,
                        "owner": owner,
                        "workspace": workspace,
                        "source": source_id,
                    },
                )
                connection.execute(
                    text(
                        "INSERT INTO ingestion_job_events "
                        "(owner_id,workspace_id,job_id,attempt,from_state,to_state,"
                        "reason_class) VALUES "
                        "(:owner,:workspace,:id,0,'queued','failed','parser_failed')"
                    ),
                    {
                        "id": job_id,
                        "owner": owner,
                        "workspace": workspace,
                    },
                )
                connection.execute(
                    text(
                        "UPDATE ingestion_jobs SET state='failed',error_code='parser_failed' "
                        "WHERE id=:id"
                    ),
                    {"id": job_id},
                )
                connection.execute(
                    text("UPDATE ingestion_jobs SET finished_at=:finished WHERE id=:id"),
                    {"id": job_id, "finished": as_of - timedelta(minutes=index + 1)},
                )
        app_engine = create_engine(database_urls.app)
        try:
            with scoped_session(create_session_factory(app_engine), owner, workspace) as session:
                view = today_view(session, as_of=as_of)
        finally:
            app_engine.dispose()
        assert [row["source_id"] for row in view["recent_captures"]["items"]] == source_ids[:5]
        assert len(view["failed_jobs"]["items"]) == 2
        active = view["active_project_sources"]["items"]
        assert [row["project_id"] for row in active] == [project_new, project_old]
        assert len({row["project_id"] for row in active}) == len(active)
    finally:
        admin_engine.dispose()


def test_today_memory_sections_are_stable_and_respect_exact_seven_day_boundary(
    database_urls: Any,
) -> None:
    owner, workspace = uuid4(), uuid4()
    seed_workspace(database_urls.admin, owner, workspace)
    chunk_id = seed_ready_chunk(
        database_urls.admin, owner, workspace, "deterministic resurfacing evidence"
    )
    as_of = datetime(2026, 8, 27, 12, tzinfo=UTC)
    app_engine = create_engine(database_urls.app)
    sessions = create_session_factory(app_engine)
    admin_engine = create_engine(database_urls.admin)
    try:
        memory_ids = []
        for index in range(6):
            proposal = propose_memory(
                sessions,
                owner_id=owner,
                workspace_id=workspace,
                statement=f"Durable memory {index}",
                category="project_fact",
                evidence_chunk_ids=[chunk_id],
                confidence=0.8,
                evidence_quality="high",
                idempotency_key=f"today-proposal-{index}",
            )
            memory = approve_memory(
                sessions,
                owner_id=owner,
                workspace_id=workspace,
                proposal_id=proposal["proposal_id"],
                idempotency_key=f"today-approve-{index}",
            )
            memory_ids.append(memory["memory_id"])

        memory_ids.sort(key=str)
        with admin_engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE approved_memories SET approved_at=:approved "
                    "WHERE owner_id=:owner AND workspace_id=:workspace"
                ),
                {
                    "approved": as_of - timedelta(hours=1),
                    "owner": owner,
                    "workspace": workspace,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_resurfacing_events "
                    "(owner_id,workspace_id,memory_id,resurfaced_at) "
                    "VALUES (:owner,:workspace,:memory,:resurfaced)"
                ),
                {
                    "owner": owner,
                    "workspace": workspace,
                    "memory": memory_ids[0],
                    "resurfaced": as_of - timedelta(days=7),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_resurfacing_events "
                    "(owner_id,workspace_id,memory_id,resurfaced_at) "
                    "VALUES (:owner,:workspace,:memory,:resurfaced)"
                ),
                {
                    "owner": owner,
                    "workspace": workspace,
                    "memory": memory_ids[1],
                    "resurfaced": as_of - timedelta(days=7, microseconds=1),
                },
            )

        with scoped_session(sessions, owner, workspace) as session:
            first = today_view(session, as_of=as_of)
            second = today_view(session, as_of=as_of)

        assert first == second
        assert [
            item["memory_id"] for item in first["recent_approved_memories"]["items"]
        ] == memory_ids[:5]
        eligible = memory_ids[1:]
        expected_resurfacing = sorted(
            eligible,
            key=lambda memory_id: (
                hashlib.sha256(
                    f"{owner}|{workspace}|{as_of.date()}|{memory_id}".encode()
                ).hexdigest(),
                str(memory_id),
            ),
        )[:3]
        assert [item["memory_id"] for item in first["resurfacing"]["items"]] == (
            expected_resurfacing
        )
    finally:
        admin_engine.dispose()
        app_engine.dispose()
