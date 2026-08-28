import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from second_brain.memory import (
    MemoryEvidenceUnavailable,
    MemoryNotFound,
    MemoryStateConflict,
    approve_memory,
    archive_memory,
    edit_and_approve_memory,
    propose_memory,
    reject_memory_proposal,
    revise_memory,
    supersede_memory,
)


def _sessions(database_url: str) -> tuple[sessionmaker[Session], Any]:
    engine = create_engine(database_url, pool_pre_ping=True)
    return sessionmaker(bind=engine, expire_on_commit=False), engine


def _seed_workspace(admin_url: str, owner_id: UUID, workspace_id: UUID) -> None:
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                {"id": owner_id, "email": f"{owner_id}@example.test"},
            )
            connection.execute(
                text(
                    "INSERT INTO workspaces (id,owner_id,name) "
                    "VALUES (:id,:owner,'Memory workspace')"
                ),
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


def _seed_ready_chunk(
    admin_url: str, owner_id: UUID, workspace_id: UUID, content: str
) -> tuple[UUID, UUID, UUID]:
    source_id, version_id, document_id, chunk_id = uuid4(), uuid4(), uuid4(), uuid4()
    digest = (content.encode().hex() + "0" * 64)[:64]
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO sources "
                    "(id,owner_id,workspace_id,source_type,display_title,object_key,"
                    "content_sha256,normalized_dedup_sha256,mime_type,processing_state) "
                    "VALUES (:id,:owner,:workspace,'note','Memory evidence',:object_key,"
                    ":digest,:normalized,'text/plain','ready')"
                ),
                {
                    "id": source_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "object_key": f"{owner_id.hex}/{workspace_id.hex}/{source_id.hex}/original",
                    "digest": digest,
                    "normalized": source_id.hex * 2,
                },
            )
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
    return source_id, version_id, chunk_id


def _approve_test_memory(
    sessions: sessionmaker[Session],
    *,
    owner_id: UUID,
    workspace_id: UUID,
    chunk_id: UUID,
    name: str,
) -> dict[str, Any]:
    proposal = propose_memory(
        sessions,
        owner_id=owner_id,
        workspace_id=workspace_id,
        statement=f"{name} meaning.",
        category="project_fact",
        evidence_chunk_ids=[chunk_id],
        confidence=0.9,
        evidence_quality="high",
        idempotency_key=f"{name}-proposal",
    )
    return approve_memory(
        sessions,
        owner_id=owner_id,
        workspace_id=workspace_id,
        proposal_id=proposal["proposal_id"],
        idempotency_key=f"{name}-approve",
    )


def _supersession_graph(admin_url: str, memory_ids: list[UUID]) -> dict[UUID, tuple[Any, ...]]:
    engine = create_engine(admin_url)
    try:
        with engine.connect() as connection:
            return {
                row.id: (row.status, row.supersedes_memory_id, row.superseded_by_id)
                for row in connection.execute(
                    text(
                        "SELECT id,status,supersedes_memory_id,superseded_by_id "
                        "FROM approved_memories WHERE id=ANY(CAST(:ids AS uuid[]))"
                    ),
                    {"ids": memory_ids},
                )
            }
    finally:
        engine.dispose()


def test_proposal_is_inactive_and_foreign_evidence_fails_closed(
    database_urls: Any,
) -> None:
    owner, workspace = uuid4(), uuid4()
    foreign_owner, foreign_workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    _seed_workspace(database_urls.admin, foreign_owner, foreign_workspace)
    source_id, version_id, chunk_id = _seed_ready_chunk(
        database_urls.admin, owner, workspace, "deliberate memory evidence"
    )
    _, _, foreign_chunk = _seed_ready_chunk(
        database_urls.admin, foreign_owner, foreign_workspace, "foreign memory evidence"
    )
    sessions, engine = _sessions(database_urls.app)
    try:
        proposal = propose_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            statement="The project uses deliberate memory.",
            category="project_fact",
            evidence_chunk_ids=[chunk_id],
            confidence=0.9,
            evidence_quality="high",
            idempotency_key="proposal-1",
        )
        assert proposal["status"] == "proposed"
        assert proposal["evidence"] == [
            {"chunk_id": chunk_id, "source_id": source_id, "source_version_id": version_id}
        ]
        admin = create_engine(database_urls.admin)
        try:
            with admin.connect() as connection:
                assert (
                    connection.scalar(
                        text("SELECT count(*) FROM approved_memories WHERE owner_id=:owner"),
                        {"owner": owner},
                    )
                    == 0
                )
        finally:
            admin.dispose()

        with pytest.raises(MemoryEvidenceUnavailable):
            propose_memory(
                sessions,
                owner_id=owner,
                workspace_id=workspace,
                statement="Foreign content must not become memory.",
                category="other",
                evidence_chunk_ids=[foreign_chunk],
                confidence=0.2,
                evidence_quality="low",
                idempotency_key="proposal-foreign",
            )
    finally:
        engine.dispose()


def test_concurrent_approval_is_idempotent_and_preserves_exact_evidence(
    database_urls: Any,
) -> None:
    owner, workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    source_id, version_id, chunk_id = _seed_ready_chunk(
        database_urls.admin, owner, workspace, "approval evidence"
    )
    sessions, engine = _sessions(database_urls.app)
    try:
        proposal = propose_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            statement="Approval is explicit.",
            category="reference",
            evidence_chunk_ids=[chunk_id],
            confidence=0.8,
            evidence_quality="high",
            idempotency_key="proposal-approve",
        )

        def approve() -> dict[str, Any]:
            return approve_memory(
                sessions,
                owner_id=owner,
                workspace_id=workspace,
                proposal_id=proposal["proposal_id"],
                idempotency_key="approve-once",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = tuple(pool.map(lambda _: approve(), range(2)))
        assert first["memory_id"] == second["memory_id"]
        assert first["revision_number"] == 1

        admin = create_engine(database_urls.admin)
        try:
            with admin.connect() as connection:
                evidence = connection.execute(
                    text(
                        "SELECT evidence.chunk_id,evidence.source_id,evidence.source_version_id "
                        "FROM memory_revision_evidence AS evidence "
                        "JOIN memory_revisions AS revision ON revision.id=evidence.revision_id "
                        "WHERE revision.memory_id=:memory"
                    ),
                    {"memory": first["memory_id"]},
                ).one()
                assert evidence == (chunk_id, source_id, version_id)
                assert (
                    connection.scalar(
                        text(
                            "SELECT count(*) FROM memory_actions "
                            "WHERE owner_id=:owner AND idempotency_key='approve-once'"
                        ),
                        {"owner": owner},
                    )
                    == 1
                )
        finally:
            admin.dispose()
    finally:
        engine.dispose()


def test_reject_edit_revision_supersession_and_archive_are_append_oriented(
    database_urls: Any,
) -> None:
    owner, workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    _, _, chunk_id = _seed_ready_chunk(database_urls.admin, owner, workspace, "revision evidence")
    sessions, engine = _sessions(database_urls.app)
    try:
        rejected = propose_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            statement="Reject this proposal.",
            category="other",
            evidence_chunk_ids=[chunk_id],
            confidence=0.3,
            evidence_quality="low",
            idempotency_key="proposal-reject",
        )
        rejection = reject_memory_proposal(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            proposal_id=rejected["proposal_id"],
            idempotency_key="reject-once",
        )
        assert rejection["status"] == "rejected"

        editable = propose_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            statement="Draft meaning.",
            category="other",
            evidence_chunk_ids=[chunk_id],
            confidence=0.5,
            evidence_quality="medium",
            idempotency_key="proposal-edit",
        )
        first = edit_and_approve_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            proposal_id=editable["proposal_id"],
            statement="Approved edited meaning.",
            category="project_fact",
            confidence=0.85,
            evidence_quality="high",
            idempotency_key="edit-approve",
        )
        revised = revise_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            memory_id=first["memory_id"],
            statement="Revised meaning.",
            category="project_fact",
            evidence_chunk_ids=[chunk_id],
            confidence=0.9,
            evidence_quality="high",
            idempotency_key="revision-2",
        )
        assert revised["revision_number"] == 2

        replacement_proposal = propose_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            statement="Replacement meaning.",
            category="project_fact",
            evidence_chunk_ids=[chunk_id],
            confidence=0.95,
            evidence_quality="high",
            idempotency_key="replacement-proposal",
        )
        replacement = approve_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            proposal_id=replacement_proposal["proposal_id"],
            idempotency_key="replacement-approve",
        )
        superseded = supersede_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            memory_id=first["memory_id"],
            superseding_memory_id=replacement["memory_id"],
            idempotency_key="supersede-once",
        )
        assert superseded["status"] == "superseded"
        archived = archive_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            memory_id=replacement["memory_id"],
            idempotency_key="archive-once",
        )
        assert archived["status"] == "archived"

        admin = create_engine(database_urls.admin)
        try:
            with admin.connect() as connection:
                revisions = [
                    tuple(row)
                    for row in connection.execute(
                        text(
                            "SELECT revision_number,normalized_statement FROM memory_revisions "
                            "WHERE memory_id=:memory ORDER BY revision_number"
                        ),
                        {"memory": first["memory_id"]},
                    ).all()
                ]
                assert revisions == [
                    (1, "Approved edited meaning."),
                    (2, "Revised meaning."),
                ]
        finally:
            admin.dispose()
    finally:
        engine.dispose()


def test_superseding_memory_cannot_be_reused_and_failed_transition_rolls_back(
    database_urls: Any,
) -> None:
    owner, workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    _, _, chunk_id = _seed_ready_chunk(
        database_urls.admin, owner, workspace, "supersession reuse evidence"
    )
    sessions, engine = _sessions(database_urls.app)
    try:
        old = _approve_test_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            chunk_id=chunk_id,
            name="reuse-old",
        )
        replacement = _approve_test_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            chunk_id=chunk_id,
            name="reuse-replacement",
        )
        unrelated = _approve_test_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            chunk_id=chunk_id,
            name="reuse-unrelated",
        )
        memory_ids = [old["memory_id"], replacement["memory_id"], unrelated["memory_id"]]

        supersede_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            memory_id=old["memory_id"],
            superseding_memory_id=replacement["memory_id"],
            idempotency_key="reuse-first-link",
        )
        expected_graph = _supersession_graph(database_urls.admin, memory_ids)

        with pytest.raises(MemoryStateConflict):
            supersede_memory(
                sessions,
                owner_id=owner,
                workspace_id=workspace,
                memory_id=unrelated["memory_id"],
                superseding_memory_id=replacement["memory_id"],
                idempotency_key="reuse-rejected-link",
            )

        assert _supersession_graph(database_urls.admin, memory_ids) == expected_graph
    finally:
        engine.dispose()


def test_supersession_accepts_a_valid_reciprocal_chain(database_urls: Any) -> None:
    owner, workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    _, _, chunk_id = _seed_ready_chunk(
        database_urls.admin, owner, workspace, "supersession chain evidence"
    )
    sessions, engine = _sessions(database_urls.app)
    try:
        memories = [
            _approve_test_memory(
                sessions,
                owner_id=owner,
                workspace_id=workspace,
                chunk_id=chunk_id,
                name=f"chain-{name}",
            )
            for name in ("a", "b", "c")
        ]
        old, middle, newest = (memory["memory_id"] for memory in memories)

        supersede_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            memory_id=old,
            superseding_memory_id=middle,
            idempotency_key="chain-a-to-b",
        )
        supersede_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            memory_id=middle,
            superseding_memory_id=newest,
            idempotency_key="chain-b-to-c",
        )

        assert _supersession_graph(database_urls.admin, [old, middle, newest]) == {
            old: ("superseded", None, middle),
            middle: ("superseded", old, newest),
            newest: ("active", middle, None),
        }
    finally:
        engine.dispose()


def test_concurrent_predecessors_competing_for_one_replacement_have_one_winner(
    database_urls: Any,
) -> None:
    owner, workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    _, _, chunk_id = _seed_ready_chunk(
        database_urls.admin, owner, workspace, "concurrent supersession evidence"
    )
    sessions, engine = _sessions(database_urls.app)
    try:
        first = _approve_test_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            chunk_id=chunk_id,
            name="race-first",
        )
        second = _approve_test_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            chunk_id=chunk_id,
            name="race-second",
        )
        replacement = _approve_test_memory(
            sessions,
            owner_id=owner,
            workspace_id=workspace,
            chunk_id=chunk_id,
            name="race-replacement",
        )
        predecessors = [first["memory_id"], second["memory_id"]]
        replacement_id = replacement["memory_id"]
        start = Barrier(2)

        def compete(candidate: tuple[UUID, str]) -> tuple[UUID, str]:
            predecessor_id, idempotency_key = candidate
            start.wait(timeout=5)
            try:
                supersede_memory(
                    sessions,
                    owner_id=owner,
                    workspace_id=workspace,
                    memory_id=predecessor_id,
                    superseding_memory_id=replacement_id,
                    idempotency_key=idempotency_key,
                )
            except MemoryStateConflict:
                return predecessor_id, "conflict"
            return predecessor_id, "success"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = dict(
                pool.map(
                    compete,
                    zip(
                        predecessors,
                        ("race-first-link", "race-second-link"),
                        strict=True,
                    ),
                )
            )

        assert sorted(outcomes.values()) == ["conflict", "success"]
        winner = next(memory_id for memory_id, outcome in outcomes.items() if outcome == "success")
        loser = next(memory_id for memory_id, outcome in outcomes.items() if outcome == "conflict")
        assert _supersession_graph(database_urls.admin, [*predecessors, replacement_id]) == {
            winner: ("superseded", None, replacement_id),
            loser: ("active", None, None),
            replacement_id: ("active", winner, None),
        }
    finally:
        engine.dispose()


def test_cross_scope_memory_decision_is_indistinguishable_from_missing(
    database_urls: Any,
) -> None:
    owner, workspace = uuid4(), uuid4()
    foreign_owner, foreign_workspace = uuid4(), uuid4()
    _seed_workspace(database_urls.admin, owner, workspace)
    _seed_workspace(database_urls.admin, foreign_owner, foreign_workspace)
    _, _, chunk_id = _seed_ready_chunk(
        database_urls.admin, owner, workspace, "private proposal evidence"
    )
    owner_sessions, owner_engine = _sessions(database_urls.app)
    foreign_sessions, foreign_engine = _sessions(database_urls.app)
    try:
        proposal = propose_memory(
            owner_sessions,
            owner_id=owner,
            workspace_id=workspace,
            statement="Private memory.",
            category="other",
            evidence_chunk_ids=[chunk_id],
            confidence=0.7,
            evidence_quality="medium",
            idempotency_key="private-proposal",
        )
        with pytest.raises(MemoryNotFound):
            approve_memory(
                foreign_sessions,
                owner_id=foreign_owner,
                workspace_id=foreign_workspace,
                proposal_id=proposal["proposal_id"],
                idempotency_key="foreign-approval",
            )
    finally:
        foreign_engine.dispose()
        owner_engine.dispose()
