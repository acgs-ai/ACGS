from threading import Event, Thread
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError

APPEND_ONLY_TABLES = (
    "source_versions",
    "ingestion_job_events",
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


def seed_member_source(
    admin_url: str,
    *,
    workspace_owner: UUID | None = None,
    member_id: UUID | None = None,
    workspace_id: UUID | None = None,
    source_id: UUID | None = None,
) -> tuple[UUID, UUID, UUID, UUID]:
    workspace_owner = workspace_owner or uuid4()
    member_id = member_id or uuid4()
    workspace_id = workspace_id or uuid4()
    source_id = source_id or uuid4()
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE sources SET processing_state='ready' WHERE id=:source"),
                {"source": source_id},
            )
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                [
                    {"id": workspace_owner, "email": f"{workspace_owner}@example.test"},
                    {"id": member_id, "email": f"{member_id}@example.test"},
                ],
            )
            connection.execute(
                text("INSERT INTO workspaces (id,owner_id,name) VALUES (:id,:owner,'workspace')"),
                {"id": workspace_id, "owner": workspace_owner},
            )
            connection.execute(
                text(
                    "INSERT INTO workspace_memberships (workspace_id,user_id,role) VALUES "
                    "(:workspace,:owner,'owner'),(:workspace,:member,'member')"
                ),
                {"workspace": workspace_id, "owner": workspace_owner, "member": member_id},
            )
            connection.execute(
                text(
                    "INSERT INTO sources "
                    "(id,owner_id,workspace_id,source_type,display_title,content_sha256,"
                    "normalized_dedup_sha256,mime_type,processing_state) VALUES "
                    "(:id,:member,:workspace,'note','member source',:content,:dedup,"
                    "'text/plain','ready')"
                ),
                {
                    "id": source_id,
                    "member": member_id,
                    "workspace": workspace_id,
                    "content": uuid4().hex * 2,
                    "dedup": uuid4().hex * 2,
                },
            )
    finally:
        engine.dispose()

    return workspace_owner, member_id, workspace_id, source_id


def seed_version_document_chunk(
    admin_url: str, owner_id: UUID, workspace_id: UUID, source_id: UUID
) -> tuple[UUID, UUID, UUID]:
    version_id, document_id, chunk_id = uuid4(), uuid4(), uuid4()
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO source_versions "
                    "(id,owner_id,workspace_id,source_id,version_number,parser_name,"
                    "parser_version,chunker_version,content_sha256) VALUES "
                    "(:id,:owner,:workspace,:source,1,'text','1','v1',:hash)"
                ),
                {
                    "id": version_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "source": source_id,
                    "hash": uuid4().hex * 2,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO documents "
                    "(id,owner_id,workspace_id,source_version_id,extracted_text,character_count) "
                    "VALUES (:id,:owner,:workspace,:version,'evidence',8)"
                ),
                {
                    "id": document_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "version": version_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO chunks "
                    "(id,owner_id,workspace_id,document_id,source_version_id,ordinal,chunk_text,"
                    "char_start,char_end,chunker_version) VALUES "
                    "(:id,:owner,:workspace,:document,:version,0,'evidence',0,8,'v1')"
                ),
                {
                    "id": chunk_id,
                    "owner": owner_id,
                    "workspace": workspace_id,
                    "document": document_id,
                    "version": version_id,
                },
            )
    finally:
        engine.dispose()
    return version_id, document_id, chunk_id


def test_non_owner_membership_can_own_scoped_objects(database_urls: Any) -> None:
    workspace_owner, member_id, workspace_id, source_id = seed_member_source(database_urls.admin)
    assert member_id != workspace_owner
    engine = create_engine(database_urls.app)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('app.owner_id',:owner,true)"), {"owner": str(member_id)}
            )
            connection.execute(
                text("SELECT set_config('app.workspace_id',:workspace,true)"),
                {"workspace": str(workspace_id)},
            )
            assert connection.scalar(text("SELECT id FROM sources")) == source_id
    finally:
        engine.dispose()


def test_app_role_cannot_update_or_delete_append_only_relations(database_urls: Any) -> None:
    engine = create_engine(database_urls.app)
    try:
        for table in APPEND_ONLY_TABLES:
            with pytest.raises(DBAPIError), engine.begin() as connection:
                connection.execute(text(f'UPDATE "{table}" SET owner_id=owner_id WHERE false'))
            with pytest.raises(DBAPIError), engine.begin() as connection:
                connection.execute(text(f'DELETE FROM "{table}" WHERE false'))
    finally:
        engine.dispose()


def test_job_and_chunk_composites_reject_mismatched_lineage(database_urls: Any) -> None:
    _, member, workspace, source_a = seed_member_source(database_urls.admin)
    source_b = uuid4()
    engine = create_engine(database_urls.admin)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO sources "
                    "(id,owner_id,workspace_id,source_type,display_title,content_sha256,"
                    "normalized_dedup_sha256,mime_type) VALUES "
                    "(:id,:owner,:workspace,'note','second',:content,:dedup,'text/plain')"
                ),
                {
                    "id": source_b,
                    "owner": member,
                    "workspace": workspace,
                    "content": uuid4().hex * 2,
                    "dedup": uuid4().hex * 2,
                },
            )
    finally:
        engine.dispose()

    version_a, document_a, _ = seed_version_document_chunk(
        database_urls.admin, member, workspace, source_a
    )
    version_b, _, _ = seed_version_document_chunk(database_urls.admin, member, workspace, source_b)
    engine = create_engine(database_urls.admin)
    try:
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ingestion_jobs "
                    "(owner_id,workspace_id,source_id,source_version_id) "
                    "VALUES (:owner,:workspace,:source,:version)"
                ),
                {"owner": member, "workspace": workspace, "source": source_a, "version": version_b},
            )
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO chunks "
                    "(owner_id,workspace_id,document_id,source_version_id,ordinal,chunk_text,"
                    "char_start,char_end,chunker_version) VALUES "
                    "(:owner,:workspace,:document,:version,1,'bad',0,3,'v1')"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "document": document_a,
                    "version": version_b,
                },
            )
        assert version_a != version_b
    finally:
        engine.dispose()


def test_job_state_requires_append_only_transactional_event(database_urls: Any) -> None:
    _, member, workspace, source = seed_member_source(database_urls.admin)
    version, _, _ = seed_version_document_chunk(database_urls.admin, member, workspace, source)
    job = uuid4()
    engine = create_engine(database_urls.admin)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ingestion_jobs "
                    "(id,owner_id,workspace_id,source_id,source_version_id) "
                    "VALUES (:job,:owner,:workspace,:source,:version)"
                ),
                {
                    "job": job,
                    "owner": member,
                    "workspace": workspace,
                    "source": source,
                    "version": version,
                },
            )
            initial = connection.execute(
                text(
                    "SELECT attempt,from_state,to_state,reason_class "
                    "FROM ingestion_job_events WHERE job_id=:job"
                ),
                {"job": job},
            ).one()
            assert initial == (0, None, "queued", "capture_queued")
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text("UPDATE ingestion_jobs SET state='processing',attempts=1 WHERE id=:job"),
                {"job": job},
            )
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text("UPDATE ingestion_job_events SET reason_class='changed' WHERE job_id=:job"),
                {"job": job},
            )
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ingestion_job_events "
                    "(owner_id,workspace_id,job_id,attempt,from_state,to_state,reason_class) "
                    "VALUES (:owner,:workspace,:job,0,'queued','dead','test_cleanup')"
                ),
                {"owner": member, "workspace": workspace, "job": job},
            )
            connection.execute(
                text("UPDATE ingestion_jobs SET state='dead' WHERE id=:job"), {"job": job}
            )
    finally:
        engine.dispose()


def test_capture_stage_state_machine_preserves_lineage(database_urls: Any) -> None:
    _, member, workspace, source = seed_member_source(database_urls.admin)
    version, _, _ = seed_version_document_chunk(database_urls.admin, member, workspace, source)
    stage, job = uuid4(), uuid4()
    engine = create_engine(database_urls.admin)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ingestion_jobs "
                    "(id,owner_id,workspace_id,source_id,source_version_id) "
                    "VALUES (:id,:owner,:workspace,:source,:version)"
                ),
                {
                    "id": job,
                    "owner": member,
                    "workspace": workspace,
                    "source": source,
                    "version": version,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO capture_stages "
                    "(id,owner_id,workspace_id,object_key,kind,intended_content_sha256,"
                    "intended_size,source_id,job_id) "
                    "VALUES (:id,:owner,:workspace,:key,'txt',:hash,8,:source,:job)"
                ),
                {
                    "id": stage,
                    "owner": member,
                    "workspace": workspace,
                    "key": f"stages/{stage}",
                    "hash": uuid4().hex * 2,
                    "source": source,
                    "job": job,
                },
            )
            connection.execute(
                text(
                    "UPDATE capture_stages SET state='stored',stored_at=clock_timestamp() "
                    "WHERE id=:id"
                ),
                {"id": stage},
            )
            connection.execute(
                text(
                    "UPDATE capture_stages SET state='finalized',finalized_at=clock_timestamp(),"
                    "source_version_id=:version WHERE id=:id"
                ),
                {"id": stage, "source": source, "version": version},
            )
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text("UPDATE capture_stages SET state='pending' WHERE id=:id"), {"id": stage}
            )
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text("UPDATE capture_stages SET object_key='changed' WHERE id=:id"), {"id": stage}
            )
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text("UPDATE capture_stages SET job_id=:job WHERE id=:id"),
                {"id": stage, "job": uuid4()},
            )
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO ingestion_job_events "
                    "(owner_id,workspace_id,job_id,attempt,from_state,to_state,reason_class) "
                    "VALUES (:owner,:workspace,:job,0,'queued','dead','test_cleanup')"
                ),
                {"owner": member, "workspace": workspace, "job": job},
            )
            connection.execute(
                text("UPDATE ingestion_jobs SET state='dead' WHERE id=:job"), {"job": job}
            )
    finally:
        engine.dispose()


def test_embedding_profiles_enforce_multiple_dimensions(database_urls: Any) -> None:
    _, member, workspace, source = seed_member_source(database_urls.admin)
    _, _, chunk = seed_version_document_chunk(database_urls.admin, member, workspace, source)
    engine = create_engine(database_urls.admin)
    try:
        with engine.begin() as connection:
            profile_three, profile_four = uuid4(), uuid4()
            connection.execute(
                text(
                    "INSERT INTO embedding_profiles "
                    "(id,owner_id,workspace_id,provider,model_identifier,"
                    "profile_version,dimensions) "
                    "VALUES (:p3,:owner,:workspace,'fake','three',1,3),"
                    "(:p4,:owner,:workspace,'fake','four',1,4)"
                ),
                {
                    "p3": profile_three,
                    "p4": profile_four,
                    "owner": member,
                    "workspace": workspace,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO embeddings (owner_id,workspace_id,chunk_id,profile_id,embedding) "
                    "VALUES (:owner,:workspace,:chunk,:profile,'[1,2,3]')"
                ),
                {"owner": member, "workspace": workspace, "chunk": chunk, "profile": profile_three},
            )
            second_chunk = uuid4()
            document = connection.scalar(
                text("SELECT document_id FROM chunks WHERE id=:chunk"), {"chunk": chunk}
            )
            version = connection.scalar(
                text("SELECT source_version_id FROM chunks WHERE id=:chunk"), {"chunk": chunk}
            )
            connection.execute(
                text(
                    "INSERT INTO chunks "
                    "(id,owner_id,workspace_id,document_id,source_version_id,ordinal,chunk_text,"
                    "char_start,char_end,chunker_version) VALUES "
                    "(:id,:owner,:workspace,:document,:version,1,'more',8,12,'v1')"
                ),
                {
                    "id": second_chunk,
                    "owner": member,
                    "workspace": workspace,
                    "document": document,
                    "version": version,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO embeddings (owner_id,workspace_id,chunk_id,profile_id,embedding) "
                    "VALUES (:owner,:workspace,:chunk,:profile,'[1,2,3,4]')"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "chunk": second_chunk,
                    "profile": profile_four,
                },
            )
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO embeddings (owner_id,workspace_id,chunk_id,profile_id,embedding) "
                    "VALUES (:owner,:workspace,:chunk,:profile,'[1,2]')"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "chunk": second_chunk,
                    "profile": profile_three,
                },
            )
    finally:
        engine.dispose()


def test_citation_composites_bind_answer_result_run_and_chunk(database_urls: Any) -> None:
    _, member, workspace, source = seed_member_source(database_urls.admin)
    _, _, chunk = seed_version_document_chunk(database_urls.admin, member, workspace, source)
    mismatched_chunk = uuid4()
    run_a, run_b, result_a, answer_a = uuid4(), uuid4(), uuid4(), uuid4()
    engine = create_engine(database_urls.admin)
    try:
        with engine.begin() as connection:
            document_id, source_version_id, char_start, char_end, chunk_text = connection.execute(
                text(
                    "SELECT document_id,source_version_id,char_start,char_end,chunk_text "
                    "FROM chunks WHERE id=:chunk"
                ),
                {"chunk": chunk},
            ).one()
            connection.execute(
                text("UPDATE sources SET processing_state='ready' WHERE id=:source"),
                {"source": source},
            )
            connection.execute(
                text(
                    "INSERT INTO retrieval_runs (id,owner_id,workspace_id,query,configuration) "
                    "VALUES (:a,:owner,:workspace,'a','{}'),(:b,:owner,:workspace,'b','{}')"
                ),
                {"a": run_a, "b": run_b, "owner": member, "workspace": workspace},
            )
            connection.execute(
                text(
                    "INSERT INTO retrieval_results "
                    "(id,owner_id,workspace_id,retrieval_run_id,chunk_id,source_id,"
                    "source_version_id,fused_rank,fused_score,selected,evidence_ordinal,"
                    "evidence_text,evidence_char_start,evidence_char_end) "
                    "VALUES (:id,:owner,:workspace,:run,:chunk,:source,:version,1,1,true,1,"
                    ":evidence,:char_start,:char_end)"
                ),
                {
                    "id": result_a,
                    "owner": member,
                    "workspace": workspace,
                    "run": run_a,
                    "chunk": chunk,
                    "source": source,
                    "version": source_version_id,
                    "evidence": chunk_text,
                    "char_start": char_start,
                    "char_end": char_end,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO answers "
                    "(id,owner_id,workspace_id,retrieval_run_id,model_provider,model_identifier,"
                    "prompt_template_version,status) VALUES "
                    "(:id,:owner,:workspace,:run,'fake','fake','v1','grounded')"
                ),
                {"id": answer_a, "owner": member, "workspace": workspace, "run": run_a},
            )
            connection.execute(
                text(
                    "INSERT INTO chunks "
                    "(id,owner_id,workspace_id,document_id,source_version_id,ordinal,chunk_text,"
                    "char_start,char_end,chunker_version) VALUES "
                    "(:id,:owner,:workspace,:document,:version,1,'other',8,13,'v1')"
                ),
                {
                    "id": mismatched_chunk,
                    "owner": member,
                    "workspace": workspace,
                    "document": document_id,
                    "version": source_version_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO citations "
                    "(owner_id,workspace_id,answer_id,retrieval_run_id,"
                    "retrieval_result_id,chunk_id,source_id,source_version_id,evidence_ordinal,"
                    "statement_id,statement_index,char_start,char_end,validated) "
                    "VALUES (:owner,:workspace,:answer,:run,:result,:chunk,:source,:version,1,"
                    ":statement,0,:char_start,:char_end,true)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "answer": answer_a,
                    "run": run_a,
                    "result": result_a,
                    "chunk": chunk,
                    "source": source,
                    "version": source_version_id,
                    "statement": uuid4(),
                    "char_start": char_start,
                    "char_end": char_end,
                },
            )
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO citations "
                    "(owner_id,workspace_id,answer_id,retrieval_run_id,"
                    "retrieval_result_id,chunk_id,source_id,source_version_id,evidence_ordinal,"
                    "statement_id,statement_index,char_start,char_end,validated) "
                    "VALUES (:owner,:workspace,:answer,:run,:result,:chunk,:source,:version,1,"
                    ":statement,1,:char_start,:char_end,true)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "answer": answer_a,
                    "run": run_b,
                    "result": result_a,
                    "chunk": mismatched_chunk,
                    "source": source,
                    "version": source_version_id,
                    "statement": uuid4(),
                    "char_start": char_start,
                    "char_end": char_end,
                },
            )
    finally:
        engine.dispose()


def test_memory_evidence_rejects_missing_and_cross_scope_chunks(database_urls: Any) -> None:
    _, member_a, workspace_a, source_a = seed_member_source(database_urls.admin)
    _, _, chunk_a = seed_version_document_chunk(
        database_urls.admin, member_a, workspace_a, source_a
    )
    _, member_b, workspace_b, source_b = seed_member_source(database_urls.admin)
    _, _, chunk_b = seed_version_document_chunk(
        database_urls.admin, member_b, workspace_b, source_b
    )
    proposal = uuid4()
    open_proposal = uuid4()
    memory = uuid4()
    revision = uuid4()
    engine = create_engine(database_urls.admin)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO memory_proposals "
                    "(id,owner_id,workspace_id,normalized_statement,category,"
                    "evidence_quality) VALUES "
                    "(:id,:owner,:workspace,'statement','fact',1),"
                    "(:open,:owner,:workspace,'open','fact',1)"
                ),
                {
                    "id": proposal,
                    "open": open_proposal,
                    "owner": member_a,
                    "workspace": workspace_a,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_proposal_evidence "
                    "(owner_id,workspace_id,proposal_id,chunk_id) VALUES "
                    "(:owner,:workspace,:proposal,:chunk),"
                    "(:owner,:workspace,:open,:chunk)"
                ),
                {
                    "owner": member_a,
                    "workspace": workspace_a,
                    "proposal": proposal,
                    "open": open_proposal,
                    "chunk": chunk_a,
                },
            )
            connection.execute(
                text(
                    "UPDATE memory_proposals SET status='approved',decided_at=now() "
                    "WHERE id=:proposal"
                ),
                {"proposal": proposal},
            )
            connection.execute(
                text(
                    "INSERT INTO approved_memories "
                    "(id,owner_id,workspace_id,proposal_id,approved_at) "
                    "VALUES (:id,:owner,:workspace,:proposal,now())"
                ),
                {
                    "id": memory,
                    "owner": member_a,
                    "workspace": workspace_a,
                    "proposal": proposal,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revisions "
                    "(id,owner_id,workspace_id,memory_id,revision_number,normalized_statement) "
                    "VALUES (:id,:owner,:workspace,:memory,1,'statement')"
                ),
                {
                    "id": revision,
                    "owner": member_a,
                    "workspace": workspace_a,
                    "memory": memory,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revision_evidence "
                    "(owner_id,workspace_id,revision_id,chunk_id) "
                    "VALUES (:owner,:workspace,:revision,:chunk)"
                ),
                {
                    "owner": member_a,
                    "workspace": workspace_a,
                    "revision": revision,
                    "chunk": chunk_a,
                },
            )
            connection.execute(
                text("UPDATE approved_memories SET current_revision_id=:revision WHERE id=:memory"),
                {"revision": revision, "memory": memory},
            )
        for invalid_chunk in (uuid4(), chunk_b):
            with pytest.raises(IntegrityError), engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO memory_proposal_evidence "
                        "(owner_id,workspace_id,proposal_id,chunk_id) "
                        "VALUES (:owner,:workspace,:proposal,:chunk)"
                    ),
                    {
                        "owner": member_a,
                        "workspace": workspace_a,
                        "proposal": open_proposal,
                        "chunk": invalid_chunk,
                    },
                )
            with pytest.raises(IntegrityError), engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO memory_revision_evidence "
                        "(owner_id,workspace_id,revision_id,chunk_id) "
                        "VALUES (:owner,:workspace,:revision,:chunk)"
                    ),
                    {
                        "owner": member_a,
                        "workspace": workspace_a,
                        "revision": revision,
                        "chunk": invalid_chunk,
                    },
                )
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text("UPDATE approved_memories SET current_revision_id=:revision WHERE id=:memory"),
                {"revision": uuid4(), "memory": memory},
            )
    finally:
        engine.dispose()


def test_app_role_cannot_commit_invalid_memory_activation_states(database_urls: Any) -> None:
    _, member, workspace, source = seed_member_source(database_urls.admin)
    _, _, chunk = seed_version_document_chunk(database_urls.admin, member, workspace, source)
    proposed_id, approved_id, approved_without_revision_id = uuid4(), uuid4(), uuid4()
    memory_id, revision_id = uuid4(), uuid4()
    admin = create_engine(database_urls.admin)
    try:
        with admin.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO memory_proposals "
                    "(id,owner_id,workspace_id,normalized_statement,category,"
                    "evidence_quality) "
                    "VALUES (:proposed,:owner,:workspace,'proposed','fact',1),"
                    "(:approved,:owner,:workspace,'approved','fact',1),"
                    "(:without_revision,:owner,:workspace,'without revision','fact',1)"
                ),
                {
                    "proposed": proposed_id,
                    "approved": approved_id,
                    "without_revision": approved_without_revision_id,
                    "owner": member,
                    "workspace": workspace,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_proposal_evidence "
                    "(owner_id,workspace_id,proposal_id,chunk_id) VALUES "
                    "(:owner,:workspace,:proposed,:chunk),"
                    "(:owner,:workspace,:approved,:chunk),"
                    "(:owner,:workspace,:without_revision,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "proposed": proposed_id,
                    "approved": approved_id,
                    "without_revision": approved_without_revision_id,
                    "chunk": chunk,
                },
            )
            connection.execute(
                text(
                    "UPDATE memory_proposals SET status='approved',decided_at=now() "
                    "WHERE id IN (:approved,:without_revision)"
                ),
                {
                    "approved": approved_id,
                    "without_revision": approved_without_revision_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO approved_memories "
                    "(id,owner_id,workspace_id,proposal_id,approved_at) "
                    "VALUES (:memory,:owner,:workspace,:proposal,now())"
                ),
                {
                    "memory": memory_id,
                    "owner": member,
                    "workspace": workspace,
                    "proposal": approved_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revisions "
                    "(id,owner_id,workspace_id,memory_id,revision_number,normalized_statement) "
                    "VALUES (:revision,:owner,:workspace,:memory,1,'approved')"
                ),
                {
                    "revision": revision_id,
                    "owner": member,
                    "workspace": workspace,
                    "memory": memory_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revision_evidence "
                    "(owner_id,workspace_id,revision_id,chunk_id) "
                    "VALUES (:owner,:workspace,:revision,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "revision": revision_id,
                    "chunk": chunk,
                },
            )
            connection.execute(
                text("UPDATE approved_memories SET current_revision_id=:revision WHERE id=:memory"),
                {"revision": revision_id, "memory": memory_id},
            )
    finally:
        admin.dispose()

    app_engine = create_engine(database_urls.app)
    invalid_memory, invalid_revision = uuid4(), uuid4()
    try:
        with pytest.raises(DBAPIError), app_engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('app.owner_id',:owner,true)"),
                {"owner": str(member)},
            )
            connection.execute(
                text("SELECT set_config('app.workspace_id',:workspace,true)"),
                {"workspace": str(workspace)},
            )
            connection.execute(
                text(
                    "INSERT INTO memory_proposals "
                    "(owner_id,workspace_id,normalized_statement,category,evidence_quality) "
                    "VALUES (:owner,:workspace,'no evidence','fact',1)"
                ),
                {"owner": member, "workspace": workspace},
            )
        with pytest.raises(DBAPIError), app_engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('app.owner_id',:owner,true)"),
                {"owner": str(member)},
            )
            connection.execute(
                text("SELECT set_config('app.workspace_id',:workspace,true)"),
                {"workspace": str(workspace)},
            )
            connection.execute(
                text(
                    "INSERT INTO approved_memories "
                    "(id,owner_id,workspace_id,proposal_id,approved_at) "
                    "VALUES (:memory,:owner,:workspace,:proposal,now())"
                ),
                {
                    "memory": invalid_memory,
                    "owner": member,
                    "workspace": workspace,
                    "proposal": proposed_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revisions "
                    "(id,owner_id,workspace_id,memory_id,revision_number,normalized_statement) "
                    "VALUES (:revision,:owner,:workspace,:memory,1,'invalid activation')"
                ),
                {
                    "revision": invalid_revision,
                    "owner": member,
                    "workspace": workspace,
                    "memory": invalid_memory,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revision_evidence "
                    "(owner_id,workspace_id,revision_id,chunk_id) "
                    "VALUES (:owner,:workspace,:revision,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "revision": invalid_revision,
                    "chunk": chunk,
                },
            )
            connection.execute(
                text("UPDATE approved_memories SET current_revision_id=:revision WHERE id=:memory"),
                {"revision": invalid_revision, "memory": invalid_memory},
            )
        with pytest.raises(DBAPIError), app_engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('app.owner_id',:owner,true)"),
                {"owner": str(member)},
            )
            connection.execute(
                text("SELECT set_config('app.workspace_id',:workspace,true)"),
                {"workspace": str(workspace)},
            )
            connection.execute(
                text(
                    "INSERT INTO approved_memories "
                    "(owner_id,workspace_id,proposal_id,approved_at) "
                    "VALUES (:owner,:workspace,:proposal,now())"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "proposal": approved_without_revision_id,
                },
            )
        with pytest.raises(DBAPIError), app_engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('app.owner_id',:owner,true)"),
                {"owner": str(member)},
            )
            connection.execute(
                text("SELECT set_config('app.workspace_id',:workspace,true)"),
                {"workspace": str(workspace)},
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revisions "
                    "(owner_id,workspace_id,memory_id,revision_number,normalized_statement) "
                    "VALUES (:owner,:workspace,:memory,2,'no evidence')"
                ),
                {"owner": member, "workspace": workspace, "memory": memory_id},
            )
    finally:
        app_engine.dispose()


def test_initial_revision_preserves_proposal_evidence_and_freezes_it_after_decision(
    database_urls: Any,
) -> None:
    _, member, workspace, source = seed_member_source(database_urls.admin)
    version, document, chunk_a = seed_version_document_chunk(
        database_urls.admin, member, workspace, source
    )
    chunk_b = uuid4()
    admin = create_engine(database_urls.admin)
    try:
        with admin.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO chunks "
                    "(id,owner_id,workspace_id,document_id,source_version_id,ordinal,chunk_text,"
                    "char_start,char_end,chunker_version) VALUES "
                    "(:id,:owner,:workspace,:document,:version,1,'other evidence',9,23,'v1')"
                ),
                {
                    "id": chunk_b,
                    "owner": member,
                    "workspace": workspace,
                    "document": document,
                    "version": version,
                },
            )
    finally:
        admin.dispose()

    def set_scope(connection: Any) -> None:
        connection.execute(
            text("SELECT set_config('app.owner_id',:owner,true)"), {"owner": str(member)}
        )
        connection.execute(
            text("SELECT set_config('app.workspace_id',:workspace,true)"),
            {"workspace": str(workspace)},
        )

    app_engine = create_engine(database_urls.app)
    try:
        matching_proposal, matching_memory, matching_revision = uuid4(), uuid4(), uuid4()
        with app_engine.begin() as connection:
            set_scope(connection)
            connection.execute(
                text(
                    "INSERT INTO memory_proposals "
                    "(id,owner_id,workspace_id,normalized_statement,category,evidence_quality) "
                    "VALUES (:proposal,:owner,:workspace,'matching','fact',1)"
                ),
                {"proposal": matching_proposal, "owner": member, "workspace": workspace},
            )
            connection.execute(
                text(
                    "INSERT INTO memory_proposal_evidence "
                    "(owner_id,workspace_id,proposal_id,chunk_id) "
                    "VALUES (:owner,:workspace,:proposal,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "proposal": matching_proposal,
                    "chunk": chunk_a,
                },
            )
            connection.execute(
                text(
                    "UPDATE memory_proposals SET status='approved',decided_at=now() "
                    "WHERE id=:proposal"
                ),
                {"proposal": matching_proposal},
            )
            connection.execute(
                text(
                    "INSERT INTO approved_memories "
                    "(id,owner_id,workspace_id,proposal_id,approved_at) "
                    "VALUES (:memory,:owner,:workspace,:proposal,now())"
                ),
                {
                    "memory": matching_memory,
                    "owner": member,
                    "workspace": workspace,
                    "proposal": matching_proposal,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revisions "
                    "(id,owner_id,workspace_id,memory_id,revision_number,normalized_statement) "
                    "VALUES (:revision,:owner,:workspace,:memory,1,'matching')"
                ),
                {
                    "revision": matching_revision,
                    "owner": member,
                    "workspace": workspace,
                    "memory": matching_memory,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revision_evidence "
                    "(owner_id,workspace_id,revision_id,chunk_id) "
                    "VALUES (:owner,:workspace,:revision,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "revision": matching_revision,
                    "chunk": chunk_a,
                },
            )
            connection.execute(
                text("UPDATE approved_memories SET current_revision_id=:revision WHERE id=:memory"),
                {"revision": matching_revision, "memory": matching_memory},
            )

        with app_engine.connect() as connection:
            set_scope(connection)
            initial_revision = connection.execute(
                text(
                    "SELECT id,normalized_statement FROM memory_revisions "
                    "WHERE memory_id=:memory AND revision_number=1"
                ),
                {"memory": matching_memory},
            ).one()
            initial_evidence = connection.execute(
                text(
                    "SELECT chunk_id FROM memory_revision_evidence "
                    "WHERE revision_id=:revision ORDER BY chunk_id"
                ),
                {"revision": matching_revision},
            ).all()

        second_revision = uuid4()
        with app_engine.begin() as connection:
            set_scope(connection)
            connection.execute(
                text(
                    "INSERT INTO memory_revisions "
                    "(id,owner_id,workspace_id,memory_id,revision_number,normalized_statement) "
                    "VALUES (:revision,:owner,:workspace,:memory,2,'revised')"
                ),
                {
                    "revision": second_revision,
                    "owner": member,
                    "workspace": workspace,
                    "memory": matching_memory,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revision_evidence "
                    "(owner_id,workspace_id,revision_id,chunk_id) "
                    "VALUES (:owner,:workspace,:revision,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "revision": second_revision,
                    "chunk": chunk_b,
                },
            )
            connection.execute(
                text("UPDATE approved_memories SET current_revision_id=:revision WHERE id=:memory"),
                {"revision": second_revision, "memory": matching_memory},
            )

        with app_engine.connect() as connection:
            set_scope(connection)
            assert (
                connection.scalar(
                    text("SELECT current_revision_id FROM approved_memories WHERE id=:memory"),
                    {"memory": matching_memory},
                )
                == second_revision
            )
            assert (
                connection.execute(
                    text(
                        "SELECT id,normalized_statement FROM memory_revisions "
                        "WHERE memory_id=:memory AND revision_number=1"
                    ),
                    {"memory": matching_memory},
                ).one()
                == initial_revision
            )
            assert (
                connection.execute(
                    text(
                        "SELECT chunk_id FROM memory_revision_evidence "
                        "WHERE revision_id=:revision ORDER BY chunk_id"
                    ),
                    {"revision": matching_revision},
                ).all()
                == initial_evidence
            )

        with pytest.raises(DBAPIError), app_engine.begin() as connection:
            set_scope(connection)
            connection.execute(
                text(
                    "INSERT INTO memory_revision_evidence "
                    "(owner_id,workspace_id,revision_id,chunk_id) "
                    "VALUES (:owner,:workspace,:revision,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "revision": matching_revision,
                    "chunk": chunk_b,
                },
            )

        with pytest.raises(DBAPIError), app_engine.begin() as connection:
            set_scope(connection)
            connection.execute(
                text(
                    "INSERT INTO memory_proposal_evidence "
                    "(owner_id,workspace_id,proposal_id,chunk_id) "
                    "VALUES (:owner,:workspace,:proposal,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "proposal": matching_proposal,
                    "chunk": chunk_b,
                },
            )

        mismatched_proposal, mismatched_memory, mismatched_revision = uuid4(), uuid4(), uuid4()
        with pytest.raises(DBAPIError), app_engine.begin() as connection:
            set_scope(connection)
            connection.execute(
                text(
                    "INSERT INTO memory_proposals "
                    "(id,owner_id,workspace_id,normalized_statement,category,evidence_quality) "
                    "VALUES (:proposal,:owner,:workspace,'mismatch','fact',1)"
                ),
                {"proposal": mismatched_proposal, "owner": member, "workspace": workspace},
            )
            connection.execute(
                text(
                    "INSERT INTO memory_proposal_evidence "
                    "(owner_id,workspace_id,proposal_id,chunk_id) "
                    "VALUES (:owner,:workspace,:proposal,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "proposal": mismatched_proposal,
                    "chunk": chunk_a,
                },
            )
            connection.execute(
                text("UPDATE memory_proposals SET status='approved' WHERE id=:proposal"),
                {"proposal": mismatched_proposal},
            )
            connection.execute(
                text(
                    "INSERT INTO approved_memories "
                    "(id,owner_id,workspace_id,proposal_id,approved_at) "
                    "VALUES (:memory,:owner,:workspace,:proposal,now())"
                ),
                {
                    "memory": mismatched_memory,
                    "owner": member,
                    "workspace": workspace,
                    "proposal": mismatched_proposal,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revisions "
                    "(id,owner_id,workspace_id,memory_id,revision_number,normalized_statement) "
                    "VALUES (:revision,:owner,:workspace,:memory,1,'mismatch')"
                ),
                {
                    "revision": mismatched_revision,
                    "owner": member,
                    "workspace": workspace,
                    "memory": mismatched_memory,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revision_evidence "
                    "(owner_id,workspace_id,revision_id,chunk_id) "
                    "VALUES (:owner,:workspace,:revision,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "revision": mismatched_revision,
                    "chunk": chunk_b,
                },
            )
            connection.execute(
                text("UPDATE approved_memories SET current_revision_id=:revision WHERE id=:memory"),
                {"revision": mismatched_revision, "memory": mismatched_memory},
            )

        foreign_proposal, foreign_memory, foreign_revision = uuid4(), uuid4(), uuid4()
        with app_engine.begin() as connection:
            set_scope(connection)
            connection.execute(
                text(
                    "INSERT INTO memory_proposals "
                    "(id,owner_id,workspace_id,normalized_statement,category,evidence_quality) "
                    "VALUES (:proposal,:owner,:workspace,'foreign','fact',1)"
                ),
                {"proposal": foreign_proposal, "owner": member, "workspace": workspace},
            )
            connection.execute(
                text(
                    "INSERT INTO memory_proposal_evidence "
                    "(owner_id,workspace_id,proposal_id,chunk_id) "
                    "VALUES (:owner,:workspace,:proposal,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "proposal": foreign_proposal,
                    "chunk": chunk_b,
                },
            )
            connection.execute(
                text("UPDATE memory_proposals SET status='approved' WHERE id=:proposal"),
                {"proposal": foreign_proposal},
            )
            connection.execute(
                text(
                    "INSERT INTO approved_memories "
                    "(id,owner_id,workspace_id,proposal_id,approved_at) "
                    "VALUES (:memory,:owner,:workspace,:proposal,now())"
                ),
                {
                    "memory": foreign_memory,
                    "owner": member,
                    "workspace": workspace,
                    "proposal": foreign_proposal,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revisions "
                    "(id,owner_id,workspace_id,memory_id,revision_number,normalized_statement) "
                    "VALUES (:revision,:owner,:workspace,:memory,1,'foreign')"
                ),
                {
                    "revision": foreign_revision,
                    "owner": member,
                    "workspace": workspace,
                    "memory": foreign_memory,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO memory_revision_evidence "
                    "(owner_id,workspace_id,revision_id,chunk_id) "
                    "VALUES (:owner,:workspace,:revision,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "revision": foreign_revision,
                    "chunk": chunk_b,
                },
            )
            connection.execute(
                text("UPDATE approved_memories SET current_revision_id=:revision WHERE id=:memory"),
                {"revision": foreign_revision, "memory": foreign_memory},
            )
        with pytest.raises(DBAPIError), app_engine.begin() as connection:
            set_scope(connection)
            connection.execute(
                text("UPDATE approved_memories SET current_revision_id=:revision WHERE id=:memory"),
                {"revision": foreign_revision, "memory": matching_memory},
            )
    finally:
        app_engine.dispose()


def test_proposal_evidence_insert_serializes_with_approval_decision(database_urls: Any) -> None:
    _, member, workspace, source = seed_member_source(database_urls.admin)
    version, document, chunk_a = seed_version_document_chunk(
        database_urls.admin, member, workspace, source
    )
    chunk_b = uuid4()
    admin = create_engine(database_urls.admin)
    try:
        with admin.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO chunks "
                    "(id,owner_id,workspace_id,document_id,source_version_id,ordinal,chunk_text,"
                    "char_start,char_end,chunker_version) VALUES "
                    "(:id,:owner,:workspace,:document,:version,1,'concurrent',9,19,'v1')"
                ),
                {
                    "id": chunk_b,
                    "owner": member,
                    "workspace": workspace,
                    "document": document,
                    "version": version,
                },
            )
    finally:
        admin.dispose()

    app_engine = create_engine(database_urls.app)

    def set_scope(connection: Any) -> None:
        connection.execute(
            text("SELECT set_config('app.owner_id',:owner,true)"), {"owner": str(member)}
        )
        connection.execute(
            text("SELECT set_config('app.workspace_id',:workspace,true)"),
            {"workspace": str(workspace)},
        )
        connection.execute(text("SET LOCAL statement_timeout = '3s'"))

    def seed_proposal(proposal: UUID) -> None:
        with app_engine.begin() as connection:
            set_scope(connection)
            connection.execute(
                text(
                    "INSERT INTO memory_proposals "
                    "(id,owner_id,workspace_id,normalized_statement,category,evidence_quality) "
                    "VALUES (:proposal,:owner,:workspace,'race','fact',1)"
                ),
                {"proposal": proposal, "owner": member, "workspace": workspace},
            )
            connection.execute(
                text(
                    "INSERT INTO memory_proposal_evidence "
                    "(owner_id,workspace_id,proposal_id,chunk_id) "
                    "VALUES (:owner,:workspace,:proposal,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "proposal": proposal,
                    "chunk": chunk_a,
                },
            )

    try:
        evidence_first = uuid4()
        seed_proposal(evidence_first)
        approval_started, approval_done = Event(), Event()
        approval_errors: list[BaseException] = []

        def approve_after_evidence_lock() -> None:
            try:
                with app_engine.begin() as connection:
                    set_scope(connection)
                    approval_started.set()
                    connection.execute(
                        text(
                            "UPDATE memory_proposals "
                            "SET status='approved',decided_at=clock_timestamp() "
                            "WHERE id=:proposal"
                        ),
                        {"proposal": evidence_first},
                    )
            except BaseException as exc:
                approval_errors.append(exc)
            finally:
                approval_done.set()

        evidence_connection = app_engine.connect()
        evidence_transaction = evidence_connection.begin()
        try:
            set_scope(evidence_connection)
            evidence_connection.execute(
                text(
                    "INSERT INTO memory_proposal_evidence "
                    "(owner_id,workspace_id,proposal_id,chunk_id) "
                    "VALUES (:owner,:workspace,:proposal,:chunk)"
                ),
                {
                    "owner": member,
                    "workspace": workspace,
                    "proposal": evidence_first,
                    "chunk": chunk_b,
                },
            )
            approval_thread = Thread(target=approve_after_evidence_lock, daemon=True)
            approval_thread.start()
            assert approval_started.wait(1)
            assert not approval_done.wait(0.2)
            evidence_transaction.commit()
            assert approval_done.wait(4)
            approval_thread.join(timeout=1)
            assert not approval_thread.is_alive()
            assert approval_errors == []
        finally:
            if evidence_transaction.is_active:
                evidence_transaction.rollback()
            evidence_connection.close()

        approval_first = uuid4()
        seed_proposal(approval_first)
        evidence_started, evidence_done = Event(), Event()
        evidence_errors: list[BaseException] = []

        def insert_after_approval_lock() -> None:
            try:
                with app_engine.begin() as connection:
                    set_scope(connection)
                    evidence_started.set()
                    connection.execute(
                        text(
                            "INSERT INTO memory_proposal_evidence "
                            "(owner_id,workspace_id,proposal_id,chunk_id) "
                            "VALUES (:owner,:workspace,:proposal,:chunk)"
                        ),
                        {
                            "owner": member,
                            "workspace": workspace,
                            "proposal": approval_first,
                            "chunk": chunk_b,
                        },
                    )
            except BaseException as exc:
                evidence_errors.append(exc)
            finally:
                evidence_done.set()

        approval_connection = app_engine.connect()
        approval_transaction = approval_connection.begin()
        try:
            set_scope(approval_connection)
            approval_connection.execute(
                text(
                    "UPDATE memory_proposals "
                    "SET status='approved',decided_at=clock_timestamp() "
                    "WHERE id=:proposal"
                ),
                {"proposal": approval_first},
            )
            evidence_thread = Thread(target=insert_after_approval_lock, daemon=True)
            evidence_thread.start()
            assert evidence_started.wait(1)
            assert not evidence_done.wait(0.2)
            approval_transaction.commit()
            assert evidence_done.wait(4)
            evidence_thread.join(timeout=1)
            assert not evidence_thread.is_alive()
            assert len(evidence_errors) == 1
            assert isinstance(evidence_errors[0], DBAPIError)
        finally:
            if approval_transaction.is_active:
                approval_transaction.rollback()
            approval_connection.close()

        with app_engine.connect() as connection:
            set_scope(connection)
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM memory_proposal_evidence AS evidence "
                        "JOIN memory_proposals AS proposal ON proposal.id=evidence.proposal_id "
                        "WHERE proposal.status <> 'proposed' "
                        "AND evidence.created_at > proposal.decided_at"
                    )
                )
                == 0
            )
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM memory_proposal_evidence "
                        "WHERE proposal_id=:proposal AND chunk_id=:chunk"
                    ),
                    {"proposal": approval_first, "chunk": chunk_b},
                )
                == 0
            )
    finally:
        app_engine.dispose()
