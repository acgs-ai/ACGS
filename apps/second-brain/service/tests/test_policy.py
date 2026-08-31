from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from second_brain.app import create_app
from second_brain.config import Settings
from second_brain.db import create_session_factory, scoped_session
from second_brain.policy import (
    PolicyContext,
    PolicyDecision,
    PolicyDenied,
    PolicyUnavailable,
    evaluate_policy,
    record_policy_decision,
)


class StubPolicyPort:
    def __init__(self, result: object = None, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.contexts: list[PolicyContext] = []

    def evaluate(self, context: PolicyContext) -> object:
        self.contexts.append(context)
        if self.error is not None:
            raise self.error
        return self.result


def context(*, native_checks: Literal["pass", "fail"] = "pass") -> PolicyContext:
    return PolicyContext(
        request_id=uuid4(),
        action="approve_memory",
        actor_id=uuid4(),
        workspace_id=uuid4(),
        resource_type="memory",
        resource_id=uuid4(),
        memory_category="reference",
        native_checks=native_checks,
        occurred_at=datetime(2026, 8, 27, 12, tzinfo=UTC),
    )


def decision(value: str = "pass", *, obligations: tuple[str, ...] = ()) -> PolicyDecision:
    return PolicyDecision(
        decision=value,
        reason_code="policy.reviewed",
        policy_id="local-policy",
        policy_version="1",
        audit_id="audit-123",
        evaluated_at=datetime(2026, 8, 27, 12, tzinfo=UTC),
        obligations=obligations,
    )


def test_disabled_policy_is_no_additional_veto_but_native_checks_still_deny() -> None:
    port = StubPolicyPort(decision())

    result = evaluate_policy(port, context(), enabled=False)

    assert result.decision == "pass"
    assert result.reason_code == "policy.disabled"
    assert port.contexts == []
    with pytest.raises(PolicyDenied, match="native_checks_failed"):
        evaluate_policy(port, context(native_checks="fail"), enabled=False)


def test_pass_never_overrides_failed_native_checks() -> None:
    port = StubPolicyPort(decision())

    with pytest.raises(PolicyDenied, match="native_checks_failed"):
        evaluate_policy(port, context(native_checks="fail"), enabled=True)

    assert port.contexts == []


@pytest.mark.parametrize("value", ["veto", "unavailable"])
def test_enabled_veto_or_unavailable_is_returned_for_durable_audit(value: str) -> None:
    port = StubPolicyPort(decision(value))

    result = evaluate_policy(port, context(), enabled=True)

    assert result.decision == value


@pytest.mark.parametrize(
    "result",
    [
        object(),
        PolicyDecision(
            decision="pass",
            reason_code="policy.reviewed",
            policy_id=None,
            policy_version="1",
            audit_id="audit-123",
            evaluated_at=datetime(2026, 8, 27, 12, tzinfo=UTC),
        ),
        decision(obligations=("unknown_obligation",)),
        decision(obligations=("record_audit",) * 9),
    ],
)
def test_enabled_malformed_result_or_obligations_fail_closed(result: object) -> None:
    evaluated = evaluate_policy(StubPolicyPort(result), context(), enabled=True)
    assert evaluated.decision == "unavailable"
    assert evaluated.reason_code == "policy.adapter_unavailable"


def test_enabled_adapter_exception_fails_closed_without_exposing_exception() -> None:
    port = StubPolicyPort(error=RuntimeError("seeded-private-source-text"))

    result = evaluate_policy(port, context(), enabled=True)

    assert result.decision == "unavailable"
    assert result.reason_code == "policy.adapter_unavailable"
    assert "seeded-private-source-text" not in str(result)


def test_policy_context_is_metadata_only_and_bounded() -> None:
    assert "content" not in PolicyContext.__dataclass_fields__
    assert "prompt" not in PolicyContext.__dataclass_fields__
    with pytest.raises(ValueError, match="non-negative"):
        PolicyContext(
            request_id=uuid4(),
            action="capture_source",
            actor_id=uuid4(),
            workspace_id=uuid4(),
            resource_type="source",
            native_checks="pass",
            byte_count=-1,
            occurred_at=datetime.now(UTC),
        )


def seed_workspace(admin_url: str, owner_id: UUID, workspace_id: UUID) -> None:
    engine = create_engine(admin_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO users (id,email) VALUES (:id,:email)"),
                {"id": owner_id, "email": f"{owner_id}@example.test"},
            )
            connection.execute(
                text("INSERT INTO workspaces (id,owner_id,name) VALUES (:id,:owner,'policy')"),
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


def test_policy_decisions_are_scoped_append_only_and_obligations_bounded(
    database_urls: Any,
) -> None:
    owner_a, workspace_a, owner_b, workspace_b = uuid4(), uuid4(), uuid4(), uuid4()
    seed_workspace(database_urls.admin, owner_a, workspace_a)
    seed_workspace(database_urls.admin, owner_b, workspace_b)
    app_engine = create_engine(database_urls.app)
    sessions = create_session_factory(app_engine)
    try:
        policy_context = replace(context(), actor_id=owner_a, workspace_id=workspace_a)
        with scoped_session(sessions, owner_a, workspace_a) as session:
            decision_id = record_policy_decision(
                session, policy_context, decision(obligations=("record_audit",))
            )
        with scoped_session(sessions, owner_b, workspace_b) as session:
            assert session.scalar(text("SELECT count(*) FROM policy_decisions")) == 0
        with pytest.raises(DBAPIError), scoped_session(sessions, owner_a, workspace_a) as session:
            session.execute(
                text(
                    "UPDATE policy_decisions SET reason_code='policy.changed' WHERE id=:decision_id"
                ),
                {"decision_id": decision_id},
            )
        with pytest.raises(DBAPIError), scoped_session(sessions, owner_a, workspace_a) as session:
            session.execute(
                text("DELETE FROM policy_decisions WHERE id=:decision_id"),
                {"decision_id": decision_id},
            )
        with (
            pytest.raises(PolicyUnavailable),
            scoped_session(sessions, owner_a, workspace_a) as session,
        ):
            record_policy_decision(
                session,
                replace(policy_context, request_id=uuid4()),
                decision(obligations=("unknown_obligation",)),
            )
    finally:
        app_engine.dispose()


async def test_enabled_policy_capture_routes_veto_and_unavailable_fail_closed(
    database_urls: Any, tmp_path: Path
) -> None:
    owner, workspace = uuid4(), uuid4()
    seed_workspace(database_urls.admin, owner, workspace)
    settings = Settings(
        app_env="test",
        database_url=database_urls.app,
        storage_root=tmp_path / "objects",
        policy_enabled=True,
    )
    headers = {
        "x-second-brain-owner-id": str(owner),
        "x-second-brain-workspace-id": str(workspace),
    }

    pass_port = StubPolicyPort(decision())
    pass_app = create_app(settings, policy_port=pass_port)
    async with AsyncClient(
        transport=ASGITransport(app=pass_app, client=("127.0.0.1", 40300)),
        base_url="http://127.0.0.1",
    ) as client:
        missing = await client.post(
            "/api/v1/captures/text",
            headers=headers,
            json={
                "title": "Native check",
                "content": "Policy cannot grant visibility.",
                "project_id": str(uuid4()),
            },
        )
        assert missing.status_code == 404 and pass_port.contexts == []

    for value, expected in (("veto", 403), ("unavailable", 503)):
        port = StubPolicyPort(decision(value))
        application = create_app(settings, policy_port=port)
        async with AsyncClient(
            transport=ASGITransport(app=application, client=("127.0.0.1", 40301)),
            base_url="http://127.0.0.1",
        ) as client:
            response = await client.post(
                "/api/v1/captures/text",
                headers=headers,
                json={"title": value, "content": "private route payload"},
            )
        assert response.status_code == expected
        assert [item.action for item in port.contexts] == ["capture_source"]

    exception_port = StubPolicyPort(error=RuntimeError("private route payload"))
    exception_app = create_app(settings, policy_port=exception_port)
    async with AsyncClient(
        transport=ASGITransport(app=exception_app, client=("127.0.0.1", 40303)),
        base_url="http://127.0.0.1",
    ) as client:
        unavailable = await client.post(
            "/api/v1/captures/text",
            headers=headers,
            json={"title": "exception", "content": "private route payload"},
        )
    assert unavailable.status_code == 503

    async with AsyncClient(
        transport=ASGITransport(app=pass_app, client=("127.0.0.1", 40302)),
        base_url="http://127.0.0.1",
    ) as client:
        allowed = await client.post(
            "/api/v1/captures/text",
            headers=headers,
            json={"title": "Allowed", "content": "metadata-only policy pass"},
        )
    assert allowed.status_code == 202
    assert [item.action for item in pass_port.contexts] == ["capture_source"]

    engine = create_engine(database_urls.admin)
    try:
        with engine.connect() as connection:
            parameters = {"owner": owner, "workspace": workspace}
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM sources "
                        "WHERE owner_id=:owner AND workspace_id=:workspace"
                    ),
                    parameters,
                )
                == 1
            )
            assert (
                connection.scalar(
                    text(
                        "SELECT count(*) FROM policy_decisions "
                        "WHERE owner_id=:owner AND workspace_id=:workspace"
                    ),
                    parameters,
                )
                == 4
            )
    finally:
        engine.dispose()
