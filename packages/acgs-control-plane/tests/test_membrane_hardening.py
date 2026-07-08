"""Regression tests for the review findings: genesis atomicity, execution-
failure receipt parity, and anchor monotonicity under stale writers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from gove_zone.decision import Decision
from gove_zone.policy import PolicyRule, RuleSetPolicy
from sqlalchemy import select

import acgs_control_plane.governance as governance
from acgs_control_plane.auth import Principal
from acgs_control_plane.db import Base, make_engine, make_session_factory
from acgs_control_plane.governance import GovernanceMembrane, _anchor, chain_tip
from acgs_control_plane.models import Organization, ReceiptRow, User
from acgs_control_plane.rbac import Role


@pytest.fixture()
def db_session(tmp_path: Path):
    engine = make_engine(f"sqlite:///{tmp_path / 'unit.sqlite3'}")
    Base.metadata.create_all(engine)
    session = make_session_factory(engine)()
    yield session
    session.close()


@pytest.fixture()
def org_row(db_session) -> Organization:
    org = Organization(name="Unit Org")
    db_session.add(org)
    db_session.commit()
    return org


def _principal(org_id: str) -> Principal:
    return Principal(user_id="u1", org_id=org_id, name="unit", role=Role.ORG_ADMIN)


def test_blocked_genesis_leaves_no_rows(
    client: TestClient, bootstrap_headers: dict[str, str], monkeypatch: Any
) -> None:
    """A denied org.create must roll back org + admin and dangle no receipt FK."""
    deny_genesis = RuleSetPolicy(
        policy_id="test-deny-genesis/v1",
        rules=(
            PolicyRule(
                rule_id="no-new-orgs",
                effect=Decision.DENY,
                tools=frozenset({"org.create"}),
                reason="org onboarding is frozen",
            ),
        ),
    )
    monkeypatch.setattr(governance, "baseline_policy", lambda: deny_genesis)
    body = {"name": "Frozen Org", "admin_name": "A", "admin_email": "a@frozen.example.com"}
    resp = client.post("/orgs", json=body, headers=bootstrap_headers)
    assert resp.status_code == 403
    assert resp.json()["decision"] == "deny"

    # Nothing persisted: the same name bootstraps cleanly once the freeze lifts.
    monkeypatch.undo()
    resp = client.post("/orgs", json=body, headers=bootstrap_headers)
    assert resp.status_code == 201, resp.text


def test_execution_failure_is_receipted(db_session, org_row: Organization, tmp_path: Path) -> None:
    """Post-ALLOW tool exceptions must appear in the queryable receipts store."""
    membrane = GovernanceMembrane(
        db_session, tmp_path / "audit", org_row.id, _principal(org_row.id)
    )

    def _boom() -> None:
        raise RuntimeError("mid-flight explosion")

    with pytest.raises(RuntimeError):
        membrane.run("thing.explode", {}, _boom, goal="unit failure")

    rows = (
        db_session.execute(select(ReceiptRow).where(ReceiptRow.org_id == org_row.id))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    row = rows[0]
    assert row.id.endswith(":failure")
    assert row.decision == "deny"
    assert row.error_class == "RuntimeError"
    # Anchor covers both chain events (allow + synthesized failure).
    count, last = chain_tip(membrane.store)
    assert count == 2
    db_session.refresh(org_row)
    assert org_row.audit_anchor_count == 2
    assert org_row.audit_anchor_hash == last
    # And no side-effect rows leaked from the failed mutation.
    assert db_session.execute(select(User).where(User.org_id == org_row.id)).scalars().all() == []


def test_anchor_never_regresses(db_session, org_row: Organization, tmp_path: Path) -> None:
    """A stale writer (older chain tip) must not roll the anchor backwards."""
    membrane = GovernanceMembrane(
        db_session, tmp_path / "audit", org_row.id, _principal(org_row.id)
    )
    membrane.run("noop.one", {}, lambda: "ok")
    membrane.run("noop.two", {}, lambda: "ok")
    db_session.refresh(org_row)
    assert org_row.audit_anchor_count == 2
    true_hash = org_row.audit_anchor_hash

    class StaleStore:
        """Simulates a request that read the chain before the second append."""

        def iter_events(self):
            yield from list(membrane.store.iter_events())[:1]

    _anchor(db_session, org_row.id, StaleStore())  # type: ignore[arg-type]
    db_session.commit()
    db_session.refresh(org_row)
    assert org_row.audit_anchor_count == 2
    assert org_row.audit_anchor_hash == true_hash
