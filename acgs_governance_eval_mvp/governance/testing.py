from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from governance.adapters.tools import GovernedToolAdapter
from governance.audit.in_memory import InMemoryAuditStore
from governance.policy_loader import load_policy_bundle, load_roles


_PACKAGE_ROOT = Path(__file__).resolve().parent
_DEFAULT_ROLES_PATH = _PACKAGE_ROOT / "roles.json"
_DEFAULT_POLICY_DIR = _PACKAGE_ROOT / "policies" / "2026-05"


def make_request(
    *,
    role: str = "LegalOps",
    action_type: str = "contract.redline",
    resource: str = "contracts/test",
    tool_input: dict[str, Any] | None = None,
    actor_id: str = "agent-test-1",
    intent: str = "test request",
    metadata: dict[str, Any] | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    """Build an ActionRequest dict ready for adapter.validate / adapter.guard.

    Defaults to a payload that the bundled roles + policies allow (LegalOps
    doing contract.redline with the right policy_citations metadata), so
    happy-path tests don't need to assemble metadata themselves. Pass
    overrides to flip into a deny path or change individual fields.
    """
    if metadata is None:
        metadata = {"policy_citations": ["CONTRACT-AUTHORITY-001"]}
    if tool_input is None:
        tool_input = {"path": f"{resource}.txt", "redactions": []}
    payload: dict[str, Any] = {
        "actor": {"id": actor_id, "role": role},
        "intent": intent,
        "action_type": action_type,
        "resource": resource,
        "metadata": metadata,
        "tool_input": tool_input,
    }
    payload.update(overrides)
    return payload


@contextmanager
def governance_test_harness(
    *,
    roles_path: str | Path | None = None,
    policy_path: str | Path | None = None,
) -> Iterator[GovernedToolAdapter]:
    """Yield a GovernedToolAdapter wired to an InMemoryAuditStore.

    Loads the bundled roles + policies from this package by default, so
    callers can exercise real decision logic without touching disk for audit
    events or supplying their own fixtures. Override roles_path / policy_path
    for tests that need a different bundle.

    The wired audit_store is reachable via adapter.audit_store for assertions
    on what events were recorded.
    """
    roles_bundle = load_roles(roles_path or _DEFAULT_ROLES_PATH)
    policy_bundle = load_policy_bundle(policy_path or _DEFAULT_POLICY_DIR)
    audit_store = InMemoryAuditStore()
    yield GovernedToolAdapter(
        roles_bundle=roles_bundle,
        policy_bundle=policy_bundle,
        audit_store=audit_store,
    )
