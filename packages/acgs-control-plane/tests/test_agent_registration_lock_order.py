"""Source-order contract for agent-registration lock and mirror effects.

The concurrent PostgreSQL deadlock (environments FOR UPDATE vs audit-chain
anchor) and phantom JSONL append (mirror before a still-abortable flush)
only reproduce on PostgreSQL under load. SQLite treats FOR UPDATE as a no-op,
so this test pins the ordering in `register()` itself.
"""

from __future__ import annotations

import inspect

from acgs_control_plane.agent_registration import AgentRegistrationService


def test_register_locks_org_anchor_before_policy_revalidation() -> None:
    source = inspect.getsource(AgentRegistrationService.register)
    before = source[source.index("def before_execute") : source.index("uow.execute(")]
    after = source[source.index("def after_success") : source.index("def before_execute")]
    assert before.index(
        "tx_session.get(Organization, org_id, with_for_update=True)"
    ) < before.index("_revalidate_active_policy_under_lock(")
    assert after.index("session.flush()") < after.index("mirror_managed_decision(")
