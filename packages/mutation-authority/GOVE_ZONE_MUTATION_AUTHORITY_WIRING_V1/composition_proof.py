#!/usr/bin/env python3
"""Adversarial proof of the two-receipt composition BINDING LOGIC.

SCOPE: this proves the composition rule in `mutation_authority.composition`
is sound on a gove-zone DOUBLE (`GovernedActionClaim`). It does NOT prove
gove-zone routes its executor through this rule — that wiring is blocked
(collision) and reported INTEGRATION INCOMPLETE. A green run here means "the
binding design is correct and ready to wire", NOT "the invariant is enforced".

Every case asserts repository state before AND after, per the task's rule that
attacks assert state, not return codes.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mutation_authority.adapters import AuthorityContext
from mutation_authority.composition import (
    GovernedActionClaim,
    compose_mutation,
    composed_evidence_fields,
)
from mutation_authority.integration_verification import IntegrationSandbox

RESOURCE = "src/module_a.py"
EFFECT_ID = "TASK-effect-1"  # matches POLICY task_authorities "TASK-*"


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str


def _ctx(sb: IntegrationSandbox, actor: str, task: str) -> AuthorityContext:
    return AuthorityContext(
        actor_id=actor, actor_key=sb.kernel.root.actor_key(actor), task_reference=task
    )


def _claim(**over) -> GovernedActionClaim:
    base = dict(
        effect_id=EFFECT_ID,
        actor="agent-alpha",
        action_kind="PreToolUse",
        classified_command="write src/module_a.py",
        target_resource=RESOURCE,
        decision="allow",
    )
    base.update(over)
    return GovernedActionClaim(**base)


def _expect(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def check_happy(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    before = (sb.kernel.repo / RESOURCE).read_bytes()
    res = compose_mutation(
        _claim(), sb.gateway, _ctx(sb, "agent-alpha", EFFECT_ID), RESOURCE, "UPDATE", b"VALUE = 2\n"
    )
    _expect(res.status == "APPLIED", f"expected APPLIED, got {res.status}: {res.reason}")
    _expect((sb.kernel.repo / RESOURCE).read_bytes() == b"VALUE = 2\n", "content not applied")
    fields = composed_evidence_fields(_claim(), res)
    _expect(fields["gove_zone_effect_id"] == EFFECT_ID, "effect_id not bound in evidence")
    _expect(fields["mutation_receipt_id"] and fields["mutation_evidence_id"], "missing ids")
    _expect(before != b"VALUE = 2\n", "test setup: content already equal")
    return "both legs authorize ⇒ APPLIED; evidence carries effect_id + receipt id"


def check_deny_launder(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    before = (sb.kernel.repo / RESOURCE).read_bytes()
    res = compose_mutation(
        _claim(decision="deny"),
        sb.gateway,
        _ctx(sb, "agent-alpha", EFFECT_ID),
        RESOURCE,
        "UPDATE",
        b"pwn\n",
    )
    _expect(res.status == "REFUSED", f"DENY laundered: {res.status}")
    _expect((sb.kernel.repo / RESOURCE).read_bytes() == before, "DENY produced a state change")
    _expect(sb.evidence.records() == [], "DENY emitted evidence")
    # No mutation DECISION/COMMIT was appended (gateway never reached).
    kinds = [e.type for e in sb.kernel.ledger.events()]
    _expect(kinds.count("DECISION") == 0 and kinds.count("COMMIT") == 0, "gateway was reached")
    return "gove-zone DENY ⇒ REFUSED before gateway; zero state change, zero evidence"


def check_ask_launder(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    before = (sb.kernel.repo / RESOURCE).read_bytes()
    res = compose_mutation(
        _claim(decision="ask"),
        sb.gateway,
        _ctx(sb, "agent-alpha", EFFECT_ID),
        RESOURCE,
        "UPDATE",
        b"pwn\n",
    )
    _expect(res.status == "REFUSED", f"ASK laundered: {res.status}")
    _expect((sb.kernel.repo / RESOURCE).read_bytes() == before, "ASK produced a state change")
    return "gove-zone ASK (non-ALLOW) ⇒ REFUSED; zero state change"


def check_receipt_cross_binding(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    before = (sb.kernel.repo / RESOURCE).read_bytes()
    # Action authorized under effect A, but the mutation context is pinned to a
    # DIFFERENT task_reference — the binding must break.
    res = compose_mutation(
        _claim(effect_id="TASK-effect-A"),
        sb.gateway,
        _ctx(sb, "agent-alpha", "TASK-effect-B"),
        RESOURCE,
        "UPDATE",
        b"pwn\n",
    )
    _expect(res.status == "REFUSED", f"cross-binding allowed: {res.status}")
    _expect("binding broken" in res.reason, res.reason)
    _expect((sb.kernel.repo / RESOURCE).read_bytes() == before, "cross-binding changed state")
    return "mutation receipt for effect A cannot satisfy action B ⇒ REFUSED"


def check_target_substitution(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    other = "src/verify_readiness.py"
    before = (sb.kernel.repo / other).read_bytes()
    # Action authorizes module_a; attempt to write verify_readiness.py.
    res = compose_mutation(
        _claim(target_resource=RESOURCE),
        sb.gateway,
        _ctx(sb, "agent-alpha", EFFECT_ID),
        other,
        "UPDATE",
        b"pwn\n",
    )
    _expect(res.status == "REFUSED", f"target substitution allowed: {res.status}")
    _expect("target mismatch" in res.reason, res.reason)
    _expect((sb.kernel.repo / other).read_bytes() == before, "target substitution changed B")
    return "ALLOW for path A cannot authorize writing path B ⇒ REFUSED"


def check_actor_substitution(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    before = (sb.kernel.repo / RESOURCE).read_bytes()
    # Action authorized for alpha; beta presents the mutation.
    res = compose_mutation(
        _claim(actor="agent-alpha"),
        sb.gateway,
        _ctx(sb, "agent-beta", EFFECT_ID),
        RESOURCE,
        "UPDATE",
        b"pwn\n",
    )
    _expect(res.status == "REFUSED", f"actor substitution allowed: {res.status}")
    _expect("actor mismatch" in res.reason, res.reason)
    _expect((sb.kernel.repo / RESOURCE).read_bytes() == before, "actor substitution changed state")
    return "action authorized for alpha cannot be carried by beta ⇒ REFUSED"


def check_ordering_is_structural(base: Path) -> str:
    # The effect cannot precede the gove-zone decision: compose_mutation takes
    # the action claim as a required precondition argument and only reaches the
    # gateway (the sole effect path) after all binding checks. There is no code
    # path in composition.py that calls request_mutation before evaluating the
    # action claim. This check documents+asserts that invariant by construction:
    import inspect

    from mutation_authority import composition

    src = inspect.getsource(composition.compose_mutation)
    gate_pos = src.index("gateway.request_mutation")
    allow_pos = src.index('action.decision != "allow"')
    _expect(allow_pos < gate_pos, "ordering inverted: gateway reached before ALLOW check")
    return "ordering is structural: ALLOW check precedes the only effect call"


CHECKS = [
    ("happy path: both legs authorize", check_happy),
    ("gove-zone DENY cannot launder a mutation", check_deny_launder),
    ("gove-zone ASK cannot launder a mutation", check_ask_launder),
    ("mutation receipt cannot cross-bind to another action", check_receipt_cross_binding),
    ("action cannot authorize a substituted target", check_target_substitution),
    ("action cannot be carried by a substituted actor", check_actor_substitution),
    ("effect cannot precede the gove-zone decision (ordering)", check_ordering_is_structural),
]


def run(work_dir: Path) -> list[CheckResult]:
    out: list[CheckResult] = []
    for i, (name, fn) in enumerate(CHECKS):
        try:
            out.append(CheckResult(name, True, fn(work_dir / f"c{i:02d}")))
        except Exception as exc:
            out.append(CheckResult(name, False, f"{type(exc).__name__}: {exc}"))
    return out


def main() -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="composition-proof-") as tmp:
        results = run(Path(tmp))
    width = max(len(r.name) for r in results)
    failures = 0
    for r in results:
        print(f"[{'PASS' if r.passed else 'FAIL'}] {r.name.ljust(width)}  {r.detail}")
        failures += 0 if r.passed else 1
    print()
    print(
        "composition binding proven on a gove-zone DOUBLE — this is design-proof, "
        "NOT enforcement (gove-zone wiring blocked; see REPORT.md)"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
