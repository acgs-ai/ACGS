"""Integration verification: MUTATION_AUTHORITY_INTEGRATION_V1 attack suite.

Covers the integrated mutation path (runtime adapter -> engine -> receipt
-> effect -> evidence -> CI gate) with adversarial checks A-G, plus a
compatibility check that re-runs the full kernel suite. Fresh sandbox per
check; logical clock; deterministic.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .adapters import AuthorityContext, MutationGateway
from .ci_gate import run_ci_gate
from .effect import ACCEPTED, REJECTED
from .evidence_emitter import EvidenceEmitter
from .ledger import LedgerIntegrityError
from .receipt import MutationDecisionReceipt
from .verification import CheckFailure, CheckResult, Sandbox, _expect
from .verification import run_all_checks as run_kernel_checks

APPLIED = "APPLIED"
DENIED = "DENIED"
GW_REJECTED = "REJECTED"


@dataclass
class IntegrationSandbox:
    kernel: Sandbox
    evidence: EvidenceEmitter
    gateway: MutationGateway

    @classmethod
    def build(cls, base: Path) -> IntegrationSandbox:
        kernel = Sandbox.build(base)
        evidence = EvidenceEmitter(base / "evidence_graph.jsonl")
        gateway = MutationGateway(kernel.root, kernel.ledger, kernel.repo, evidence)
        return cls(kernel=kernel, evidence=evidence, gateway=gateway)

    def ctx(self, actor: str, task: str = "TASK-1") -> AuthorityContext:
        return AuthorityContext(
            actor_id=actor,
            actor_key=self.kernel.root.actor_key(actor),
            task_reference=task,
        )

    def gate(self):
        return run_ci_gate(self.kernel.root, self.kernel.ledger, self.kernel.repo, self.evidence)


# ---------------------------------------------------------------------------
# Structural checks
# ---------------------------------------------------------------------------


def check_integrated_happy_path(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    resource = "src/verify_readiness.py"
    result = sb.gateway.request_mutation(
        sb.ctx("agent-alpha"), resource, "UPDATE", b"print('readiness v2')\n"
    )
    _expect(result.status == APPLIED, f"{result.status}: {result.reason}")
    _expect(result.receipt is not None and result.evidence_id is not None, "missing refs")
    records = sb.evidence.records()
    _expect(len(records) == 1, "expected exactly one evidence record")
    record = records[0]
    for key in (
        "actor",
        "resource",
        "previous_hash",
        "new_hash",
        "decision",
        "receipt_id",
        "policy_version",
        "authority_chain_ref",
    ):
        _expect(key in record, f"evidence record missing {key}")
    gate = sb.gate()
    _expect(gate.passed, f"CI gate failed on clean state: {gate.failures}")
    return "APPLIED with receipt + evidence; CI gate green"


def check_deterministic_gateway(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    first = sb.gateway.request_mutation(sb.ctx("agent-gamma"), "src/module_a.py", "UPDATE", b"x\n")
    second = sb.gateway.request_mutation(sb.ctx("agent-gamma"), "src/module_a.py", "UPDATE", b"x\n")
    _expect(first.status == second.status == DENIED, "expected DENY both times")
    _expect(first.reason == second.reason, "same request, different reasons")
    _expect(sb.evidence.records() == [], "denied request emitted evidence")
    return "identical request ⇒ identical verdict; denials emit no evidence"


def check_kernel_suite_compatibility(base: Path) -> str:
    results = run_kernel_checks(base / "kernel")
    failed = [r.name for r in results if not r.passed]
    _expect(not failed, f"kernel checks regressed: {failed}")
    return f"kernel suite still green ({len(results)}/{len(results)})"


# ---------------------------------------------------------------------------
# Attack suite A-G (integration boundary)
# ---------------------------------------------------------------------------


def attack_a_direct_filesystem_bypass(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    (sb.kernel.repo / "src/verify_readiness.py").write_bytes(b"rogue\n")
    gate = sb.gate()
    _expect(not gate.passed, "CI gate passed over an unauthorized mutation")
    _expect(any("unauthorized mutation" in f for f in gate.failures), str(gate.failures))
    result = sb.gateway.request_mutation(
        sb.ctx("agent-alpha"), "src/verify_readiness.py", "UPDATE", b"v2\n"
    )
    _expect(result.status == DENIED, "gateway allowed a laundering mutation")
    _expect("diverged" in result.reason, result.reason)
    return "gate FAIL (attributed to resource); laundering request DENIED"


def attack_b_fake_receipt(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    applied = sb.gateway.request_mutation(
        sb.ctx("agent-alpha"), "src/module_a.py", "UPDATE", b"VALUE = 2\n"
    )
    assert applied.receipt is not None
    forged = MutationDecisionReceipt.from_dict(
        {**applied.receipt.to_dict(), "resource": "src/verify_readiness.py"}
    )
    result = sb.gateway.binder.commit(forged, b"pwn\n", 99)
    _expect(result.status == REJECTED, "forged receipt accepted")
    _expect("signature invalid" in result.reason, result.reason)

    # Fabricated evidence with no backing COMMIT event.
    fake = dict(sb.evidence.records()[0])
    fake["receipt_id"] = "0" * 64
    body = {k: v for k, v in fake.items() if k != "evidence_id"}
    from .canonical import hash_obj

    fake["evidence_id"] = hash_obj(body)
    with sb.evidence.path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(fake, sort_keys=True) + "\n")
    gate = sb.gate()
    _expect(not gate.passed, "gate accepted fabricated evidence")
    # The forged record carries a receipt_id with no COMMIT and no valid
    # root-key signature; either rejection (signature or fabricated) is a
    # correct fail — signature is the stronger, earlier catch.
    _expect(
        any(("fabricated evidence" in f or "signature" in f) for f in gate.failures),
        str(gate.failures),
    )
    return "forged receipt REJECTED; unsigned/fabricated evidence fails the gate"


def attack_c_receipt_reuse(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    applied = sb.gateway.request_mutation(
        sb.ctx("agent-alpha"), "src/module_a.py", "UPDATE", b"VALUE = 2\n"
    )
    assert applied.receipt is not None
    replay = sb.gateway.binder.commit(applied.receipt, b"VALUE = 666\n", 99)
    _expect(replay.status == REJECTED, "receipt reuse accepted")
    _expect("already consumed" in replay.reason, replay.reason)
    _expect(
        (sb.kernel.repo / "src/module_a.py").read_bytes() == b"VALUE = 2\n",
        "replay changed the file",
    )
    _expect(sb.gate().passed, "gate failed after correctly-rejected replay")
    return "consumed receipt reuse REJECTED; state and gate unaffected"


def attack_d_actor_scope_escalation(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    # (1) Actor requests a resource outside its registered scope.
    out_of_scope = sb.gateway.request_mutation(
        sb.ctx("agent-gamma"), "src/verify_readiness.py", "UPDATE", b"v2\n"
    )
    _expect(out_of_scope.status == DENIED, "out-of-scope request allowed")
    _expect("scope does not permit" in out_of_scope.reason, out_of_scope.reason)
    # (2) Impersonation: claim alpha's identity with gamma's key.
    stolen = AuthorityContext(
        actor_id="agent-alpha",
        actor_key=sb.kernel.root.actor_key("agent-gamma"),
        task_reference="TASK-1",
    )
    impersonation = sb.gateway.request_mutation(
        stolen, "src/verify_readiness.py", "UPDATE", b"v2\n"
    )
    _expect(impersonation.status == DENIED, "impersonation allowed")
    _expect("signature invalid" in impersonation.reason, impersonation.reason)
    return "out-of-scope DENIED; cross-actor key impersonation DENIED"


def attack_e_ledger_rollback(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    sb.gateway.request_mutation(sb.ctx("agent-alpha"), "src/module_a.py", "UPDATE", b"VALUE = 2\n")
    lines = sb.kernel.ledger.path.read_text().splitlines()
    sb.kernel.ledger.path.write_text("\n".join(lines[:-1]) + "\n")
    gate = sb.gate()
    _expect(not gate.passed, "gate passed over a rolled-back ledger")
    _expect(any("anchor" in f for f in gate.failures), str(gate.failures))
    try:
        sb.gateway.request_mutation(
            sb.ctx("agent-alpha"), "src/module_a.py", "UPDATE", b"VALUE = 3\n"
        )
    except LedgerIntegrityError:
        return "rollback DETECTED by gate; gateway fails closed on the rolled-back chain"
    raise CheckFailure("gateway kept operating on a rolled-back ledger")


def attack_f_evidence_removed(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    sb.gateway.request_mutation(sb.ctx("agent-alpha"), "src/module_a.py", "UPDATE", b"VALUE = 2\n")
    _expect(sb.gate().passed, "gate not green before evidence removal")
    sb.evidence.path.write_text("")  # attacker strips the evidence graph
    gate = sb.gate()
    _expect(not gate.passed, "silent mutation went undetected")
    _expect(any("silent mutation" in f for f in gate.failures), str(gate.failures))
    return "stripped evidence ⇒ gate FAIL: silent mutation named per COMMIT"


def attack_g_adapter_bypass(base: Path) -> str:
    sb = IntegrationSandbox.build(base)
    # (1) No authority context at all.
    no_ctx = sb.gateway.request_mutation(None, "src/module_a.py", "UPDATE", b"x\n")
    _expect(no_ctx.status == GW_REJECTED, "missing context accepted")
    _expect("missing authority context" in no_ctx.reason, no_ctx.reason)
    # (2) Context that does not resolve to a registered actor.
    ghost = AuthorityContext(
        actor_id="agent-ghost", actor_key=b"\x00" * 32, task_reference="TASK-1"
    )
    unresolved = sb.gateway.request_mutation(ghost, "src/module_a.py", "UPDATE", b"x\n")
    _expect(unresolved.status == GW_REJECTED, "unregistered actor accepted")
    # (3) Incomplete context (no task authority).
    incomplete = AuthorityContext(
        actor_id="agent-alpha",
        actor_key=sb.kernel.root.actor_key("agent-alpha"),
        task_reference="",
    )
    no_task = sb.gateway.request_mutation(incomplete, "src/module_a.py", "UPDATE", b"x\n")
    _expect(no_task.status == GW_REJECTED, "context without task authority accepted")
    # (4) Skipping the adapter: direct EffectBinder call with an unissued receipt.
    decision = sb.kernel.engine.decide(
        sb.kernel.intent("agent-alpha", "src/module_a.py"), sb.kernel.tick()
    )
    assert decision.receipt is not None
    unissued = MutationDecisionReceipt.from_dict(
        {**decision.receipt.to_dict(), "receipt_id": "f" * 64}
    )
    direct = sb.gateway.binder.commit(unissued, b"x\n", sb.kernel.tick())
    _expect(direct.status == REJECTED, "unissued receipt accepted by binder")
    _expect(sb.evidence.records() == [], "bypass attempts emitted evidence")
    return "no/unresolved/incomplete context REJECTED; binder demands issued receipt"


def attack_h_clock_skew_dos(base: Path) -> str:
    """Uncredentialed caller injects a huge timestamp to expire live receipts."""
    sb = IntegrationSandbox.build(base)
    # A legitimate agent takes out a live receipt (issued, unconsumed).
    decision = sb.kernel.engine.decide(
        sb.kernel.intent("agent-beta", "src/module_a.py"), sb.gateway._next_tick()
    )
    _expect(decision.decision == "ALLOW" and decision.receipt is not None, "setup failed")
    assert decision.receipt is not None
    open_before = sb.kernel.ledger.open_receipts_for("src/module_a.py", sb.gateway._next_tick())
    _expect(len(open_before) == 1, "beta receipt should be live")

    # Attacker calls decide() directly with a giant now. Even a guaranteed
    # DENY (here: agent-gamma, out of scope on src/*) appends a DECISION
    # event carrying that attacker-chosen timestamp.
    bogus = sb.kernel.intent("agent-gamma", "src/module_a.py")
    denied = sb.kernel.engine.decide(bogus, 999_999_999)
    _expect(denied.decision == "DENY", "setup expected a DENY")

    # Gateway clock must NOT have leapt forward; beta's receipt still live.
    tick = sb.gateway._next_tick()
    _expect(tick < 1000, f"clock skewed to {tick} by unauthenticated event")
    still_open = sb.kernel.ledger.open_receipts_for("src/module_a.py", tick)
    _expect(len(still_open) == 1, "victim receipt was expired by clock-skew DoS")
    result = sb.gateway.binder.commit(decision.receipt, b"VALUE = 2\n", sb.gateway._next_tick())
    _expect(result.status == ACCEPTED, f"victim commit failed after skew attempt: {result.reason}")
    return "count-based clock immune to injected timestamps; victim receipt survives"


def attack_i_evidence_forgery(base: Path) -> str:
    """Forge a self-consistent evidence record without the root key."""
    sb = IntegrationSandbox.build(base)
    sb.gateway.request_mutation(sb.ctx("agent-alpha"), "src/module_a.py", "UPDATE", b"VALUE = 2\n")
    _expect(sb.gate().passed, "gate not green pre-attack")
    commit = next(e for e in sb.kernel.ledger.events() if e.type == "COMMIT")
    # Attacker rebuilds a record from public ledger data with forged fields,
    # signs the content hash (no root key) — exactly the prior CRITICAL repro.
    from .canonical import hash_obj

    forged_body = {
        "actor": commit.payload["actor"],
        "resource": commit.payload["resource"],
        "previous_hash": commit.payload["before_hash"],
        "new_hash": commit.payload["after_hash"],
        "decision": "OVERRIDDEN",
        "receipt_id": commit.payload["receipt_id"],
        "policy_version": "0" * 64,
        "authority_chain_ref": {
            "ledger_seq": commit.seq,
            "ledger_event_hash": commit.event_hash,
        },
        "timestamp": commit.timestamp,
    }
    forged = {**forged_body, "evidence_id": hash_obj(forged_body), "signature": "deadbeef"}
    # (a) forged duplicate appended alongside the genuine record.
    with sb.evidence.path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(forged, sort_keys=True) + "\n")
    gate = sb.gate()
    _expect(not gate.passed, "gate accepted a forged evidence record")
    _expect(
        any("signature" in f or "duplicate" in f for f in gate.failures),
        str(gate.failures),
    )
    return "forged record fails root-key signature; duplicate shadowing blocked"


def attack_j_gate_exception_safe(base: Path) -> str:
    """Malformed evidence / ledger payload must FAIL the gate, not raise."""
    sb = IntegrationSandbox.build(base)
    sb.gateway.request_mutation(sb.ctx("agent-alpha"), "src/module_a.py", "UPDATE", b"VALUE = 2\n")
    # (1) Corrupt evidence line (invalid JSON).
    with sb.evidence.path.open("a", encoding="utf-8") as fh:
        fh.write("{ not json\n")
    gate = sb.gate()
    _expect(not gate.passed, "malformed evidence line did not fail the gate")
    _expect(any("fail closed" in f for f in gate.failures), str(gate.failures))
    # (2) Schema-violating COMMIT payload appended straight to the ledger.
    sb2 = IntegrationSandbox.build(base / "b")
    sb2.kernel.ledger.append("COMMIT", {"receipt_id": "x", "actor": "a", "resource": "r"}, 5)
    gate2 = sb2.gate()
    _expect(not gate2.passed, "malformed COMMIT payload did not fail the gate")
    return "malformed evidence and ledger payloads both fail closed (no raw raise)"


def attack_k_gateway_path_escape(base: Path) -> str:
    """Absolute/traversal resource paths are rejected BEFORE the gateway
    touches the filesystem: no pre-state hash of files outside the repo,
    no intent, no ledger event, no effect."""
    sb = IntegrationSandbox.build(base)
    outside = base / "outside.txt"
    outside.write_text("untouchable", encoding="utf-8")
    before_events = sum(1 for _ in sb.kernel.ledger.events())
    for path in ("../outside.txt", "/etc/hostname", "src/../../outside.txt", ""):
        res = sb.gateway.request_mutation(sb.ctx("agent-alpha"), path, "UPDATE", b"pwn")
        _expect(res.status == GW_REJECTED, f"escaping path {path!r} not rejected: {res.status}")
        _expect(res.receipt is None, f"escaping path {path!r} produced a receipt")
    _expect(
        sum(1 for _ in sb.kernel.ledger.events()) == before_events,
        "path-escape rejection appended ledger events",
    )
    _expect(outside.read_text(encoding="utf-8") == "untouchable", "outside file was mutated")
    return "absolute/traversal paths rejected before any read; zero events, zero effects"


def attack_m_commit_post_state_laundering(base: Path) -> str:
    """A chain-valid COMMIT referencing a legitimately issued receipt but
    recording a DIFFERENT after_hash (arbitrary bytes written in-process,
    evidence then 'recovered') must fail the gate on the receipt binding:
    the receipt authorized exactly one post-state."""
    sb = IntegrationSandbox.build(base)
    decision = sb.kernel.engine.decide(
        sb.kernel.intent("agent-alpha", "src/module_a.py"), sb.kernel.tick()
    )
    _expect(decision.decision == "ALLOW" and decision.receipt is not None, "setup failed")
    receipt = decision.receipt
    assert receipt is not None
    from .canonical import sha256_hex

    malicious = b"MALICIOUS = 666\n"
    _expect(sha256_hex(malicious) != receipt.expected_state_hash, "fixture must differ")
    (sb.kernel.repo / "src/module_a.py").write_bytes(malicious)
    sb.kernel.ledger.append(
        "COMMIT",
        {
            "receipt_id": receipt.receipt_id,
            "actor": receipt.actor,
            "resource": receipt.resource,
            "before_hash": receipt.previous_state_hash,
            "after_hash": sha256_hex(malicious),
            "decision": "ALLOW",
        },
        sb.kernel.tick(),
    )
    sb.evidence.recover_missing(sb.kernel.root, sb.kernel.ledger)
    gate = sb.gate()
    _expect(not gate.passed, "gate laundered unauthorized bytes under a real receipt")
    _expect(
        any("does not match its receipt's binding" in f for f in gate.failures),
        str(gate.failures),
    )
    return "COMMIT post-state must equal the receipt's expected_state_hash; gate FAIL"


def attack_l_malformed_evidence_projection(base: Path) -> str:
    """A corrupt evidence_graph.jsonl must block the mutation BEFORE the
    effect (fail closed, side effect did not run) instead of surfacing as an
    uncaught JSONDecodeError after the effect is already durable."""
    sb = IntegrationSandbox.build(base)
    sb.gateway.request_mutation(sb.ctx("agent-alpha"), "src/module_a.py", "UPDATE", b"VALUE = 2\n")
    sb.evidence.path.write_text("{ not json\n", encoding="utf-8")
    target = sb.kernel.repo / "src/module_a.py"
    before = target.read_bytes()
    before_events = sum(1 for _ in sb.kernel.ledger.events())
    res = sb.gateway.request_mutation(
        sb.ctx("agent-alpha"), "src/module_a.py", "UPDATE", b"VALUE = 3\n"
    )
    _expect(res.status == GW_REJECTED, f"expected REJECTED, got {res.status}: {res.reason}")
    _expect("evidence projection" in res.reason, res.reason)
    _expect(target.read_bytes() == before, "side effect ran despite a malformed projection")
    _expect(
        sum(1 for _ in sb.kernel.ledger.events()) == before_events,
        "malformed-projection rejection appended ledger events",
    )
    return "malformed evidence projection rejects the request before any effect"


INTEGRATION_CHECKS: list[tuple[str, Callable[[Path], str]]] = [
    (
        "integrated happy path: adapter → receipt → effect → evidence → gate",
        check_integrated_happy_path,
    ),
    ("deterministic gateway behavior", check_deterministic_gateway),
    ("ATTACK A: direct filesystem mutation bypass", attack_a_direct_filesystem_bypass),
    ("ATTACK B: fake mutation receipt / fabricated evidence", attack_b_fake_receipt),
    ("ATTACK C: valid receipt reused", attack_c_receipt_reuse),
    ("ATTACK D: actor scope escalation / impersonation", attack_d_actor_scope_escalation),
    ("ATTACK E: ledger rollback", attack_e_ledger_rollback),
    ("ATTACK F: evidence emission removed", attack_f_evidence_removed),
    ("ATTACK G: runtime adapter bypass", attack_g_adapter_bypass),
    ("ATTACK H: clock-skew receipt-expiry DoS", attack_h_clock_skew_dos),
    ("ATTACK I: evidence forgery / duplicate shadowing", attack_i_evidence_forgery),
    ("ATTACK J: ci_gate exception-safety (malformed input)", attack_j_gate_exception_safe),
    ("ATTACK K: gateway path escape (absolute / traversal)", attack_k_gateway_path_escape),
    (
        "ATTACK L: malformed evidence projection blocks before effect",
        attack_l_malformed_evidence_projection,
    ),
    (
        "ATTACK M: COMMIT post-state laundering under an issued receipt",
        attack_m_commit_post_state_laundering,
    ),
    ("compatibility: full kernel suite re-run", check_kernel_suite_compatibility),
]


def run_all_integration_checks(work_dir: Path) -> list[CheckResult]:
    results: list[CheckResult] = []
    for index, (name, fn) in enumerate(INTEGRATION_CHECKS):
        sandbox_dir = work_dir / f"integration-{index:02d}"
        try:
            detail = fn(sandbox_dir)
            results.append(CheckResult(name=name, passed=True, detail=detail))
        except (CheckFailure, AssertionError) as exc:
            results.append(CheckResult(name=name, passed=False, detail=str(exc)))
        except Exception as exc:
            results.append(
                CheckResult(name=name, passed=False, detail=f"{type(exc).__name__}: {exc}")
            )
    return results
