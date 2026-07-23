"""One-command local smoke proof for the governed runtime kernel.

The smoke path is intentionally dependency-free and local-only. It proves the
core developer promise without requiring Claude Code, Codex, a live agent
framework, production credentials, or network access:

* an allowed tool call executes after policy/audit recording,
* a denied tool call is blocked before side effects,
* the audit JSONL chain verifies after both decisions.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from gove_zone._strict_dispatch_fixture import build_strict_dispatch_fixture
from gove_zone.kernel import Kernel
from gove_zone.managed_execution import ManagedExecutionRefusal, ManagedExecutionResult
from gove_zone.policy import BoundaryPolicy

CLAIM_BOUNDARY = (
    "Local gove-zone smoke proof only; not production deployment proof, not "
    "third-party framework certification, and not evidence that a live agent "
    "host is configured."
)


def _pass(check_id: str, evidence: str) -> dict[str, str]:
    return {"id": check_id, "status": "pass", "evidence": evidence}


def _run_smoke(audit_path: Path, *, scratch: Path, audit_retained: bool) -> dict[str, Any]:
    safe_path = scratch / "allowed.txt"
    denied_path = scratch / "id_rsa"
    checks: list[dict[str, str]] = []

    policy = BoundaryPolicy(
        forbidden_keywords=["id_rsa", "/etc/shadow", "~/.ssh"],
        rule_id="SMOKE_SECRET_BOUNDARY",
    )
    fixture = build_strict_dispatch_fixture(
        scratch / "strict-fixture",
        audit_path=audit_path,
        name="write_file",
        actor="gove-zone-smoke",
        policy=policy,
        policy_artifact={
            "kind": "smoke-boundary-policy",
            "version": policy.version,
            "forbidden_keywords": ["id_rsa", "/etc/shadow", "~/.ssh"],
            "rule_id": "SMOKE_SECRET_BOUNDARY",
        },
        server_id="smoke-server",
        tool="write-file-adapter",
        operation="fixture.write_file",
        resource="local-scratch",
        execution_boundary="smoke-receipt-gate",
        side_effect_class="file-write",
    )
    kernel = Kernel(
        policy=policy,
        audit=fixture.audit,
        actor="gove-zone-smoke",
        dispatcher=fixture.dispatcher,
    )

    @kernel.tool("write_file")
    def write_file(path: str, content: str) -> int:
        Path(path).write_text(content, encoding="utf-8")
        return len(content)

    allow_result = kernel.dispatch(
        "write_file",
        {"path": str(safe_path), "content": "governed hello\n"},
        goal="prove allowed side effect",
    )
    if not isinstance(allow_result, ManagedExecutionResult):
        raise RuntimeError("smoke side effect did not use the strict receipt gate")
    allow_event = next(
        (
            event
            for event in fixture.audit.iter_events()
            if str(event.get("event_id")) == allow_result.audit_event_id
        ),
        None,
    )
    if allow_event is None:
        raise RuntimeError("strict smoke allow audit event is missing")
    allow_audit_hash = str(allow_event["event_hash"])
    bytes_written = allow_result.payload
    if safe_path.read_text(encoding="utf-8") != "governed hello\n":
        raise RuntimeError("allowed smoke write did not persist expected content")
    checks.append(
        _pass(
            "allow-before-side-effect",
            "ALLOW receipt emitted and safe write executed after audit append",
        )
    )

    try:
        kernel.dispatch(
            "write_file",
            {"path": str(denied_path), "content": "secret"},
            goal="prove denied side effect",
        )
    except ManagedExecutionRefusal as exc:
        deny_decision = exc.decision.value
        deny_events = list(fixture.audit.iter_events())
        deny_reason_codes = list(deny_events[-1].get("matched_rules", exc.reason_codes))
        deny_audit_hash = str(deny_events[-1]["event_hash"])
    else:  # pragma: no cover - defensive, impossible if policy works
        raise RuntimeError("denied smoke write unexpectedly executed")
    if denied_path.exists():
        raise RuntimeError("denied smoke write created a side-effect file")
    checks.append(
        _pass(
            "deny-before-side-effect",
            "DENY receipt emitted and blocked path write left no side effect",
        )
    )

    audit_verdict = kernel.audit.verify_chain()
    if audit_verdict["valid"] is not True or audit_verdict["checked"] != 4:
        raise RuntimeError(f"smoke audit chain failed: {audit_verdict}")
    checks.append(
        _pass(
            "audit-chain-verifies",
            "two decisions and the allowed execution lifecycle form a valid hash chain",
        )
    )

    return {
        "artifactKind": "gove-zone-smoke-report",
        "status": "pass",
        "claimBoundary": CLAIM_BOUNDARY,
        "auditPath": str(audit_path),
        "auditRetained": audit_retained,
        "checks": checks,
        "allow": {
            "decision": "allow",
            "tool": "write_file",
            "goal": "prove allowed side effect",
            "bytesWritten": bytes_written,
            "auditHash": allow_audit_hash,
        },
        "deny": {
            "decision": deny_decision,
            "tool": "write_file",
            "goal": "prove denied side effect",
            "matchedRules": deny_reason_codes,
            "auditHash": deny_audit_hash,
        },
        "audit": audit_verdict,
    }


def run_smoke(audit_path: str | Path | None = None) -> dict[str, Any]:
    """Run the local allow/deny/audit smoke proof.

    If *audit_path* is omitted, the audit chain is written in a temporary
    directory and removed after the report is built. Pass an explicit path when
    the smoke audit JSONL should be retained as release evidence.
    """
    if audit_path is not None:
        with tempfile.TemporaryDirectory(prefix="gove-zone-smoke-work-") as scratch:
            return _run_smoke(Path(audit_path), scratch=Path(scratch), audit_retained=True)

    with tempfile.TemporaryDirectory(prefix="gove-zone-smoke-") as scratch:
        scratch_path = Path(scratch)
        return _run_smoke(scratch_path / "audit.jsonl", scratch=scratch_path, audit_retained=False)
