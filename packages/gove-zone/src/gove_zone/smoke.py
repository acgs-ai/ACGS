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

from gove_zone.audit import ChainHashAuditStore
from gove_zone.errors import DeniedError
from gove_zone.kernel import Kernel
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

    kernel = Kernel(
        policy=BoundaryPolicy(
            forbidden_keywords=["id_rsa", "/etc/shadow", "~/.ssh"],
            rule_id="SMOKE_SECRET_BOUNDARY",
        ),
        audit=ChainHashAuditStore(audit_path),
        actor="gove-zone-smoke",
    )

    @kernel.tool("write_file")
    def write_file(path: str, content: str) -> int:
        Path(path).write_text(content, encoding="utf-8")
        return len(content)

    bytes_written, allow_receipt = kernel.dispatch(
        "write_file",
        {"path": str(safe_path), "content": "governed hello\n"},
        goal="prove allowed side effect",
    )
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
    except DeniedError as exc:
        deny_record = exc.record
        deny_audit_hash = exc.audit_hash
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
    if audit_verdict["valid"] is not True or audit_verdict["checked"] != 2:
        raise RuntimeError(f"smoke audit chain failed: {audit_verdict}")
    checks.append(
        _pass(
            "audit-chain-verifies",
            "two smoke decisions are linked by a valid hash chain",
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
            "decision": allow_receipt.record.decision.value,
            "tool": allow_receipt.record.tool,
            "goal": allow_receipt.record.goal,
            "bytesWritten": bytes_written,
            "auditHash": allow_receipt.audit_hash,
        },
        "deny": {
            "decision": deny_record.decision.value,
            "tool": deny_record.tool,
            "goal": deny_record.goal,
            "matchedRules": list(deny_record.matched_rules),
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
