"""Worked end-to-end example: governed file writes.

Demonstrates the full kernel loop on a single tool — ``write_file``:

  Goal → Proposed Action → Governance Decision → Tool Execution or Denial
       → Receipt → Audit Log

Run::

    PYTHONPATH=packages/gove-zone/src python3 packages/gove-zone/examples/write_file_guard.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from gove_zone import (
    BoundaryPolicy,
    ChainHashAuditStore,
    DeniedError,
    Kernel,
)


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="gove-zone-demo-"))
    audit_path = tmp / "audit.jsonl"

    kernel = Kernel(
        policy=BoundaryPolicy(
            forbidden_keywords=["~/.ssh", "/etc/shadow", "id_rsa"],
            rule_id="FS-GUARD",
        ),
        audit=ChainHashAuditStore(audit_path),
        actor="demo-runner",
    )

    @kernel.tool("write_file")
    def write_file(path: str, content: str) -> int:
        Path(path).write_text(content)
        return len(content)

    # 1. ALLOW path — the safe write executes and the receipt captures
    #    every governance field required by the MVP spec.
    safe_path = str(tmp / "hello.txt")
    bytes_written, receipt = kernel.dispatch(
        "write_file",
        {"path": safe_path, "content": "hello\n"},
        goal="seed demo file",
    )
    print("ALLOW")
    print(f"  wrote {bytes_written} bytes to {safe_path}")
    print(f"  decision        = {receipt.record.decision.value}")
    print(f"  goal            = {receipt.record.goal!r}")
    print(f"  policy_version  = {receipt.record.policy_version}")
    print(f"  argument_hash   = {receipt.record.argument_hash[:16]}…")
    print(f"  audit_hash      = {receipt.audit_hash[:16]}…")
    print()

    # 2. DENY path — the attempted exfiltration is blocked BEFORE the
    #    file operation can run. No side effect; the attempt is anchored
    #    in the audit chain.
    try:
        kernel.dispatch(
            "write_file",
            {"path": "/tmp/fake/id_rsa", "content": "stolen"},
            goal="exfiltrate ssh key",
        )
    except DeniedError as exc:
        print("DENY")
        print("  blocked write to a path matching id_rsa")
        print(f"  goal            = {exc.record.goal!r}")
        print(f"  reason          = {exc.record.reason}")
        print(f"  matched_rules   = {list(exc.record.matched_rules)}")
        print(f"  audit_hash      = {exc.audit_hash[:16]}…")
        assert not Path("/tmp/fake/id_rsa").exists()
        print()

    # 3. Audit chain integrity — both events are anchored and the chain
    #    verifies. Tampering with the JSONL would flip ``valid`` to False.
    result = kernel.audit.verify_chain()
    print("AUDIT")
    print(f"  chain valid     = {result['valid']}")
    print(f"  events          = {result['checked']}")
    print(f"  log path        = {audit_path}")


if __name__ == "__main__":
    main()
