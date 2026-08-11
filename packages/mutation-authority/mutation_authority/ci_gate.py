"""CI enforcement gate.

Deterministic, fail-closed verification that the governed repository is
exactly the state its governance layer authorizes:

1. governance-root integrity
2. ledger chain + anchor (rollback/rewrite/regeneration detection)
3. genesis <-> root binding
4. repository state == ledger-authorized state (no unauthorized mutation)
5. receipt provenance for every COMMIT
6. COMMIT <-> evidence bijection (no silent mutation events)

Any check failure — or any exception while checking — fails the gate.
There is no skip path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .engine import _verify_chain_root_binding
from .evidence_emitter import EvidenceEmitter, policy_version
from .ledger import EVENT_COMMIT, AuditLedger
from .root import GovernanceRoot
from .state import repository_violations


@dataclass(frozen=True)
class GateResult:
    passed: bool
    failures: list[str]


def run_ci_gate(
    root: GovernanceRoot,
    ledger: AuditLedger,
    repo_dir: Path,
    evidence: EvidenceEmitter,
) -> GateResult:
    # Fail-closed contract: ANY exception anywhere in the six checks — a
    # malformed evidence line, a schema-violating ledger payload, unreadable
    # key material — is a gate FAILURE, never a skip and never a raw raise.
    try:
        return _run_ci_gate(root, ledger, repo_dir, evidence)
    except Exception as exc:
        return GateResult(False, [f"ci gate aborted (fail closed): {type(exc).__name__}: {exc}"])


def _run_ci_gate(
    root: GovernanceRoot,
    ledger: AuditLedger,
    repo_dir: Path,
    evidence: EvidenceEmitter,
) -> GateResult:
    failures: list[str] = []

    # 1-3. Governance layer integrity.
    root.verify_integrity()
    ledger.verify_chain()
    _verify_chain_root_binding(ledger, root)

    # 4. No unauthorized repository mutation.
    for violation in repository_violations(ledger, repo_dir, root.governed_prefixes()):
        failures.append(f"unauthorized mutation: {violation['kind']} on {violation['resource']}")

    # 5. Receipt provenance for every COMMIT.
    issued = ledger.issued_receipts()
    commits = [e for e in ledger.events() if e.type == EVENT_COMMIT]
    for event in commits:
        receipt = issued.get(event.payload.get("receipt_id", ""))
        if receipt is None:
            failures.append(f"COMMIT seq={event.seq} references a receipt never issued in-chain")
            continue
        if (
            receipt["actor"] != event.payload["actor"]
            or receipt["resource"] != event.payload["resource"]
            or receipt["previous_state_hash"] != event.payload["before_hash"]
        ):
            failures.append(f"COMMIT seq={event.seq} does not match its receipt's binding")

    # 6. COMMIT <-> evidence bijection.
    #    Authenticity first: only root-key-signed records that re-hash to
    #    their evidence_id are admitted. A forger with evidence-file write
    #    access but no keystore access cannot produce one.
    records = evidence.records()
    by_receipt: dict[str, dict] = {}
    seen_receipts: set[str] = set()
    for record in records:
        if not EvidenceEmitter.verify_record(root, record):
            failures.append("evidence record fails root-key signature (forged/tampered)")
            continue
        receipt_id = record.get("receipt_id", "")
        # Duplicate detection: >1 admitted record per receipt_id is itself a
        # failure — otherwise a later forged duplicate could shadow the real
        # record under last-wins selection.
        if receipt_id in seen_receipts:
            failures.append(f"duplicate evidence for receipt {receipt_id[:12]}…")
            continue
        seen_receipts.add(receipt_id)
        by_receipt[receipt_id] = record

    commit_by_receipt = {e.payload["receipt_id"]: e for e in commits}
    for receipt_id, event in commit_by_receipt.items():
        record = by_receipt.get(receipt_id)
        if record is None:
            failures.append(
                f"silent mutation: COMMIT seq={event.seq} "
                f"({event.payload['resource']}) has no evidence record"
            )
            continue
        # Cross-check EVERY field against ledger-derived ground truth,
        # including policy_version, decision, and timestamp (previously
        # unchecked, so those audit claims carried no integrity guarantee).
        expected = {
            "actor": event.payload["actor"],
            "resource": event.payload["resource"],
            "previous_hash": event.payload["before_hash"],
            "new_hash": event.payload["after_hash"],
            "decision": event.payload["decision"],
            "policy_version": policy_version(root),
            "authority_chain_ref": {
                "ledger_seq": event.seq,
                "ledger_event_hash": event.event_hash,
            },
            "timestamp": event.timestamp,
        }
        if any(record.get(k) != v for k, v in expected.items()):
            failures.append(f"evidence for COMMIT seq={event.seq} disagrees with the ledger")
    for receipt_id in by_receipt:
        if receipt_id not in commit_by_receipt:
            failures.append(
                f"fabricated evidence: record for receipt {receipt_id[:12]}… has no COMMIT event"
            )

    return GateResult(passed=not failures, failures=failures)
