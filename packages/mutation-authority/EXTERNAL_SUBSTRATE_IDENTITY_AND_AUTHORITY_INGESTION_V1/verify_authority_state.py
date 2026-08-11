#!/usr/bin/env python3
"""Top verifier: substrate identity + live counts + authority state + verdict.

Read-only with respect to the substrate. Does its own read-only verification
and never depends on the legacy verifier being able to write its child reports
into the read-only Downloads mount (Section 17). Emits the Section 23 report
block and exactly one primary verdict (Section 25).

With no authority evidence on file, the correct outcome is AUTHORITY_LAYER_READY
with every request still ROUTING_REQUIRED — the mechanism exists and refuses to
manufacture readiness. That is success, not failure (Section 24 / 26).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import validator_trust as VT
from _identity import IDENTITY_CONFIRMED, MANIFEST_NAME, verify_manifest
from _registry import REGISTRY_NAME, read_registry
from _substrate import SubstrateError, derive_counts, load_requests, resolve_root
from authority_lifecycle import superseded_ids_of
from authority_receipt import (
    ReceiptError,
    ReplayLedger,
    load_key,
    require_substrate_binding,
    verify_receipt,
)
from authority_router import (
    AUTHORITY_EVIDENCED,
    IDENTITY_EVIDENCED,
    RouteResult,
    derived_counts,
    in_effect,
    route,
    validate_evidence,
)

HERE = Path(__file__).resolve().parent

# Verdicts (Section 25)
AUTHORITY_LAYER_READY = "AUTHORITY_LAYER_READY"
AUTHORITY_PARTIALLY_ACTIVATED = "AUTHORITY_PARTIALLY_ACTIVATED"
AUTHORITY_ACTIVATED = "AUTHORITY_ACTIVATED"
SUBSTRATE_DIVERGED = "SUBSTRATE_DIVERGED"
INTEGRATION_BLOCKED = "INTEGRATION_BLOCKED"


def compute_state(
    substrate_root: Path,
    registry_path: Path,
    keystore: Path,
    eval_instant: str | None,
    manifest_path: Path | None = None,
    validator_registry_path: Path | None = None,
    validator_keystore: Path | None = None,
    policy_path: Path | None = None,
    replay_path: Path | None = None,
) -> dict[str, Any]:
    """Compute the full authority state. Pure w.r.t. the substrate (read-only).

    manifest_path defaults to the package identity manifest; tests may point it
    at a fixture manifest so the confirmed-identity path is exercisable without
    the external substrate present.

    Returns a dict with the identity result, live counts, evidence
    classification, routing result, receipt verification, invariant checks, the
    Section 23 report, and the verdict.
    """
    manifest = json.loads((manifest_path or (HERE / MANIFEST_NAME)).read_text(encoding="utf-8"))
    require_substrate_binding(manifest.get("substrate_id"), manifest.get("critical_set_digest"))
    identity = verify_manifest(manifest, substrate_root)
    confirmed = identity["state"] == IDENTITY_CONFIRMED

    # --- classify evidence (registry-only; independent of the substrate) ---
    records = read_registry(registry_path)
    # A record named in another record's `supersedes` is inactive (Section 15)
    # only when the SUCCESSOR itself qualifies (schema-valid, attested, receipted,
    # in effect) — `supersedes` is attacker-writable content and an unqualified
    # successor must not deactivate established authority.
    superseded_ids = superseded_ids_of(records, eval_instant)
    verified, identity_only, expired, revoked, malformed, superseded = [], [], [], [], [], []
    for rec in records:
        try:
            validate_evidence(rec)
        except Exception:
            malformed.append(rec)
            continue
        if rec.get("authority_evidence_id") in superseded_ids:
            superseded.append(rec)
        elif rec.get("revoked_at"):
            revoked.append(rec)
        elif rec.get("verification_state") == IDENTITY_EVIDENCED:
            identity_only.append(rec)
        elif rec.get("verification_state") == AUTHORITY_EVIDENCED and in_effect(rec, eval_instant):
            verified.append(rec)
        elif rec.get("verification_state") == AUTHORITY_EVIDENCED:
            expired.append(rec)  # authority-evidenced but not in effect at the instant

    # --- VALIDATOR_TRUST_GOVERNANCE_V1 gate: routing eligibility is
    # governed-ACTIVE only. Beyond the onboarding attestation gate, the
    # attestation's VALIDATOR must be registered, authorized for the evidence
    # class, valid at attestation time, and its signature intact; conflicted,
    # invalidated, stale, or doubt-cast records never route (fail closed). An
    # empty validator registry trusts nobody.
    events = VT.load_validator_events(
        validator_registry_path or (HERE / VT.VALIDATOR_REGISTRY_NAME)
    )
    vkeystore = validator_keystore or (HERE / VT.VALIDATOR_KEYSTORE_NAME)
    policy = VT.load_policy(policy_path or (HERE / VT.POLICY_NAME))
    # The authority receipt key gates INGESTED/ACTIVE: a record must carry a
    # verifiable ingestion receipt, not just a receipt-shaped string.
    # Verification NEVER mints the key (load_key, not load_or_create_key):
    # creating a fresh key here would silently invalidate every receipt on
    # file while presenting as a healthy trust root. An absent keystore is
    # tolerable only while no record claims an ingestion receipt.
    key = load_key(keystore)
    if key is None and any(isinstance(r, dict) and r.get("ingestion_receipt") for r in records):
        raise ReceiptError(
            "authority keystore is missing but registry records carry ingestion "
            "receipts — refusing to verify against a trust root that does not "
            "exist (verification must not mint a new receipt key)"
        )
    routable = VT.governed_active_records(
        records,
        eval_instant,
        events=events,
        keystore_dir=vkeystore,
        policy=policy,
        artifact_dir=registry_path.parent / ".authority_artifacts",
        receipt_key=key,
        substrate_identity=manifest["substrate_id"],
        substrate_digest=manifest["critical_set_digest"],
    )
    lifecycle = VT.governed_lifecycle_distribution(
        records,
        eval_instant,
        events=events,
        keystore_dir=vkeystore,
        policy=policy,
        receipt_key=key,
        substrate_identity=manifest["substrate_id"],
        substrate_digest=manifest["critical_set_digest"],
    )

    # --- substrate reads (best-effort; a drifted/absent substrate must not crash) ---
    try:
        requests = load_requests(substrate_root)
    except SubstrateError:
        requests = []
    try:
        live_counts = derive_counts(substrate_root)
    except SubstrateError:
        live_counts = {}

    # --- I9 / ordering invariant: identity authorization completes BEFORE the
    # first state-changing instruction. A substrate that is not IDENTITY_CONFIRMED
    # yields ZERO transitions and ZERO receipts — route() is never entered and no
    # ReplayLedger slot is consumed. ---
    # Verification recomputes deterministically, so the replay ledger is
    # in-memory by default (duplicates within one evaluation still fail).
    # An EXECUTION context — anything acting on receipts — must pass
    # replay_path so consumed receipt ids persist across process restarts.
    if confirmed:
        routed = route(
            requests,
            routable,
            substrate_identity=manifest["substrate_id"],
            substrate_digest=manifest["critical_set_digest"],
            key=key,
            eval_instant=eval_instant,
            replay=ReplayLedger(replay_path),
        )
    else:
        routed = RouteResult(
            request_final_state={r.get("request_id", ""): r.get("routing_state") for r in requests}
        )

    # --- verify every minted receipt ---
    receipt_failures = sum(1 for r in routed.transitions if not verify_receipt(key, r))

    dcounts = derived_counts(requests, routed.request_final_state)

    # --- invariants (I1..I14) computed on the current state ---
    rights_on_requests = sum(1 for r in requests if r.get("rights_assertion") is not None)
    invented_on_requests = sum(
        1 for r in requests if r.get("authority_identity_ref") not in (None, "")
    )
    ready = dcounts["ready_to_send"]
    invariants = {
        "I6_ready_does_not_imply_rights_cleared": rights_on_requests == 0,
        "I7_routing_creates_no_rights_assertion": routed.rights_assertions_created == 0,
        "I8_counts_are_derived": dcounts == derived_counts(requests, routed.request_final_state),
        "I10_no_fabricated_recipient": routed.recipients_invented == 0
        and invented_on_requests == 0,
        "I11_every_transition_receipted": receipt_failures == 0
        and len(routed.transitions) == 2 * ready,
        "I13_substrate_untouched": identity["state"] == IDENTITY_CONFIRMED,
    }
    invariants_hold = all(invariants.values())

    # --- Section 23 report ---
    report = {
        "substrate_identity": manifest.get("substrate_id"),
        "substrate_identity_state": identity["state"],
        "identity_strength": manifest.get("identity_strength"),
        "critical_objects_verified": manifest.get("critical_object_count"),
        "requirements": live_counts.get("requirements"),
        "assets": live_counts.get("assets"),
        "mappings": live_counts.get("mappings"),
        "request_records": live_counts.get("requests"),
        "coverage_edges": live_counts.get("coverage_edges"),
        "routing_required": dcounts["routing_required"],
        "ready_to_send": dcounts["ready_to_send"],
        "no_evidenced_counsel_identity": dcounts["no_evidenced_counsel_identity"],
        "no_appointed_controller": dcounts["no_appointed_controller"],
        "authority_evidence_records": len(records),
        "verified_authority_records": len(verified),
        "routable_authority_records": len(routable),
        "lifecycle_distribution": lifecycle,
        "validator_registry_events": None if events is None else len(events),
        "registered_validators": None
        if events is None
        else len({e.get("validator_id") for e in events if e.get("event") == "REGISTER"}),
        "identity_only_authority_records": len(identity_only),
        "superseded_authority_records": len(superseded),
        "expired_authority_records": len(expired),
        "revoked_authority_records": len(revoked),
        "malformed_authority_records": len(malformed),
        "rights_assertions": rights_on_requests,
        "recipients_invented": routed.recipients_invented + invented_on_requests,
        "authority_receipts": len(routed.transitions),
        "receipt_verification_failures": receipt_failures,
    }

    # --- verdict (Section 25) ---
    total = live_counts.get("requests", 0)
    identity_ok = identity["state"] == IDENTITY_CONFIRMED
    counts_ok = all(
        live_counts.get(k) == manifest["expected_counts"][k] for k in manifest["expected_counts"]
    )
    if not identity_ok:
        verdict = SUBSTRATE_DIVERGED
    elif not (counts_ok and invariants_hold and receipt_failures == 0):
        verdict = INTEGRATION_BLOCKED
    elif ready == 0:
        verdict = AUTHORITY_LAYER_READY
    elif ready >= total:
        verdict = AUTHORITY_ACTIVATED
    else:
        verdict = AUTHORITY_PARTIALLY_ACTIVATED

    return {
        "identity": identity,
        "report": report,
        "invariants": invariants,
        "verdict": verdict,
        "transitions": routed.transitions,
    }


def main(argv: list[str]) -> int:
    # Parse options BEFORE positionals: `--instant=...` as the only argument
    # must set the evaluation instant, never be mistaken for a substrate root.
    instant = None
    positional: list[str] = []
    for a in argv:
        if a.startswith("--instant="):
            instant = a.split("=", 1)[1]
        elif a.startswith("--"):
            print(f"FATAL: unknown option: {a}", file=sys.stderr)
            return 2
        else:
            positional.append(a)

    substrate_root = resolve_root(positional[0] if positional else None)
    manifest_path = HERE / MANIFEST_NAME
    if not manifest_path.is_file():
        print(f"VERDICT: {INTEGRATION_BLOCKED}")
        print(
            f"  {MANIFEST_NAME} not found — run build_substrate_identity.py first", file=sys.stderr
        )
        return 2

    try:
        state = compute_state(
            substrate_root,
            HERE / REGISTRY_NAME,
            HERE / ".authority_keystore",
            instant,
        )
    except ReceiptError as exc:
        print(f"VERDICT: {INTEGRATION_BLOCKED}")
        print(f"  {exc}", file=sys.stderr)
        return 2
    print("=== Section 23 — authority state report ===")
    print(json.dumps(state["report"], indent=1))
    print("\n=== invariants ===")
    for k, v in state["invariants"].items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
    print(f"\nVERDICT: {state['verdict']}")
    if state["verdict"] == AUTHORITY_LAYER_READY:
        print(
            "  mechanism present and fail-closed; no external authority evidence on file, so "
            "every request correctly remains ROUTING_REQUIRED (Section 24)."
        )
    return (
        0
        if state["verdict"]
        in (AUTHORITY_LAYER_READY, AUTHORITY_ACTIVATED, AUTHORITY_PARTIALLY_ACTIVATED)
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
