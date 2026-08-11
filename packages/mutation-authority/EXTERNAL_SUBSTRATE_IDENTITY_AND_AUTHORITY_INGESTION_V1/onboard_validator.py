#!/usr/bin/env python3
"""EXTERNAL_VALIDATOR_ONBOARDING_V1 — evidence-backed validator registration.

The production path for putting a validator into the registry. Refuses to
register anything it cannot verify; never creates appointment facts, keys it
was not given, or validator identities.

Fail-closed gates, in order:
  1. the appointment record satisfies the onboarding contract
     (identity binding, external appointment authority — no self-appointment,
     class scope, temporal validity, evidence references, key binding);
  2. every appointment_evidence digest matches the sha256 of a supplied real
     artifact (--evidence, repeatable) — a mismatch is forged evidence;
  3. the onboarding instant lies inside the appointment's effective period;
  4. the key ownership proof verifies against the bound key
     (HMAC: keystore key; Ed25519: public key in the appointment);
  5. no conflicting registration exists: the validator_id is unregistered and
     the evidence digests are not already consumed by another validator
     (copied-identity / conflicting-appointments defense);
  6. the REGISTER event is appended chain-linked, carrying the appointment
     binding and evidence digests so provenance is verifiable forever.

`--emit-ownership-payload` prints what the validator's key must sign — the
signing itself happens with the validator's key, not by this tool.

Exit codes: 0 registered · 3 refused (contract/evidence/temporal/conflict)
· 4 key not provably owned · 2 operational error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _canonical import sha256_hex
from validator_admin import _append
from validator_onboarding import (
    ACTIVE,
    AppointmentError,
    appointment_binding,
    derive_ceremony_state,
    key_ownership_payload,
    validate_appointment,
    verify_key_ownership,
)
from validator_trust import (
    ED25519,
    EVENT_SCHEMA,
    VALIDATOR_KEYSTORE_NAME,
    VALIDATOR_REGISTRY_NAME,
    _parse_z,
    load_validator_events,
)

HERE = Path(__file__).resolve().parent


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Onboard one externally appointed validator.")
    ap.add_argument("--appointment", required=True, help="appointment record JSON")
    ap.add_argument(
        "--evidence",
        action="append",
        default=[],
        help="real appointment artifact (repeatable; bytes hashed)",
    )
    ap.add_argument("--registry", default=str(HERE / VALIDATOR_REGISTRY_NAME))
    ap.add_argument("--keystore", default=str(HERE / VALIDATOR_KEYSTORE_NAME))
    ap.add_argument("--instant", required=True, help="onboarding instant, ISO-8601 Z")
    ap.add_argument(
        "--emit-ownership-payload",
        action="store_true",
        help="print the payload the validator's key must sign, then exit",
    )
    args = ap.parse_args(argv)

    app_path = Path(args.appointment)
    if not app_path.is_file():
        print(f"FATAL: appointment file not found: {app_path}", file=sys.stderr)
        return 2
    appointment = json.loads(app_path.read_text(encoding="utf-8"))

    # Gate 1 — onboarding contract.
    try:
        validate_appointment(appointment)
    except AppointmentError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 3

    if args.emit_ownership_payload:
        print(key_ownership_payload(appointment))
        return 0

    if _parse_z(args.instant) is None:
        print("FATAL: --instant must be an ISO-8601 Z instant", file=sys.stderr)
        return 2

    # Gate 2 — every evidence digest must match a supplied real artifact.
    supplied = {}
    for p in args.evidence:
        path = Path(p)
        if not path.is_file():
            print(f"FATAL: evidence artifact not found: {path}", file=sys.stderr)
            return 2
        supplied[sha256_hex(path.read_bytes())] = path
    required = [e["source_digest"] for e in appointment["appointment_evidence"]]
    unmatched = [d for d in required if d not in supplied]
    if unmatched:
        print(
            "REFUSED: forged or missing onboarding evidence — no supplied artifact "
            f"matches digest(s) {[d[:16] + '…' for d in unmatched]}",
            file=sys.stderr,
        )
        return 3

    # Gate 3 — the onboarding instant must lie inside the appointment period.
    now = _parse_z(args.instant)
    frm = _parse_z(appointment["effective_from"])
    until = appointment.get("effective_until")
    if now < frm:
        print("REFUSED: appointment not yet effective at this instant", file=sys.stderr)
        return 3
    if until is not None and now >= _parse_z(until):
        print("REFUSED: expired appointment — effective period has ended", file=sys.stderr)
        return 3

    # Gate 4 — the appointee must provably control the bound key.
    owned, reason = verify_key_ownership(appointment, keystore_dir=Path(args.keystore))
    if not owned:
        print(f"KEY NOT BOUND: {reason}", file=sys.stderr)
        print(
            "  the key_ownership_proof must be a signature over "
            "--emit-ownership-payload made with the bound key.",
            file=sys.stderr,
        )
        return 4

    # Gate 5 — no conflicting registration.
    registry = Path(args.registry)
    events = load_validator_events(registry)
    if events is None:
        print("FATAL: validator registry is malformed — refusing to append", file=sys.stderr)
        return 2
    vid = appointment["validator_id"]
    if any(e.get("event") == "REGISTER" and e.get("validator_id") == vid for e in events):
        print(f"REFUSED: conflicting appointment — {vid} is already registered", file=sys.stderr)
        return 3
    consumed = {
        d
        for e in events
        if e.get("event") == "REGISTER" and e.get("validator_id") != vid
        for d in e.get("appointment_evidence_digests") or []
    }
    reused = [d for d in required if d in consumed]
    if reused:
        print(
            "REFUSED: copied validator identity — appointment evidence "
            f"{[d[:16] + '…' for d in reused]} already backs another validator",
            file=sys.stderr,
        )
        return 3

    # Gate 6 — chain-linked REGISTER with full provenance.
    kb = appointment["key_binding"]
    event = {
        "schema": EVENT_SCHEMA,
        "event": "REGISTER",
        "validator_id": vid,
        "validator_identity": appointment["subject_identity"],
        "organization": appointment["organization"],
        "authorized_classes": sorted(appointment["authorized_classes"]),
        "jurisdiction": appointment["jurisdiction"],
        "appointment_authority": appointment["appointment_authority"],
        "key_id": kb["key_id"],
        "key_algorithm": kb["key_algorithm"],
        "key_fingerprint": kb["key_fingerprint"],
        "effective_from": appointment["effective_from"],
        "effective_until": appointment.get("effective_until"),
        "appointment_binding": appointment_binding(appointment),
        "appointment_evidence_digests": sorted(required),
        "onboarding": "EXTERNAL_VALIDATOR_ONBOARDING_V1",
    }
    if kb["key_algorithm"] == ED25519:
        event["public_key"] = kb["public_key"]
    _append(registry, event)

    state = derive_ceremony_state(
        appointment,
        events=load_validator_events(registry),
        keystore_dir=Path(args.keystore),
        instant=args.instant,
    )
    print(f"REGISTERED {vid} — ceremony_state = {state}")
    if state != ACTIVE:
        print("  (registered but not ACTIVE at this instant — trust will not use it yet)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
