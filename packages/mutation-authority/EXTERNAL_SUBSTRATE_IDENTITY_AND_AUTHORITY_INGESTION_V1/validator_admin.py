#!/usr/bin/env python3
"""VALIDATOR_TRUST_GOVERNANCE_V1 — validator registry administration.

Appends tamper-evident lifecycle events to the validator registry:

    rotate    — issue a new signing key from a given instant; the old key can
                no longer sign new attestations (old signatures made inside
                their window remain verifiable).
    revoke    — end the validator's authority at a given instant.

Registration is NOT available here: enrolling a validator requires
evidence-backed appointment provenance and goes through the 6-gate
onboarding CLI (onboard_validator.py, EXTERNAL_VALIDATOR_ONBOARDING_V1).
A REGISTER event without onboarding provenance is refused at verification
time (`register_missing_onboarding_provenance`), so a self-asserted
registration path would authorize nothing anyway.

The registry is append-only JSONL; every event carries an `event_binding`
digest, so editing history in place is detectable and makes the validator
unverifiable (fail closed). This tool never writes a validation block and
never touches the evidence registry.

Production discipline: the production registry stays EMPTY until a real
validator is appointed by a real authority and onboarded with evidence.

Exit codes: 0 ok · 3 refused (duplicate/unknown/invalid) · 2 operational error.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from _canonical import sha256_hex
from validator_trust import (
    EVENT_SCHEMA,
    GENESIS,
    VALIDATOR_KEYSTORE_NAME,
    VALIDATOR_REGISTRY_NAME,
    _parse_z,
    event_binding,
    load_validator_events,
)

HERE = Path(__file__).resolve().parent


def _append(path: Path, event: dict) -> None:
    """Append one chain-linked event: prev_event_binding continues the registry
    hash chain (GENESIS for the first event) and is covered by event_binding."""
    events = load_validator_events(path) or []
    event["prev_event_binding"] = events[-1]["event_binding"] if events else GENESIS
    event["event_binding"] = event_binding(event)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")


def _write_key(keystore: Path, key_id: str) -> str:
    if "/" in key_id or "\\" in key_id or ".." in key_id:
        raise ValueError(f"unsafe key_id: {key_id!r}")
    keystore.mkdir(parents=True, exist_ok=True)
    p = keystore / key_id
    if p.exists():
        raise ValueError(f"key_id already exists in keystore: {key_id}")
    key = secrets.token_bytes(32)
    p.write_bytes(key)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return sha256_hex(key)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Validator registry administration.")
    ap.add_argument("--registry", default=str(HERE / VALIDATOR_REGISTRY_NAME))
    ap.add_argument("--keystore", default=str(HERE / VALIDATOR_KEYSTORE_NAME))
    sub = ap.add_subparsers(dest="cmd", required=True)

    rot = sub.add_parser("rotate")
    rot.add_argument("--validator-id", required=True)
    rot.add_argument("--key-id", required=True, help="NEW key id")
    rot.add_argument("--instant", required=True, help="rotation instant, ISO-8601 Z")

    rev = sub.add_parser("revoke")
    rev.add_argument("--validator-id", required=True)
    rev.add_argument("--instant", required=True, help="revocation instant, ISO-8601 Z")

    args = ap.parse_args(argv)
    registry = Path(args.registry)
    keystore = Path(args.keystore)
    events = load_validator_events(registry)
    if events is None:
        print("FATAL: validator registry is malformed — refusing to append", file=sys.stderr)
        return 2
    mine = [e for e in events if e.get("validator_id") == args.validator_id]

    if not any(e.get("event") == "REGISTER" for e in mine):
        print(f"REFUSED: {args.validator_id} is not registered", file=sys.stderr)
        return 3
    if _parse_z(args.instant) is None:
        print("REFUSED: --instant must be an ISO-8601 Z instant", file=sys.stderr)
        return 3

    if args.cmd == "rotate":
        try:
            fingerprint = _write_key(keystore, args.key_id)
        except ValueError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 3
        _append(
            registry,
            {
                "schema": EVENT_SCHEMA,
                "event": "ROTATE",
                "validator_id": args.validator_id,
                "key_id": args.key_id,
                "key_fingerprint": fingerprint,
                "instant": args.instant,
            },
        )
        print(f"ROTATED {args.validator_id} -> key={args.key_id} fingerprint={fingerprint}")
        return 0

    if args.cmd == "revoke":
        _append(
            registry,
            {
                "schema": EVENT_SCHEMA,
                "event": "REVOKE",
                "validator_id": args.validator_id,
                "instant": args.instant,
            },
        )
        print(f"REVOKED {args.validator_id} at {args.instant}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
