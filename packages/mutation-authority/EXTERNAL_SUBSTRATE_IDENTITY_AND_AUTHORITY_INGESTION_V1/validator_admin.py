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

import _ed25519
from _canonical import hmac_sign, hmac_verify, sha256_hex
from validator_trust import (
    ED25519,
    EVENT_SCHEMA,
    GENESIS,
    HMAC_SHA256,
    KEY_ALGORITHMS,
    VALIDATOR_KEYSTORE_NAME,
    VALIDATOR_REGISTRY_NAME,
    _parse_z,
    chain_intact,
    event_binding,
    load_validator_events,
    registry_write_lock,
    rotation_payload,
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
    """Create a fresh HMAC key atomically with owner-only permissions.
    O_CREAT|O_EXCL with mode 0600 means the key bytes are never observable
    through a world-readable window; a permission failure fails closed."""
    if "/" in key_id or "\\" in key_id or ".." in key_id:
        raise ValueError(f"unsafe key_id: {key_id!r}")
    keystore.mkdir(parents=True, exist_ok=True)
    p = keystore / key_id
    key = secrets.token_bytes(32)
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ValueError(f"key_id already exists in keystore: {key_id}") from None
    except OSError as exc:
        raise ValueError(f"cannot create key with owner-only permissions: {exc}") from exc
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
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
    rot.add_argument(
        "--algorithm",
        choices=list(KEY_ALGORITHMS),
        default=None,
        help="successor key algorithm (default: the validator's current algorithm)",
    )
    rot.add_argument(
        "--public-key",
        default=None,
        help="ed25519 successor public key (raw hex); the private key never leaves the validator",
    )
    rot.add_argument(
        "--rotation-authorization",
        default=None,
        help=(
            "signature by the CURRENT (predecessor) key over the rotation "
            "payload — required when the predecessor key is ed25519 (the "
            "private key never leaves the validator). HMAC predecessors are "
            "signed automatically from the keystore."
        ),
    )

    rev = sub.add_parser("revoke")
    rev.add_argument("--validator-id", required=True)
    rev.add_argument("--instant", required=True, help="revocation instant, ISO-8601 Z")

    args = ap.parse_args(argv)
    registry = Path(args.registry)
    keystore = Path(args.keystore)
    # Every registry writer serializes on the SAME sidecar lock (shared with
    # the onboarding CLI) across its whole read-validate-append sequence: two
    # writers that both read the same tail would emit events with the same
    # prev_event_binding, and the second append would fork the hash chain and
    # invalidate the entire validator history until manual repair.
    with registry_write_lock(registry):
        return _admin(args, registry, keystore)


def _admin(args: argparse.Namespace, registry: Path, keystore: Path) -> int:
    events = load_validator_events(registry)
    if events is None:
        print("FATAL: validator registry is malformed — refusing to append", file=sys.stderr)
        return 2
    if not chain_intact(events):
        print(
            "FATAL: validator registry hash chain is broken — refusing to append "
            "(appending would launder tampered history behind a fresh chain link)",
            file=sys.stderr,
        )
        return 2
    mine = [e for e in events if e.get("validator_id") == args.validator_id]

    if not any(e.get("event") == "REGISTER" for e in mine):
        print(f"REFUSED: {args.validator_id} is not registered", file=sys.stderr)
        return 3
    if _parse_z(args.instant) is None:
        print("REFUSED: --instant must be an ISO-8601 Z instant", file=sys.stderr)
        return 3

    if args.cmd == "rotate":
        # A rotation must not silently downgrade the validator's signature
        # scheme: without --algorithm the successor key keeps the algorithm of
        # the validator's current (latest) key instead of defaulting to HMAC.
        current = [e for e in mine if e.get("event") in ("REGISTER", "ROTATE")]
        # The predecessor is selected as the LAST APPENDED key event, so the
        # new rotation's instant must be strictly later than every existing
        # key event's instant. An out-of-order instant (e.g. an August
        # rotation appended after a September one) would make the CLI sign
        # with a predecessor that is not the key current at that instant:
        # this command would report ROTATED while rotations_authenticated()
        # (which sorts by instant) rejects the whole history at read time.
        new_instant = _parse_z(args.instant)
        prior_instants = [
            _parse_z(e.get("effective_from") if e.get("event") == "REGISTER" else e.get("instant"))
            for e in current
        ]
        if any(i is None for i in prior_instants):
            print(
                "REFUSED: an existing key event carries an unparseable instant — "
                "cannot establish the key current at the rotation instant",
                file=sys.stderr,
            )
            return 3
        if prior_instants and new_instant <= max(prior_instants):
            print(
                "REFUSED: non-monotonic rotation instant — it must be strictly "
                "later than every existing key event for this validator "
                f"(latest: {max(prior_instants).strftime('%Y-%m-%dT%H:%M:%SZ')})",
                file=sys.stderr,
            )
            return 3
        inferred = current[-1].get("key_algorithm", HMAC_SHA256) if current else HMAC_SHA256
        algorithm = args.algorithm or inferred
        event = {
            "schema": EVENT_SCHEMA,
            "event": "ROTATE",
            "validator_id": args.validator_id,
            "key_id": args.key_id,
            "key_algorithm": algorithm,
            "instant": args.instant,
        }
        if algorithm == ED25519:
            if not args.public_key:
                print(
                    "REFUSED: rotating an ed25519 validator requires --public-key "
                    "(raw hex); pass --algorithm hmac-sha256 to downgrade explicitly",
                    file=sys.stderr,
                )
                return 3
            try:
                pub = bytes.fromhex(args.public_key)
            except ValueError:
                pub = b""
            if len(pub) != 32:
                print("REFUSED: --public-key must be 32 raw ed25519 bytes as hex", file=sys.stderr)
                return 3
            event["public_key"] = pub.hex()
            event["key_fingerprint"] = sha256_hex(pub)
        else:
            if args.public_key:
                print(
                    "REFUSED: --public-key is only valid with --algorithm ed25519",
                    file=sys.stderr,
                )
                return 3
            try:
                event["key_fingerprint"] = _write_key(keystore, args.key_id)
            except ValueError as exc:
                print(f"REFUSED: {exc}", file=sys.stderr)
                return 3

        # A rotation must be authorized by the key it retires: verification
        # refuses any ROTATE without a predecessor signature
        # (`unauthenticated_rotation`), so an attacker who can append registry
        # lines cannot rotate a trusted validator onto a key they hold.
        pred = current[-1] if current else None
        if pred is None:
            print("REFUSED: no current key to authorize this rotation", file=sys.stderr)
            return 3
        # A SUPPLIED authorization is verified against the predecessor key
        # BEFORE it is appended: copying an arbitrary string into the registry
        # would produce a chain-valid ROTATE that every later verification
        # rejects as `unauthenticated_rotation`, silently bricking the
        # validator's whole history at read time instead of failing loudly
        # here at write time.
        payload = rotation_payload(event)
        if pred.get("key_algorithm", HMAC_SHA256) == ED25519:
            if not args.rotation_authorization:
                print(
                    "REFUSED: rotating away from an ed25519 key requires "
                    "--rotation-authorization (signature by the current key over "
                    "the rotation payload; the private key never leaves the "
                    "validator)",
                    file=sys.stderr,
                )
                return 3
            pk = pred.get("public_key")
            try:
                pred_pub = bytes.fromhex(pk) if isinstance(pk, str) else b""
            except ValueError:
                pred_pub = b""
            if len(pred_pub) != 32 or sha256_hex(pred_pub) != pred.get("key_fingerprint"):
                print(
                    "REFUSED: predecessor ed25519 public key is missing or does "
                    "not match its registered fingerprint",
                    file=sys.stderr,
                )
                return 3
            if not _ed25519.verify(pred_pub, payload, args.rotation_authorization):
                print(
                    "REFUSED: --rotation-authorization does not verify against "
                    "the predecessor key over this rotation payload",
                    file=sys.stderr,
                )
                return 3
            event["rotation_authorization"] = args.rotation_authorization
        else:
            pred_key_path = keystore / str(pred.get("key_id"))
            if args.rotation_authorization:
                if not pred_key_path.is_file():
                    print(
                        "REFUSED: predecessor key not in keystore — cannot "
                        "verify the supplied rotation authorization",
                        file=sys.stderr,
                    )
                    return 3
                pred_key = pred_key_path.read_bytes()
                if sha256_hex(pred_key) != pred.get("key_fingerprint") or not hmac_verify(
                    pred_key, payload, args.rotation_authorization
                ):
                    print(
                        "REFUSED: --rotation-authorization does not verify against "
                        "the predecessor key over this rotation payload",
                        file=sys.stderr,
                    )
                    return 3
                event["rotation_authorization"] = args.rotation_authorization
            else:
                if not pred_key_path.is_file():
                    print(
                        "REFUSED: predecessor key not in keystore — cannot authorize this rotation",
                        file=sys.stderr,
                    )
                    return 3
                event["rotation_authorization"] = hmac_sign(pred_key_path.read_bytes(), payload)
        _append(registry, event)
        print(
            f"ROTATED {args.validator_id} -> key={args.key_id} "
            f"algorithm={algorithm} fingerprint={event['key_fingerprint']}"
        )
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
