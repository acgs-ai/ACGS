#!/usr/bin/env python3
"""VALIDATOR_TRUST_GOVERNANCE_V1 — validator registry administration.

Appends tamper-evident lifecycle events to the validator registry:

    rotate    — issue a new signing key from a given instant; the old key can
                no longer sign new attestations (old signatures made inside
                their window remain verifiable).
    revoke    — end the validator's authority at a given instant.

    prepare-rotation — stage an ed25519 -> HMAC rotation: mints (or reuses)
                the successor HMAC key in the keystore and prints the exact
                rotation payload the predecessor ed25519 holder must sign.
                Needed because the HMAC key fingerprint is part of the signed
                payload, so the payload cannot exist before the key does; the
                holder signs offline, then `rotate --rotation-authorization`
                reuses the staged key. Idempotent.

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


def _stage_key(keystore: Path, key_id: str) -> str:
    """Mint the successor HMAC key, or reuse an already-staged one.

    Idempotent on purpose: prepare-rotation may be re-run (or a rotate may be
    retried after a refused attempt) and must keep returning the SAME
    fingerprint, because the predecessor's offline signature covers it."""
    if "/" in key_id or "\\" in key_id or ".." in key_id:
        raise ValueError(f"unsafe key_id: {key_id!r}")
    p = keystore / key_id
    if p.is_file():
        return sha256_hex(p.read_bytes())
    return _write_key(keystore, key_id)


def _key_events(mine: list[dict]) -> list[dict]:
    return [e for e in mine if e.get("event") in ("REGISTER", "ROTATE")]


def _rotation_guard_error(
    mine: list[dict], current: list[dict], key_id: str, instant: str
) -> str | None:
    """Shared write-time guards for rotate and prepare-rotation, so a staged
    payload is always one that rotate will actually accept.

    A rotation at or after the validator's earliest REVOKE instant is refused:
    authority_valid_at() treats that revocation as terminal and _key_windows()
    discards windows beginning at or after it, so the CLI would append an
    authenticated ROTATE, print ROTATED, and hand back a key that can never
    validate an attestation. Rotations strictly BEFORE the revocation remain
    legal (their window is trimmed at the revocation instant).

    The predecessor is selected as the LAST APPENDED key event, so the new
    rotation's instant must be strictly later than every existing key event's
    instant. An out-of-order instant (e.g. an August rotation appended after
    a September one) would make the CLI sign with a predecessor that is not
    the key current at that instant: the command would report ROTATED while
    rotations_authenticated() (which sorts by instant) rejects the whole
    history at read time.

    A successor key id must be NEW for this validator, for every algorithm.
    HMAC rotations were only refused incidentally (keystore O_EXCL); an
    ed25519 rotation reusing an existing key_id with a new public key would
    be appended, and then _key_windows() treats the later event as current
    while _key_event_of() resolves the FIRST event with that id — so
    attestations verify against the retired key and the "successfully
    rotated" validator is unusable."""
    new_instant = _parse_z(instant)
    revocation_instants = []
    for e in mine:
        if e.get("event") != "REVOKE":
            continue
        rev = _parse_z(e.get("instant"))
        if rev is None:
            return (
                "an existing REVOKE event carries an unparseable instant — "
                "cannot establish whether the validator is revoked at the "
                "rotation instant"
            )
        revocation_instants.append(rev)
    if revocation_instants and new_instant >= min(revocation_instants):
        return (
            "validator is revoked at or before this rotation instant — a key "
            "issued at or after the earliest revocation "
            f"({min(revocation_instants).strftime('%Y-%m-%dT%H:%M:%SZ')}) "
            "could never validate an attestation (revocation is terminal)"
        )
    prior_instants = [
        _parse_z(e.get("effective_from") if e.get("event") == "REGISTER" else e.get("instant"))
        for e in current
    ]
    if any(i is None for i in prior_instants):
        return (
            "an existing key event carries an unparseable instant — "
            "cannot establish the key current at the rotation instant"
        )
    if prior_instants and new_instant <= max(prior_instants):
        return (
            "non-monotonic rotation instant — it must be strictly "
            "later than every existing key event for this validator "
            f"(latest: {max(prior_instants).strftime('%Y-%m-%dT%H:%M:%SZ')})"
        )
    if any(e.get("key_id") == key_id for e in current):
        return (
            f"key_id {key_id!r} already appears in this "
            "validator's key history — a rotation must introduce a new key id"
        )
    return None


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

    prep = sub.add_parser(
        "prepare-rotation",
        help=(
            "stage an ed25519 -> hmac-sha256 rotation: mint (or reuse) the "
            "successor HMAC key and print the rotation payload the current "
            "ed25519 key holder must sign for --rotation-authorization"
        ),
    )
    prep.add_argument("--validator-id", required=True)
    prep.add_argument("--key-id", required=True, help="NEW key id")
    prep.add_argument("--instant", required=True, help="rotation instant, ISO-8601 Z")

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

    if args.cmd == "prepare-rotation":
        current = _key_events(mine)
        pred = current[-1] if current else None
        if pred is None:
            print("REFUSED: no current key to authorize a rotation", file=sys.stderr)
            return 3
        if pred.get("key_algorithm", HMAC_SHA256) != ED25519:
            print(
                "REFUSED: prepare-rotation is only for ed25519 predecessors — "
                "HMAC predecessors are signed automatically by `rotate`",
                file=sys.stderr,
            )
            return 3
        guard = _rotation_guard_error(mine, current, args.key_id, args.instant)
        if guard is not None:
            print(f"REFUSED: {guard}", file=sys.stderr)
            return 3
        try:
            fingerprint = _stage_key(keystore, args.key_id)
        except ValueError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 3
        event = {
            "schema": EVENT_SCHEMA,
            "event": "ROTATE",
            "validator_id": args.validator_id,
            "key_id": args.key_id,
            "key_algorithm": HMAC_SHA256,
            "instant": args.instant,
            "key_fingerprint": fingerprint,
        }
        print(
            f"STAGED successor key {args.key_id} (fingerprint={fingerprint}); "
            "sign the payload below with the current ed25519 key and pass the "
            "signature to `rotate --rotation-authorization`:",
            file=sys.stderr,
        )
        print(rotation_payload(event))
        return 0

    if args.cmd == "rotate":
        # Freshly minted (never staged) successor keys must not survive a
        # refusal: the keystore's O_EXCL discipline would turn every retry
        # with the same --key-id into a spurious duplicate. Keys staged by
        # prepare-rotation are deliberately durable — the predecessor's
        # offline signature covers their fingerprint, so deleting one on a
        # refused attempt would make the already-signed payload unusable.
        minted_key_path: Path | None = None

        def _refuse(msg: str) -> int:
            if minted_key_path is not None:
                minted_key_path.unlink(missing_ok=True)
            print(f"REFUSED: {msg}", file=sys.stderr)
            return 3

        # A rotation must not silently downgrade the validator's signature
        # scheme: without --algorithm the successor key keeps the algorithm of
        # the validator's current (latest) key instead of defaulting to HMAC.
        current = _key_events(mine)
        # A rotation must be authorized by the key it retires: verification
        # refuses any ROTATE without a predecessor signature
        # (`unauthenticated_rotation`), so an attacker who can append registry
        # lines cannot rotate a trusted validator onto a key they hold.
        pred = current[-1] if current else None
        if pred is None:
            return _refuse("no current key to authorize this rotation")
        pred_is_ed25519 = pred.get("key_algorithm", HMAC_SHA256) == ED25519
        guard = _rotation_guard_error(mine, current, args.key_id, args.instant)
        if guard is not None:
            return _refuse(guard)
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
                return _refuse(
                    "rotating an ed25519 validator requires --public-key "
                    "(raw hex); pass --algorithm hmac-sha256 to downgrade explicitly"
                )
            try:
                pub = bytes.fromhex(args.public_key)
            except ValueError:
                pub = b""
            if len(pub) != 32:
                return _refuse("--public-key must be 32 raw ed25519 bytes as hex")
            event["public_key"] = pub.hex()
            event["key_fingerprint"] = sha256_hex(pub)
        else:
            if args.public_key:
                return _refuse("--public-key is only valid with --algorithm ed25519")
            successor_path = keystore / args.key_id
            if pred_is_ed25519 and successor_path.is_file():
                # An ed25519 -> HMAC rotation is only signable if the successor
                # key (whose fingerprint is inside the signed payload) exists
                # BEFORE the holder signs: reuse the key staged by
                # prepare-rotation instead of minting a conflicting fresh one.
                event["key_fingerprint"] = sha256_hex(successor_path.read_bytes())
            else:
                try:
                    event["key_fingerprint"] = _write_key(keystore, args.key_id)
                except ValueError as exc:
                    return _refuse(str(exc))
                minted_key_path = successor_path

        # A SUPPLIED authorization is verified against the predecessor key
        # BEFORE it is appended: copying an arbitrary string into the registry
        # would produce a chain-valid ROTATE that every later verification
        # rejects as `unauthenticated_rotation`, silently bricking the
        # validator's whole history at read time instead of failing loudly
        # here at write time.
        payload = rotation_payload(event)
        if pred_is_ed25519:
            if not args.rotation_authorization:
                return _refuse(
                    "rotating away from an ed25519 key requires "
                    "--rotation-authorization (signature by the current key over "
                    "the rotation payload; the private key never leaves the "
                    "validator)"
                )
            pk = pred.get("public_key")
            try:
                pred_pub = bytes.fromhex(pk) if isinstance(pk, str) else b""
            except ValueError:
                pred_pub = b""
            if len(pred_pub) != 32 or sha256_hex(pred_pub) != pred.get("key_fingerprint"):
                return _refuse(
                    "predecessor ed25519 public key is missing or does "
                    "not match its registered fingerprint"
                )
            if not _ed25519.verify(pred_pub, payload, args.rotation_authorization):
                return _refuse(
                    "--rotation-authorization does not verify against "
                    "the predecessor key over this rotation payload"
                )
            event["rotation_authorization"] = args.rotation_authorization
        else:
            pred_key_path = keystore / str(pred.get("key_id"))
            if args.rotation_authorization:
                if not pred_key_path.is_file():
                    return _refuse(
                        "predecessor key not in keystore — cannot "
                        "verify the supplied rotation authorization"
                    )
                pred_key = pred_key_path.read_bytes()
                if sha256_hex(pred_key) != pred.get("key_fingerprint") or not hmac_verify(
                    pred_key, payload, args.rotation_authorization
                ):
                    return _refuse(
                        "--rotation-authorization does not verify against "
                        "the predecessor key over this rotation payload"
                    )
                event["rotation_authorization"] = args.rotation_authorization
            else:
                if not pred_key_path.is_file():
                    return _refuse(
                        "predecessor key not in keystore — cannot authorize this rotation"
                    )
                # Sign only with the key the registry actually registered: a
                # corrupted or swapped keystore file would produce a ROTATE
                # that rotations_authenticated() rejects at read time, silently
                # bricking the validator's whole history while this command
                # reports success.
                pred_key = pred_key_path.read_bytes()
                if sha256_hex(pred_key) != pred.get("key_fingerprint"):
                    return _refuse(
                        "keystore predecessor key does not match its "
                        "registered fingerprint — signing with it would append "
                        "an unauthenticated rotation"
                    )
                event["rotation_authorization"] = hmac_sign(pred_key, payload)
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
