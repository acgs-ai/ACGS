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
import os
import stat
import sys
from pathlib import Path

from _canonical import sha256_hex
from validator_admin import RegistryWriteError, _append
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
    APPOINTMENT_ARTIFACTS_DIR_NAME,
    APPOINTMENTS_DIR_NAME,
    ED25519,
    EVENT_SCHEMA,
    VALIDATOR_KEYSTORE_NAME,
    VALIDATOR_REGISTRY_NAME,
    _parse_z,
    chain_intact,
    load_validator_events,
    registry_write_lock,
)

HERE = Path(__file__).resolve().parent


# Exclusive cross-process lock over the registry for the whole
# read-check-append sequence. Shared with validator_admin (rotate/revoke)
# via validator_trust.registry_write_lock so admin/onboarding races
# serialize on the same sidecar, not just onboarding/onboarding ones.
_registry_lock = registry_write_lock


def _retain_appointment(keystore: Path, binding: str, document: bytes) -> str | None:
    """Durably retain the verified appointment record through pinned,
    no-follow directory descriptors. Returns an error message on refusal.

    The retention pathname is predictable (`.appointments/<binding>.json`
    under the keystore), so a pre-planted symlink — the `.appointments`
    entry itself or the digest-named file — would otherwise be followed by
    a plain pathname write, truncating an arbitrary external file during an
    otherwise valid onboarding while the ceremony still derives ACTIVE
    (the provenance verifier follows the same link). Every component is
    opened O_NOFOLLOW relative to a retained parent descriptor, any
    existing non-regular entry is refused, and the directory entry is
    revalidated after the durable write — fail closed."""
    ks_fd = -1
    app_fd = -1
    fd = -1
    try:
        keystore.mkdir(parents=True, exist_ok=True)
        try:
            ks_fd = os.open(keystore, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            return f"cannot pin keystore directory {keystore}: {exc}"
        try:
            os.mkdir(APPOINTMENTS_DIR_NAME, dir_fd=ks_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            return f"cannot create appointment retention directory: {exc}"
        try:
            app_fd = os.open(
                APPOINTMENTS_DIR_NAME,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=ks_fd,
            )
        except OSError as exc:
            return (
                "appointment retention directory is symlinked or not a real "
                f"directory — refusing to follow it: {exc}"
            )
        name = f"{binding}.json"
        try:
            existing = os.stat(name, dir_fd=app_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            return f"cannot inspect retained appointment entry {name}: {exc}"
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            return (
                f"retained appointment entry {name} is not a regular file — "
                "refusing to write through it"
            )
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o644, dir_fd=app_fd)
        except OSError as exc:
            return f"retained appointment entry {name} is symlinked or unopenable: {exc}"
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return f"retained appointment entry {name} is not a regular file"
        os.ftruncate(fd, 0)
        view = memoryview(document)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                return "short write while retaining the appointment record"
            view = view[written:]
        os.fsync(fd)
        # The appended-to inode must still be what the configured entry
        # names: a rename-and-replace mid-write would leave the retained
        # record on a detached file while provenance later reads a swap.
        try:
            named = os.stat(name, dir_fd=app_fd, follow_symlinks=False)
        except OSError as exc:
            return f"retained appointment entry {name} replaced during write: {exc}"
        opened = os.fstat(fd)
        if not stat.S_ISREG(named.st_mode) or (named.st_dev, named.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            return f"retained appointment entry {name} replaced during write"
        os.fsync(app_fd)
        return None
    finally:
        for f in (fd, app_fd, ks_fd):
            if f >= 0:
                os.close(f)


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

    # Gates 5 and 6 run under ONE exclusive registry lock: the conflict
    # checks read the registry and the append writes it, so two racing
    # onboarding runs must serialize across the whole read-check-append
    # sequence or both could pass gate 5 against the same snapshot and both
    # register (duplicate validator_id / reused appointment evidence).
    registry = Path(args.registry)
    with _registry_lock(registry):
        # Gate 5 — no conflicting registration.
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
        vid = appointment["validator_id"]
        if any(e.get("event") == "REGISTER" and e.get("validator_id") == vid for e in events):
            print(
                f"REFUSED: conflicting appointment — {vid} is already registered",
                file=sys.stderr,
            )
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

        # Retain the verified appointment record AND the immutable artifact
        # bytes BEFORE appending: REGISTER provenance is only meaningful if
        # later verification can re-validate the appointment material —
        # including re-hashing the actual evidence artifacts — independently
        # of the registry event itself. A validator whose appointment
        # artifacts stop verifying stops being trusted.
        retention_error = _retain_appointment(
            Path(args.keystore),
            event["appointment_binding"],
            (json.dumps(appointment, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
        )
        if retention_error is not None:
            print(f"FATAL: {retention_error}", file=sys.stderr)
            return 2
        artifact_dir = Path(args.keystore) / APPOINTMENT_ARTIFACTS_DIR_NAME
        artifact_dir.mkdir(parents=True, exist_ok=True)
        for digest in required:
            data = supplied[digest].read_bytes()
            if sha256_hex(data) != digest:
                # The artifact changed on disk between gate 2 and retention.
                print(
                    f"FATAL: evidence artifact {supplied[digest]} changed while "
                    "onboarding — refusing to retain unverified bytes",
                    file=sys.stderr,
                )
                return 2
            retained_artifact = artifact_dir / digest
            if retained_artifact.exists():
                # A preexisting digest-named artifact must actually verify:
                # registering over incorrect or partial retained bytes would
                # report the ceremony as active while
                # _register_has_onboarding_provenance() later rejects all
                # trust for this validator — and a retry is refused because
                # the validator is already registered. A matching regular
                # file is kept; anything else is replaced atomically with
                # the verified supplied bytes (their content is uniquely
                # determined by the digest). A non-regular path (symlink,
                # directory) is never followed or overwritten — fail closed.
                if retained_artifact.is_symlink() or not retained_artifact.is_file():
                    print(
                        f"FATAL: retained appointment artifact {retained_artifact} "
                        "is not a regular file — refusing to register over it",
                        file=sys.stderr,
                    )
                    return 2
                try:
                    existing = retained_artifact.read_bytes()
                except OSError:
                    existing = None
                if existing is not None and sha256_hex(existing) == digest:
                    continue
            tmp = artifact_dir / f".{digest}.tmp"
            tmp.write_bytes(data)
            os.replace(tmp, retained_artifact)
        try:
            _append(registry, event)
        except RegistryWriteError as exc:
            print(f"FATAL: {exc}", file=sys.stderr)
            return 2

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
