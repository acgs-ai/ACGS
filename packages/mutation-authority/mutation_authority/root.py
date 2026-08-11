"""Immutable governance root.

The governance root holds mutation policy, the actor registry, and the
signed manifest that seals both. Signing keys live in a keystore
directory *outside* the governed repository tree, so no governed mutation
can reach them.

Fail-closed contract: every decision and every effect binding calls
``verify_integrity()`` first. A tampered root raises
``RootIntegrityError`` and no decision of any kind is produced.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_json, hash_obj, hmac_sign, hmac_verify, sha256_hex

POLICY_FILE = "policy.json"
ACTORS_FILE = "actors.json"
MANIFEST_FILE = "manifest.json"
ROOT_KEY_FILE = "root.key"

_SEALED_FILES = (POLICY_FILE, ACTORS_FILE)


class RootIntegrityError(Exception):
    """The governance root has been tampered with. Fail closed."""


class UnknownActorError(Exception):
    """No key material registered for the requested actor."""


def _create_key_file(path: Path) -> None:
    """Create a signing-key file atomically with owner-read-only permissions.

    O_CREAT|O_EXCL with mode 0400 makes creation and permission-restriction a
    single operation: the key bytes are never observable through a
    umask-derived window, and an interrupted bootstrap can never leave a
    readable key behind for a later ``initialize()`` to silently accept. Any
    permission/IO error fails closed instead of falling back to
    create-then-chmod."""
    if path.exists():
        return
    key = secrets.token_bytes(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except FileExistsError:
        return  # concurrently bootstrapped; the existing key wins
    except OSError as exc:
        raise RootIntegrityError(
            f"cannot create key file with owner-only permissions: {exc}"
        ) from exc
    try:
        os.write(fd, key)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class GovernanceRoot:
    root_dir: Path
    keystore_dir: Path
    policy: dict[str, Any]
    actors: dict[str, Any]
    manifest: dict[str, Any]

    # -- construction -----------------------------------------------------

    @classmethod
    def initialize(
        cls,
        root_dir: Path,
        keystore_dir: Path,
        policy: dict[str, Any],
        actors: dict[str, Any],
    ) -> GovernanceRoot:
        """Create a new governance root and its keystore.

        Initialization is a bootstrap ceremony: it happens once, before any
        agent runs, and is the only code path that writes to the root.

        Re-running it against a directory that already holds root or keystore
        material is refused outright: silently rewriting policy.json /
        actors.json and re-signing a fresh manifest over them would let anyone
        who can invoke initialize() replace the governance contract in place —
        the exact mutation the sealed root exists to prevent. Fail closed;
        replacing a root is a deliberate operator action (new directories),
        never an overwrite.
        """
        existing = [
            p.name
            for p in (
                root_dir / POLICY_FILE,
                root_dir / ACTORS_FILE,
                root_dir / MANIFEST_FILE,
                keystore_dir / ROOT_KEY_FILE,
            )
            if p.exists()
        ]
        if keystore_dir.is_dir():
            existing.extend(sorted(p.name for p in keystore_dir.glob("actor_*.key")))
        if existing:
            raise RootIntegrityError(
                "governance root already initialized — refusing to overwrite "
                f"existing material: {existing}"
            )
        root_dir.mkdir(parents=True, exist_ok=True)
        keystore_dir.mkdir(parents=True, exist_ok=True)

        root_key_path = keystore_dir / ROOT_KEY_FILE
        _create_key_file(root_key_path)

        for actor_id in actors:
            _create_key_file(keystore_dir / f"actor_{actor_id}.key")

        (root_dir / POLICY_FILE).write_text(canonical_json(policy) + "\n")
        (root_dir / ACTORS_FILE).write_text(canonical_json(actors) + "\n")

        files = {name: sha256_hex((root_dir / name).read_bytes()) for name in _SEALED_FILES}
        manifest_body = {"files": files}
        signature = hmac_sign(root_key_path.read_bytes(), hash_obj(manifest_body))
        manifest = {**manifest_body, "signature": signature}
        (root_dir / MANIFEST_FILE).write_text(canonical_json(manifest) + "\n")

        return cls.load(root_dir, keystore_dir)

    @classmethod
    def load(cls, root_dir: Path, keystore_dir: Path) -> GovernanceRoot:
        try:
            policy = json.loads((root_dir / POLICY_FILE).read_text())
            actors = json.loads((root_dir / ACTORS_FILE).read_text())
            manifest = json.loads((root_dir / MANIFEST_FILE).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RootIntegrityError(f"governance root unreadable: {exc}") from exc
        root = cls(
            root_dir=root_dir,
            keystore_dir=keystore_dir,
            policy=policy,
            actors=actors,
            manifest=manifest,
        )
        root.verify_integrity()
        return root

    # -- integrity --------------------------------------------------------

    def verify_integrity(self) -> None:
        """Re-hash sealed files, re-check the manifest signature, and re-check
        the CACHED policy/actors/manifest against the sealed on-disk state.

        Raises RootIntegrityError on any mismatch. Called before every
        decision and every effect binding — never cached.

        The in-memory comparison matters because every decision reads policy
        and actor records from ``self.policy`` / ``self.actors``: mutating
        those dicts in place (the dataclass is frozen, its dict fields are
        not) would grant scopes or activate actors that the sealed, signed
        files never authorized, while the disk-only checks kept passing.
        """
        try:
            manifest = json.loads((self.root_dir / MANIFEST_FILE).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RootIntegrityError(f"manifest unreadable: {exc}") from exc

        files = manifest.get("files")
        signature = manifest.get("signature")
        if not isinstance(files, dict) or not isinstance(signature, str):
            raise RootIntegrityError("manifest malformed")

        if not hmac_verify(self.root_key(), hash_obj({"files": files}), signature):
            raise RootIntegrityError("manifest signature invalid")

        disk: dict[str, Any] = {}
        for name in _SEALED_FILES:
            path = self.root_dir / name
            if not path.exists():
                raise RootIntegrityError(f"sealed root file missing: {name}")
            data = path.read_bytes()
            if files.get(name) != sha256_hex(data):
                raise RootIntegrityError(f"sealed root file modified: {name}")
            try:
                disk[name] = json.loads(data)
            except json.JSONDecodeError as exc:
                raise RootIntegrityError(f"sealed root file unparseable: {name}: {exc}") from exc

        # Disk is verified; now the cached copies every decision actually
        # consults must agree with it (in-memory tamper fails closed too).
        if manifest != self.manifest:
            raise RootIntegrityError("cached manifest diverges from the sealed manifest on disk")
        if disk[POLICY_FILE] != self.policy:
            raise RootIntegrityError("cached policy diverges from the sealed policy on disk")
        if disk[ACTORS_FILE] != self.actors:
            raise RootIntegrityError("cached actor registry diverges from the sealed actors file")

    def manifest_hash(self) -> str:
        return hash_obj(self.manifest)

    # -- key material -----------------------------------------------------

    def root_key(self) -> bytes:
        try:
            return (self.keystore_dir / ROOT_KEY_FILE).read_bytes()
        except OSError as exc:
            raise RootIntegrityError(f"root key unreadable: {exc}") from exc

    def actor_key(self, actor_id: str) -> bytes:
        path = self.keystore_dir / f"actor_{actor_id}.key"
        if not path.exists():
            raise UnknownActorError(actor_id)
        return path.read_bytes()

    # -- policy accessors -------------------------------------------------

    def actor_record(self, actor_id: str) -> dict[str, Any] | None:
        record = self.actors.get(actor_id)
        return record if isinstance(record, dict) else None

    def governed_prefixes(self) -> list[str]:
        return list(self.policy.get("governed_prefixes", []))

    def protected_prefixes(self) -> list[str]:
        return list(self.policy.get("protected_prefixes", []))

    def receipt_ttl(self) -> int:
        return int(self.policy.get("receipt_ttl", 8))

    def task_authorities(self) -> dict[str, list[str]]:
        return dict(self.policy.get("task_authorities", {}))
