"""Principal key store for Phase 2 hop-signature verification.

See `docs/design/phase2-trace-crypto.md` §key store and ADR-0007 §5.

The `KeyEntry` returned by ``PrincipalKeyStore.get(key_id)`` carries
the metadata the verifier needs to bind a key to a delegator's
identity, tenant, purpose, validity window, and revocation state.
The Phase 2 file-backed implementation is for tests and local
development; production KMS / HSM integration is Phase 3+.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class UnknownSigningKeyError(LookupError):
    """Raised when a hop references a ``signing_key_id`` not in the store."""


@dataclass(frozen=True)
class KeyEntry:
    """Frozen view of one principal's signing key plus its metadata.

    The verifier uses every field — see §5 of the design doc:
    ``key.principal_id == hop.delegator_id``, ``key.tenant ==
    hop.tenant``, ``"trace-delegation" in key.purposes``, and the
    validity / revocation windows around ``hop.delegated_at``.
    """

    key_id: str
    public_key: Ed25519PublicKey
    principal_id: str
    tenant: str
    issuer: str
    valid_from: datetime
    valid_to: datetime
    purposes: frozenset[str]
    revoked_at: datetime | None


class PrincipalKeyStore(Protocol):
    """Verification-side contract. Production impls live in Phase 3."""

    def get(self, key_id: str) -> KeyEntry: ...


def _parse_dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"datetime {value!r} is not timezone-aware")
    return parsed


class FilePrincipalKeyStore:
    """JSON-file backed key store. Test / local-dev only.

    File format: a top-level JSON array of records, each with:

    .. code-block:: json

        {
          "key_id":         "key-1",
          "public_key_hex": "<32 bytes hex>",
          "principal_id":   "orchestrator-root",
          "tenant":         "default",
          "issuer":         "acgs-root-ca",
          "valid_from":     "<ISO-8601 tz-aware>",
          "valid_to":       "<ISO-8601 tz-aware>",
          "purposes":       ["trace-delegation"],
          "revoked_at":     null
        }
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._cache: dict[str, KeyEntry] | None = None

    def _load(self) -> dict[str, KeyEntry]:
        if self._cache is not None:
            return self._cache
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(f"key store at {self._path} is not a JSON array")
        entries: dict[str, KeyEntry] = {}
        for record in raw:
            pk_bytes = bytes.fromhex(record["public_key_hex"])
            public_key = Ed25519PublicKey.from_public_bytes(pk_bytes)
            entries[record["key_id"]] = KeyEntry(
                key_id=record["key_id"],
                public_key=public_key,
                principal_id=record["principal_id"],
                tenant=record["tenant"],
                issuer=record["issuer"],
                valid_from=_parse_dt(record["valid_from"]),
                valid_to=_parse_dt(record["valid_to"]),
                purposes=frozenset(record.get("purposes", ())),
                revoked_at=(_parse_dt(record["revoked_at"]) if record.get("revoked_at") else None),
            )
        self._cache = entries
        return entries

    def get(self, key_id: str) -> KeyEntry:
        entries = self._load()
        try:
            return entries[key_id]
        except KeyError as exc:
            raise UnknownSigningKeyError(key_id) from exc


__all__ = [
    "FilePrincipalKeyStore",
    "KeyEntry",
    "PrincipalKeyStore",
    "UnknownSigningKeyError",
]
