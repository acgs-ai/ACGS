"""HMAC-based licensee references.

The ledger never carries raw licensee identity. A licensee reference is
HMAC-SHA256 over the identity under a dedicated key with explicit domain
separation — never a plain hash of a name or email (plain hashes of
low-entropy identities are trivially reversible by dictionary).

The reference key is secret material and lives only in the restricted
store. Destroying it (plus the roster mapping) severs linkability:
crypto-shredding for erasure requests, per the design's §5.1.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import secrets as pysecrets

from .errors import StoreIntegrityError
from .store import CanaryStoreBackend, Secret

_REF_DOMAIN = b"acgs-canary/v1/licensee-ref"
_KEY_RECORD = "licensee-ref-key"


def ensure_ref_key(store: CanaryStoreBackend) -> None:
    """Create the dedicated reference key once. Never overwrites."""
    if store.read_record(_KEY_RECORD) is None:
        store.write_record(
            _KEY_RECORD,
            {
                "schema": "acgs_canary_licensee_ref_key/v1",
                "key_hex": pysecrets.token_bytes(32).hex(),  # SECRET
            },
            overwrite=False,
        )


def _ref_key(store: CanaryStoreBackend) -> Secret:
    rec = store.read_record(_KEY_RECORD)
    if rec is None:
        raise StoreIntegrityError("licensee reference key not provisioned")
    return Secret(bytes.fromhex(rec["key_hex"]))


def licensee_ref(store: CanaryStoreBackend, identity: str) -> str:
    """Opaque reference for a licensee identity. Deterministic per store."""
    if not identity or not identity.strip():
        raise StoreIntegrityError("empty licensee identity")
    key = _ref_key(store)
    mac = hmac_mod.new(
        key.reveal(), _REF_DOMAIN + b"\x1f" + identity.encode("utf-8"), hashlib.sha256
    )
    return f"lref_{mac.hexdigest()}"
