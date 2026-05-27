"""PrincipalKeyStore + KeyEntry contract.

See `docs/design/phase2-trace-crypto.md` §key store and ADR-0007 §5.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

# cryptography is already a transitive dep; if it ever isn't we want
# this to skip cleanly.
pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def _imports():
    from governance.crypto.principal_keys import (
        FilePrincipalKeyStore,
        KeyEntry,
        UnknownSigningKeyError,
    )

    return KeyEntry, FilePrincipalKeyStore, UnknownSigningKeyError


def _gen_key():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key()


def _now():
    return datetime.now(tz=timezone.utc).replace(microsecond=0)


def _entry_dict(
    *,
    key_id="key-1",
    public_key,
    principal_id="orchestrator-root",
    tenant="default",
    issuer="acgs-root-ca",
    valid_from=None,
    valid_to=None,
    purposes=("trace-delegation",),
    revoked_at=None,
):
    from cryptography.hazmat.primitives import serialization

    pk_hex = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    valid_from = valid_from or (_now() - timedelta(days=1))
    valid_to = valid_to or (_now() + timedelta(days=30))
    return {
        "key_id": key_id,
        "public_key_hex": pk_hex,
        "principal_id": principal_id,
        "tenant": tenant,
        "issuer": issuer,
        "valid_from": valid_from.isoformat(),
        "valid_to": valid_to.isoformat(),
        "purposes": list(purposes),
        "revoked_at": revoked_at.isoformat() if revoked_at else None,
    }


def test_key_entry_loads_metadata_from_file(tmp_path):
    KeyEntry, FilePrincipalKeyStore, _ = _imports()
    _, pk = _gen_key()
    keys = [_entry_dict(public_key=pk)]
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(keys), encoding="utf-8")

    store = FilePrincipalKeyStore(path)
    entry = store.get("key-1")

    assert isinstance(entry, KeyEntry)
    assert entry.key_id == "key-1"
    assert entry.principal_id == "orchestrator-root"
    assert entry.tenant == "default"
    assert entry.issuer == "acgs-root-ca"
    assert "trace-delegation" in entry.purposes
    assert entry.revoked_at is None


def test_unknown_key_id_raises(tmp_path):
    _, FilePrincipalKeyStore, UnknownSigningKeyError = _imports()
    path = tmp_path / "keys.json"
    path.write_text("[]", encoding="utf-8")

    store = FilePrincipalKeyStore(path)
    with pytest.raises(UnknownSigningKeyError):
        store.get("missing")


def test_revoked_at_round_trips(tmp_path):
    _, FilePrincipalKeyStore, _ = _imports()
    _, pk = _gen_key()
    revoked = _now() - timedelta(hours=1)
    keys = [_entry_dict(public_key=pk, revoked_at=revoked)]
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(keys), encoding="utf-8")

    entry = FilePrincipalKeyStore(path).get("key-1")
    assert entry.revoked_at == revoked


def test_purposes_are_a_frozenset(tmp_path):
    _, FilePrincipalKeyStore, _ = _imports()
    _, pk = _gen_key()
    keys = [_entry_dict(public_key=pk, purposes=("trace-delegation", "policy-sign"))]
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(keys), encoding="utf-8")

    entry = FilePrincipalKeyStore(path).get("key-1")
    assert isinstance(entry.purposes, frozenset)
    assert entry.purposes == frozenset({"trace-delegation", "policy-sign"})


def test_valid_from_to_are_timezone_aware(tmp_path):
    _, FilePrincipalKeyStore, _ = _imports()
    _, pk = _gen_key()
    keys = [_entry_dict(public_key=pk)]
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(keys), encoding="utf-8")

    entry = FilePrincipalKeyStore(path).get("key-1")
    assert entry.valid_from.tzinfo is not None
    assert entry.valid_to.tzinfo is not None


def test_public_key_decodes_to_ed25519_public_key(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    _, FilePrincipalKeyStore, _ = _imports()
    _, pk = _gen_key()
    keys = [_entry_dict(public_key=pk)]
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(keys), encoding="utf-8")

    entry = FilePrincipalKeyStore(path).get("key-1")
    assert isinstance(entry.public_key, Ed25519PublicKey)
