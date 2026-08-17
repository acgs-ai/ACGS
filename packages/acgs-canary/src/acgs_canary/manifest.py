"""Private variant manifest: canonical construction and verification.

A variant manifest is a PRIVATE artifact describing one prepared variant.
It is not evidence of delivery, acceptance, or issuance — those states
exist only in the acceptance ledger (ledger.py), and a manifest alone must
never be presented as any of them.
"""

from __future__ import annotations

import secrets as pysecrets
from typing import Any

from .canonical import canonical_bytes, canonical_sha256_hex
from .errors import ManifestError
from .pool import TIER_T0, TIER_T1
from .protocol import protocol_hash
from .store import CanaryStoreBackend

SCHEMA = "acgs_canary_variant_manifest/v1"
_VARIANT_PREFIX = "variant-"
_TIERS = frozenset({TIER_T0, TIER_T1})
_REGEN_STATES = frozenset({"pending", "regenerated", "reconciled"})

_REQUIRED_FIELDS = frozenset(
    {
        "schema",
        "variant_id",
        "tier",
        "source_release",
        "source_tree_sha256",
        "injected_tree_sha256",
        "canary_commitment_hex",
        "placement_commitment_hex",
        "derived_artifacts_status",
        "created_at",
        "protocol_sha256",
        "issuer_ref",
        "ledger_entry_seq",
    }
)


def new_variant_id() -> str:
    """Random 128-bit variant id, non-sequential, nothing licensee-derived."""
    return f"vt_{pysecrets.token_hex(16)}"


def build_manifest(
    *,
    variant_id: str,
    tier: str,
    source_release: str,
    source_tree_sha256: str,
    canary_commitment_hex: str,
    placement_commitment_hex: str,
    created_at: str,
    protocol_sha256: str,
    issuer_ref: str,
    injected_tree_sha256: str | None = None,
    derived_artifacts_status: str = "pending",
    ledger_entry_seq: int | None = None,
) -> dict[str, Any]:
    """Construct a manifest dict; validates all invariants."""
    manifest = {
        "schema": SCHEMA,
        "variant_id": variant_id,
        "tier": tier,
        "source_release": source_release,
        "source_tree_sha256": source_tree_sha256,
        "injected_tree_sha256": injected_tree_sha256,
        "canary_commitment_hex": canary_commitment_hex,
        "placement_commitment_hex": placement_commitment_hex,
        "derived_artifacts_status": derived_artifacts_status,
        "created_at": created_at,
        "protocol_sha256": protocol_sha256,
        "issuer_ref": issuer_ref,
        "ledger_entry_seq": ledger_entry_seq,
    }
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: dict[str, Any]) -> None:
    """Fail-closed structural validation."""
    keys = set(manifest)
    missing = _REQUIRED_FIELDS - keys
    unknown = keys - _REQUIRED_FIELDS
    if missing:
        raise ManifestError(f"missing manifest fields: {sorted(missing)}")
    if unknown:
        raise ManifestError(f"unknown critical manifest fields: {sorted(unknown)}")
    if manifest["schema"] != SCHEMA:
        raise ManifestError(f"schema mismatch: {manifest['schema']!r}")
    vid = manifest["variant_id"]
    if not (isinstance(vid, str) and vid.startswith("vt_") and len(vid) == 35):
        raise ManifestError("variant_id must be vt_ + 32 hex chars (128-bit)")
    try:
        bytes.fromhex(vid[3:])
    except ValueError as exc:
        raise ManifestError("variant_id suffix is not hex") from exc
    if manifest["tier"] not in _TIERS:
        raise ManifestError(f"unknown tier: {manifest['tier']!r}")
    for field in (
        "source_tree_sha256",
        "canary_commitment_hex",
        "placement_commitment_hex",
        "protocol_sha256",
    ):
        _require_hex64(manifest[field], field)
    # The frozen-protocol contract is enforced HERE, not only in the CLI:
    # a manifest bound to a foreign protocol identity must fail validation
    # for every library consumer (build/store/load/hash), not just for the
    # variant-verify command.
    if manifest["protocol_sha256"] != protocol_hash():
        raise ManifestError(
            "manifest protocol identity does not match this package's frozen "
            "protocol; mixed-protocol artifacts are refused"
        )
    injected = manifest["injected_tree_sha256"]
    if injected is not None:
        _require_hex64(injected, "injected_tree_sha256")
    status = manifest["derived_artifacts_status"]
    if status not in _REGEN_STATES:
        raise ManifestError(f"illegal derived_artifacts_status: {status!r}")
    # A finalized injected tree without regenerated/reconciled derived
    # artifacts is the design's "internally inconsistent sealed release"
    # failure (round-2 condition 2): refuse the combination.
    if injected is not None and status == "pending":
        raise ManifestError(
            "injected tree is finalized but derived artifacts are 'pending'; "
            "derived artifacts must be regenerated over the injected tree"
        )
    # The reverse is equally inconsistent: derived artifacts cannot have
    # been regenerated/reconciled over an injected tree that does not exist.
    if injected is None and status != "pending":
        raise ManifestError(
            f"derived_artifacts_status is {status!r} but no injected tree is "
            "finalized; non-pending statuses require injected_tree_sha256"
        )
    seq = manifest["ledger_entry_seq"]
    if seq is not None and (not isinstance(seq, int) or seq < 0):
        raise ManifestError("ledger_entry_seq must be a non-negative integer")


def _require_hex64(value: Any, field: str) -> None:
    if not (isinstance(value, str) and len(value) == 64):
        raise ManifestError(f"{field} must be 64 hex chars")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ManifestError(f"{field} is not hex") from exc


def manifest_hash(manifest: dict[str, Any]) -> str:
    validate_manifest(manifest)
    return canonical_sha256_hex(manifest)


def store_manifest(store: CanaryStoreBackend, manifest: dict[str, Any]) -> None:
    """Persist, enforcing variant_id uniqueness against the store."""
    validate_manifest(manifest)
    name = f"{_VARIANT_PREFIX}{manifest['variant_id']}"
    if store.read_record(name) is not None:
        raise ManifestError(f"variant_id already exists: {manifest['variant_id']}")
    store.write_record(name, manifest, overwrite=False)


def load_manifest(store: CanaryStoreBackend, variant_id: str) -> dict[str, Any]:
    rec = store.read_record(f"{_VARIANT_PREFIX}{variant_id}")
    if rec is None:
        raise ManifestError(f"unknown variant: {variant_id}")
    validate_manifest(rec)
    return rec


def update_manifest(store: CanaryStoreBackend, variant_id: str, **changes: Any) -> dict[str, Any]:
    """Apply an explicit, validated field update (e.g. finalize injected tree,
    record derived-artifact regeneration, link the ledger entry)."""
    allowed = {"injected_tree_sha256", "derived_artifacts_status", "ledger_entry_seq"}
    illegal = set(changes) - allowed
    if illegal:
        raise ManifestError(f"fields not updatable: {sorted(illegal)}")
    manifest = load_manifest(store, variant_id)
    manifest.update(changes)
    validate_manifest(manifest)
    store.write_record(f"{_VARIANT_PREFIX}{variant_id}", manifest, overwrite=True)
    return manifest


def canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    validate_manifest(manifest)
    return canonical_bytes(manifest)
