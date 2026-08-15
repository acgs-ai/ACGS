"""Frozen protocol identity.

PROTOCOL is a machine-readable description of every semantic rule in the
canary protocol. Its canonical hash (protocol_sha256) is bound into every
variant manifest, ledger entry, signature payload, and anchor bundle — a
semantic change to any rule below changes the hash, and mixed-protocol
artifacts fail closed everywhere the hash is checked.

Reproducibility: the hash is SHA-256 over canonical_bytes(PROTOCOL)
(sorted keys, no whitespace, ASCII), so formatting of this source file
cannot affect it; only changing the data below can.
"""

from __future__ import annotations

from typing import Any

from .canonical import canonical_sha256_hex

PROTOCOL: dict[str, Any] = {
    "schema": "acgs_canary_protocol/v1",
    "version": "1.0.0",
    "canary_identifier": {
        "format": "cn_ + 16 lowercase hex chars (64-bit CSPRNG)",
        "token": "192-bit CSPRNG bytes; exported only as SHA-256 digest",
        "min_placements": 2,
    },
    "variant_identifier": {
        "format": "vt_ + 32 lowercase hex chars (128-bit CSPRNG)",
        "licensee_derivation": "forbidden — nothing licensee-derived in the id",
    },
    "selection": {
        "ranking": "HMAC-SHA256(selection_salt, "
        "'acgs-canary/v1/selection' 0x1f context 0x1f canary_id)",
        "t0_context": "t0",
        "t1_shared_context": "t1-shared",
        "t1_unique_context": "t1-unique 0x1f variant_id",
        "burned_or_contaminated": "never selected",
        "tier_crossing": "refused",
        "determinism": "deterministic given pool state + variant_id; salt is secret",
    },
    "merkle": {
        "hash": "sha256",
        "leaf": "sha256(0x00 || domain || 0x1f || leaf_bytes)",
        "node": "sha256(0x01 || domain || 0x1f || left || right)",
        "leaf_bytes": "canonical({canary_id, token_sha256})",
        "ordering": "leaves sorted by leaf hash; duplicates rejected",
        "odd_nodes": "promoted, never duplicated",
        "domains": {"t0": "acgs-canary/v1/t0", "t1": "acgs-canary/v1/t1"},
    },
    "canonical_json": {
        "sort_keys": True,
        "separators": [",", ":"],
        "ensure_ascii": True,
        "floats": "rejected",
        "encoding": "utf-8",
    },
    "variant_manifest_schema": "acgs_canary_variant_manifest/v1",
    "ledger": {
        "schema": "acgs_canary_ledger/v1",
        "entry_kinds": [
            "variant.prepared",
            "variant.issuer_signed",
            "variant.countersigned",
            "anchor.recorded",
        ],
        "chain": "entry_hash = sha256(canonical(entry minus entry_hash)); prev links",
        "genesis_prev": "64 zero chars",
        "state_transitions": "append-only entries; prior entries immutable",
        "completed_t1": "requires licensee countersignature entry",
    },
    "signature_domains": {
        "domain": "acgs-canary/v1/sig",
        "payload": "length_prefixed(domain, ledger_id, protocol_sha256, role, purpose, payload)",
        "length_prefix": "8-byte big-endian per part",
        "roles": ["issuer", "licensee"],
        "purposes": ["variant-issue", "variant-countersign"],
        "issuer_signs": "prepared entry hash",
        "licensee_signs": "issuer-signed entry hash (binds the issuer signature)",
        "algorithm": "ed25519",
    },
    "hmac_domains": {
        "licensee_ref": "acgs-canary/v1/licensee-ref",
        "selection": "acgs-canary/v1/selection",
        "key_policy": "dedicated 256-bit keys per domain; plain identity hashes forbidden",
    },
    "anchor_bundle_schema": "acgs_canary_anchor_bundle/v1",
    "anchoring": {
        "anchor_of_record": ["rfc3161", "opentimestamps"],
        "mirror": "supplementary only; never independent evidence",
        "dispute_test": "confirmed independent anchor time strictly precedes observation time",
    },
    "verification_rules": {
        "fail_closed": True,
        "unknown_critical_fields": "rejected",
        "non_canonical_encoding": "rejected",
        "torn_tail": "detected; recoverable only by explicit logged truncation",
        "duplicate_variant_issuance": "rejected",
        "cross_ledger_replay": "rejected via ledger_id binding in signatures",
    },
    "evidentiary_limits": {
        "prevention": "not provided",
        "t0": "corpus-level detection only; never names a party",
        "t1": "identifies the variant's custodian set, not the releaser or intent",
        "frameproof_against_publisher": False,
        "unanchored_artifacts": "publisher testimony, not independent evidence",
        "absence_of_canary": "never exculpatory",
        "detection_regimes_claimed": ["fine-tuning-on-corpus", "verbatim-redistribution"],
        "dilute_pretraining_detection": "not claimed",
        "scope": "published sample pack only; full corpus not covered",
        "derived_artifacts": "must be regenerated over the injected tree",
        "production_t1": "blocked until organizational signing key is configured",
    },
}


def protocol_hash() -> str:
    """The frozen protocol identity hash."""
    return canonical_sha256_hex(PROTOCOL)
