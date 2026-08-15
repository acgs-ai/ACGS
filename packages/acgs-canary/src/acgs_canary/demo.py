"""R0 self-check: an isolated, end-to-end evidence pack.

Everything here runs against a throwaway restricted store under a private
temporary directory, with clearly-marked ephemeral test keys and fixture
anchor evidence. The emitted pack is a TEST/DEVELOPMENT ARTIFACT and says
so conspicuously; nothing it contains is a public release, a completed
commercial issuance, independent proof, or evidence of model training or
licensee intent.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import signing as sig
from .anchor import (
    STATE_CONFIRMED,
    AnchorEvidence,
    FixtureVerifier,
    anchor_predates,
    build_anchor_bundle,
    bundle_hash,
)
from .canonical import canonical_sha256_hex
from .errors import LedgerError
from .ledger import AcceptanceLedger, ledger_path
from .licensee import ensure_ref_key, licensee_ref
from .manifest import build_manifest, store_manifest
from .pool import CanaryPool
from .protocol import protocol_hash
from .store import RestrictedFileStore

DISCLAIMER = [
    "TEST/DEVELOPMENT ARTIFACT",
    "not a public release",
    "not a completed commercial issuance",
    "not independent proof unless backed by a real qualifying external anchor",
    "not evidence of model training or licensee intent",
]


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def run_selfcheck() -> dict[str, Any]:
    """Run the full local chain in isolation. Returns the invariant report."""
    invariants: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="acgs-canary-r0-") as tmp:
        store_dir = Path(tmp) / "restricted"
        store_dir.mkdir(mode=0o700)
        os.chmod(store_dir, 0o700)
        assert stat.S_IMODE(store_dir.stat().st_mode) == 0o700

        store = RestrictedFileStore(store_dir)
        store.initialize(operator="r0-selfcheck")
        pool = CanaryPool(store)
        pool.init_pool(pool_id="r0-demo-pool", created_at=_now(), operator="r0-selfcheck")

        # Small non-production pool.
        pool.generate(tier="T0", count=4, placements=2, created_at=_now())
        pool.generate(tier="T1", count=8, placements=3, created_at=_now())
        pool.validate()
        invariants["pool_invariants_hold"] = True

        # T0 example.
        t0_ids = pool.select_t0(count=3)
        t0_commitment = pool.commitment(t0_ids, tier="T0")
        t0_manifest = build_manifest(
            variant_id="vt_" + "00" * 16,
            tier="T0",
            source_release="r0-demo-source",
            source_tree_sha256="11" * 32,
            canary_commitment_hex=t0_commitment.hex(),
            placement_commitment_hex=canonical_sha256_hex(
                {"variant": "t0-demo", "ids": sorted(t0_ids)}
            ),
            created_at=_now(),
            protocol_sha256=protocol_hash(),
            issuer_ref="issuer:r0-selfcheck",
        )
        store_manifest(store, t0_manifest)
        invariants["t0_commitment_built"] = True

        # T1 example with a keyed selection.
        from .manifest import new_variant_id

        t1_vid = new_variant_id()
        t1_sel = pool.select_t1(variant_id=t1_vid, shared=2, unique=3)
        t1_ids = t1_sel["shared"] + t1_sel["unique"]
        t1_commitment = pool.commitment(t1_ids, tier="T1")
        allocation = {
            "schema": "acgs_canary_allocation/v1",
            "variant_id": t1_vid,
            "tier": "T1",
            "shared": sorted(t1_sel["shared"]),
            "unique": sorted(t1_sel["unique"]),
        }
        t1_manifest = build_manifest(
            variant_id=t1_vid,
            tier="T1",
            source_release="r0-demo-source",
            source_tree_sha256="11" * 32,
            canary_commitment_hex=t1_commitment.hex(),
            placement_commitment_hex=canonical_sha256_hex(allocation),
            created_at=_now(),
            protocol_sha256=protocol_hash(),
            issuer_ref="issuer:r0-selfcheck",
        )
        store_manifest(store, t1_manifest)
        recomputed = pool.commitment(t1_ids, tier="T1").hex()
        invariants["t1_commitment_verifies"] = recomputed == t1_manifest["canary_commitment_hex"]

        # Tier separation: T0 canaries must be refused in a T1 commitment.
        try:
            pool.commitment(t0_ids, tier="T1")
            invariants["tier_namespace_separation"] = False
        except Exception:
            invariants["tier_namespace_separation"] = True

        # Licensee reference (HMAC, dedicated key; identity never stored).
        ensure_ref_key(store)
        lref = licensee_ref(store, "example-licensee-demo-only")
        invariants["licensee_ref_is_opaque"] = lref.startswith("lref_") and len(lref) == 69

        # Ledger.
        ledger = AcceptanceLedger.create(
            ledger_path(store),
            protocol_sha256=protocol_hash(),
            operator="r0-selfcheck",
            timestamp=_now(),
        )
        prepared = ledger.append_prepared(
            variant_id=t1_vid,
            tier="T1",
            variant_tree_sha256=None,
            source_tree_sha256="11" * 32,
            canary_commitment_hex=t1_commitment.hex(),
            allocation_manifest_sha256=canonical_sha256_hex(allocation),
            licensee_ref=lref,
            acceptance_ref={"kind": "contract", "doc_hash": "22" * 32},
            delivery={"channel": "demo", "ref": "local"},
            timestamp=_now(),
        )
        state0 = ledger.issuance_state(t1_vid)
        invariants["prepared_is_not_completed_t1"] = not state0["completed_t1_issuance"]

        issuer_key = sig.ephemeral_test_key("r0-issuer")
        issued = ledger.append_issuer_signature(
            target_entry_hash=prepared["entry_hash"], key=issuer_key, timestamp=_now()
        )
        state1 = ledger.issuance_state(t1_vid)
        invariants["issuer_signed_is_not_completed_t1"] = not state1["completed_t1_issuance"]

        # Production policy: ephemeral key refused for production issuance.
        try:
            sig.enforce_production_policy(issuer_key, production=True)
            invariants["production_blocked_without_org_key"] = False
        except Exception:
            invariants["production_blocked_without_org_key"] = True

        licensee_key = sig.ephemeral_test_key("r0-licensee")
        ledger.append_licensee_countersignature(
            issuer_entry_hash=issued["entry_hash"], key=licensee_key, timestamp=_now()
        )
        state2 = ledger.issuance_state(t1_vid)
        invariants["countersigned_completes_t1"] = state2["completed_t1_issuance"]
        invariants["unanchored_is_publisher_testimony"] = (
            state2["evidence_label"] == "publisher-testimony"
        )

        report = ledger.verify()
        invariants["ledger_chain_verifies"] = report.entries == 4

        # Anchor with FIXTURE evidence (non-production by construction).
        bundle = build_anchor_bundle(
            ledger_head_hash=report.head_hash,
            pool_manifest_sha256=canonical_sha256_hex(pool.pool_manifest()),
            protocol_sha256=protocol_hash(),
            commitment_roots_hex=[t1_commitment.hex()],
            created_at=_now(),
        )
        bhash = bundle_hash(bundle)
        evidence = AnchorEvidence(
            kind="rfc3161",
            state=STATE_CONFIRMED,
            bundle_sha256=bhash,
            evidence_ref="fixture-1",
            anchored_at="2026-08-15T00:00:00Z",
            production=False,
        )
        verifier = FixtureVerifier(
            {"fixture-1": {"bundle_sha256": bhash, "anchored_at": "2026-08-15T00:00:00Z"}}
        )
        invariants["fixture_anchor_predates_observation"] = anchor_predates(
            evidence, bundle, observation_time="2026-08-16T00:00:00Z", verifier=verifier
        )
        ledger.append_anchor(
            head_hash=report.head_hash,
            anchor_ref={"kind": "rfc3161", "bundle_sha256": bhash, "production": False},
            timestamp=_now(),
        )
        state3 = ledger.issuance_state(t1_vid)
        invariants["anchored_state_tracked"] = state3["anchored"]

        # Mirror evidence must never satisfy the independent-anchor test.
        mirror = AnchorEvidence(
            kind="mirror",
            state=STATE_CONFIRMED,
            bundle_sha256=bhash,
            evidence_ref="hf-mirror",
            anchored_at="2026-08-15T00:00:00Z",
            production=False,
        )
        try:
            anchor_predates(
                mirror, bundle, observation_time="2026-08-16T00:00:00Z", verifier=verifier
            )
            invariants["mirror_rejected_as_independent_anchor"] = False
        except Exception:
            invariants["mirror_rejected_as_independent_anchor"] = True

        # Tamper case: flip one byte mid-chain and prove rejection.
        lp = ledger_path(store)
        raw = lp.read_bytes()
        lines = raw.split(b"\n")
        tampered_line = lines[1].replace(b'"tier":"T1"', b'"tier":"T0"', 1)
        assert tampered_line != lines[1]
        lines[1] = tampered_line
        lp.write_bytes(b"\n".join(lines))
        try:
            AcceptanceLedger(lp).verify()
            invariants["tamper_rejected"] = False
        except LedgerError:
            invariants["tamper_rejected"] = True

        # Evidence pack (non-secret): public identifiers and digests only.
        pack = {
            "disclaimer": DISCLAIMER,
            "protocol_sha256": protocol_hash(),
            "pool_manifest_sha256": canonical_sha256_hex(pool.pool_manifest()),
            "t0_commitment_hex": t0_commitment.hex(),
            "t1_variant_id": t1_vid,
            "t1_commitment_hex": t1_commitment.hex(),
            "ledger_head_hash": report.head_hash,
            "anchor_bundle_sha256": bhash,
            "anchor_evidence": "fixture (non-production)",
            "licensee_ref_prefix": lref[:10] + "…",
            "invariants": invariants,
        }
        pack_path = Path(tmp) / "r0-evidence-pack.json"
        pack_path.write_text(json.dumps(pack, indent=2, sort_keys=True) + "\n")

    all_hold = all(invariants.values())
    return {
        "ok": all_hold,
        "command": "r0-selfcheck",
        "disclaimer": DISCLAIMER,
        "invariants": invariants,
        "all_invariants_hold": all_hold,
        "protocol_sha256": protocol_hash(),
    }
