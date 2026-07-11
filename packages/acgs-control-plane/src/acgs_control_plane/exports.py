"""Compliance export bundles.

An export is a self-contained, hash-manifested evidence bundle: org metadata,
policy bundle history, every receipt row, and the raw audit chain events.
Section hashes and the bundle hash use gove-zone's canonical ``sha256_json``
so an external verifier can recompute them without this package.
"""

from __future__ import annotations

from typing import Any

from gove_zone import sha256_json
from sqlalchemy import select
from sqlalchemy.orm import Session

from acgs_control_plane.governance import GovernanceMembrane, chain_tip
from acgs_control_plane.models import AgentRecord, Organization, PolicyBundle, ReceiptRow

EXPORT_SCHEMA = "acgs-control-plane/export/v1"


def build_export_bundle(
    session: Session,
    membrane: GovernanceMembrane,
    org: Organization,
    *,
    note: str = "",
) -> dict[str, Any]:
    receipts = [
        row.payload
        for row in session.execute(
            select(ReceiptRow)
            .where(ReceiptRow.org_id == org.id)
            .order_by(ReceiptRow.created_at.asc(), ReceiptRow.id.asc())
        ).scalars()
    ]
    policies = [
        {
            "bundle_id": p.id,
            "policy_id": p.policy_id,
            "version": p.version,
            "status": p.status,
            "bundle": p.bundle,
            "created_at": p.created_at.isoformat(),
        }
        for p in session.execute(
            select(PolicyBundle)
            .where(PolicyBundle.org_id == org.id)
            .order_by(PolicyBundle.created_at.asc(), PolicyBundle.id.asc())
        ).scalars()
    ]
    agents = [
        {
            "agent_id": a.id,
            "name": a.name,
            "trust_tier": a.trust_tier,
            "allowed_tools": list(a.allowed_tools),
            "status": a.status,
        }
        for a in session.execute(
            select(AgentRecord)
            .where(AgentRecord.org_id == org.id)
            .order_by(AgentRecord.created_at.asc(), AgentRecord.id.asc())
        ).scalars()
    ]
    audit_events = list(membrane.store.iter_events())
    count, last = chain_tip(membrane.store)

    sections: dict[str, Any] = {
        "organization": {"org_id": org.id, "name": org.name},
        "policies": policies,
        "agents": agents,
        "receipts": receipts,
        "audit_chain": {"events": audit_events, "event_count": count, "last_hash": last},
    }
    manifest = {name: sha256_json(payload) for name, payload in sections.items()}
    return {
        "schema": EXPORT_SCHEMA,
        "note": note,
        "sections": sections,
        "manifest": manifest,
        "bundle_hash": sha256_json(manifest),
    }


def verify_export_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Recompute section hashes + bundle hash. Pure function of the bundle."""
    sections = bundle.get("sections", {})
    manifest = bundle.get("manifest", {})
    mismatches = [
        name for name, payload in sections.items() if manifest.get(name) != sha256_json(payload)
    ]
    bundle_hash_ok = bundle.get("bundle_hash") == sha256_json(manifest)
    return {
        "valid": not mismatches and bundle_hash_ok,
        "section_mismatches": mismatches,
        "bundle_hash_ok": bundle_hash_ok,
    }
