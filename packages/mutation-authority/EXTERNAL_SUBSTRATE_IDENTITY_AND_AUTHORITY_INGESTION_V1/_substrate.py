"""Read-only access to the external COMMERCIAL_BUYER_READINESS_V1 substrate.

This module NEVER writes into the substrate. It resolves the substrate root,
enumerates a fixed deterministic set of critical objects, hashes them, and
re-derives the structural counts from the *live* registries (not from any
cached verification_report.json). Every function fails closed: a missing
critical object or registry raises SubstrateError rather than returning a
partial answer.

Substrate root = the ``COMMERCIAL_BUYER_READINESS_V1`` directory. Resolution
order:
  1. explicit ``root`` argument;
  2. ``$ACGS_COMMERCIAL_SUBSTRATE_ROOT`` (relocation support — Section 6);
  3. the observed canonical path in the downloaded trajectory bundle.

Identity is bound to the *bytes of the critical objects*, not to the pathname
(Section 6): a relocated substrate whose critical objects are identical still
verifies.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from _canonical import ABSENT, hash_file

# Observed canonical location (the extraction of
# traj_procurement_guideline_20260609.zip). Not load-bearing for identity —
# only a default. Identity rests on critical-object hashes.
DEFAULT_SUBSTRATE_ROOT = (
    Path.home()
    / "Downloads"
    / "traj_procurement_guideline_20260609 (2)"
    / "governance_trajectories"
    / "COMMERCIAL_BUYER_READINESS_V1"
)

SUBSTRATE_ENV = "ACGS_COMMERCIAL_SUBSTRATE_ROOT"

# Layer subdirectories that carry the request/mapping state this layer routes.
REQ_EXEC = "COMMERCIAL_RIGHTS_REQUEST_EXECUTION_V1"
REQ_MODEL = "COMMERCIAL_RIGHTS_REQUIREMENT_MODEL_V1"

# Live registries the counts are re-derived from (relative to the root).
REL_REQUEST_REGISTRY = f"{REQ_EXEC}/COMMERCIAL_RIGHTS_REQUEST_REGISTRY.json"
REL_COVERAGE = f"{REQ_EXEC}/COMMERCIAL_RIGHTS_REQUEST_COVERAGE.json"
REL_MAPPING = f"{REQ_MODEL}/RIGHTS_REQUEST_MAPPING.json"
REL_REQUIREMENTS = f"{REQ_MODEL}/COMMERCIAL_RIGHTS_REQUIREMENTS.json"

# The fixed critical-object set that establishes substrate identity. Chosen as
# the smallest set that pins the two layers carrying the 340 requests / 408
# mappings / 12 requirements, plus the top verifier and each layer's own
# sha256sums.txt manifest (which transitively pins every file in that layer).
# Enumerated as an explicit list — never a directory walk — so identity is
# deterministic and order-independent.
CRITICAL_OBJECTS: tuple[str, ...] = (
    "verify_readiness.py",
    "README.md",
    f"{REQ_EXEC}/COMMERCIAL_RIGHTS_REQUEST_REGISTRY.json",
    f"{REQ_EXEC}/COMMERCIAL_RIGHTS_REQUEST_COVERAGE.json",
    f"{REQ_EXEC}/COMMERCIAL_RIGHTS_REQUIREMENT_ONTOLOGY.json",
    f"{REQ_EXEC}/COMMERCIAL_RIGHTS_REQUEST_SCHEMA.json",
    f"{REQ_EXEC}/CRE_INDEX.json",
    f"{REQ_EXEC}/verify_commercial_rights_requests.py",
    f"{REQ_EXEC}/sha256sums.txt",
    f"{REQ_MODEL}/COMMERCIAL_RIGHTS_REQUIREMENTS.json",
    f"{REQ_MODEL}/RIGHTS_REQUEST_MAPPING.json",
    f"{REQ_MODEL}/RIGHTS_REQUIREMENT_SCHEMA.json",
    f"{REQ_MODEL}/CR_INDEX.json",
    f"{REQ_MODEL}/verify_rights_requirements.py",
    f"{REQ_MODEL}/sha256sums.txt",
)

# Routing bases and states as the substrate spells them (never re-spelled here).
ROUTING_REQUIRED = "ROUTING_REQUIRED"
READY_TO_SEND = "READY_TO_SEND"
BASIS_COUNSEL = "NO_EVIDENCED_COUNSEL_IDENTITY"
BASIS_CONTROLLER = "NO_APPOINTED_CONTROLLER"


class SubstrateError(RuntimeError):
    """A required substrate object is missing or malformed — fail closed."""


def resolve_root(root: str | os.PathLike[str] | None = None) -> Path:
    if root is not None:
        return Path(root)
    env = os.environ.get(SUBSTRATE_ENV)
    if env:
        return Path(env)
    return DEFAULT_SUBSTRATE_ROOT


def _load_json(path: Path) -> Any:
    import json

    if not path.is_file():
        raise SubstrateError(f"substrate object missing: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise SubstrateError(f"substrate object unreadable: {path}: {exc}") from exc


def compute_critical_objects(root: Path) -> dict[str, dict[str, Any]]:
    """{relpath: {"sha256": hex|ABSENT, "bytes": int|None}} over the fixed set.

    ABSENT for anything not present. The caller decides whether ABSENT is a
    mismatch; this function only measures.
    """
    out: dict[str, dict[str, Any]] = {}
    for rel in CRITICAL_OBJECTS:
        p = root / rel
        digest = hash_file(p)
        out[rel] = {
            "sha256": digest,
            "bytes": (p.stat().st_size if digest != ABSENT else None),
        }
    return out


def derive_counts(root: Path) -> dict[str, int]:
    """Re-derive the headline counts from the live registries, read-only.

    Never reads a cached verification_report.json — every number here is
    computed from the request registry, the coverage graph, the mapping
    registry, and the requirement catalog directly (Section 18).
    """
    requests = _load_json(root / REL_REQUEST_REGISTRY).get("requests", [])
    edges = _load_json(root / REL_COVERAGE).get("edges", [])
    mappings = _load_json(root / REL_MAPPING).get("mappings", [])
    requirements = _load_json(root / REL_REQUIREMENTS).get("requirements", [])

    if not isinstance(requests, list) or not isinstance(mappings, list):
        raise SubstrateError("substrate registries are not lists")

    routing_required = sum(1 for r in requests if r.get("routing_state") == ROUTING_REQUIRED)
    ready_to_send = sum(1 for r in requests if r.get("routing_state") == READY_TO_SEND)
    counsel = sum(
        1
        for r in requests
        if r.get("routing_state") == ROUTING_REQUIRED and r.get("routing_basis") == BASIS_COUNSEL
    )
    controller = sum(
        1
        for r in requests
        if r.get("routing_state") == ROUTING_REQUIRED and r.get("routing_basis") == BASIS_CONTROLLER
    )
    # A recipient is "invented" iff a request names an authority identity that
    # is not backed by an evidenced-identity reference. In the pristine
    # substrate every authority_identity_ref is null → 0.
    recipients_invented = sum(
        1 for r in requests if r.get("authority_identity_ref") not in (None, "")
    )
    rights_assertions = sum(1 for r in requests if r.get("rights_assertion") is not None)

    asset_ids: set[str] = set()
    for m in mappings:
        if isinstance(m.get("asset_id"), str):
            asset_ids.add(m["asset_id"])

    return {
        "requirements": len(requirements),
        "assets": len(asset_ids),
        "mappings": len(mappings),
        "source_request_required": sum(
            1 for m in mappings if m.get("status") == "REQUEST_REQUIRED"
        ),
        "source_blocked": sum(1 for m in mappings if m.get("status") == "BLOCKED"),
        "requests": len(requests),
        "coverage_edges": len(edges),
        "routing_required": routing_required,
        "ready_to_send": ready_to_send,
        "no_evidenced_counsel_identity": counsel,
        "no_appointed_controller": controller,
        "rights_assertions": rights_assertions,
        "recipients_invented": recipients_invented,
    }


def load_requests(root: Path) -> list[dict[str, Any]]:
    """The 340 request records, read-only."""
    reqs = _load_json(root / REL_REQUEST_REGISTRY).get("requests", [])
    if not isinstance(reqs, list):
        raise SubstrateError("request registry .requests is not a list")
    return reqs
