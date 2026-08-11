"""Scope-aware authority router.

Maps verified external authority evidence onto the substrate's request records
and derives request-level transitions. It is the only place a request may leave
ROUTING_REQUIRED, and it does so only when a real, verified, in-effect,
scope-matching authority record exists. It never edits an aggregate counter
(Section 11) and never writes a rights_assertion (Section 7 / invariant I7).

Authority classes and the routing basis each may satisfy — and ONLY that basis
(invariants I4 / Section 9):

    DATA_CONTROLLER             -> NO_APPOINTED_CONTROLLER
    COUNSEL_OR_RIGHTS_AUTHORITY -> NO_EVIDENCED_COUNSEL_IDENTITY

Identity known is not authority (I2): a record must be AUTHORITY_EVIDENCED, not
merely IDENTITY_EVIDENCED. Authority without matching scope is insufficient
(I3). Controller authority never covers a counsel-routed request and vice versa.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from _canonical import sha256_hex
from _substrate import BASIS_CONTROLLER, BASIS_COUNSEL, READY_TO_SEND, ROUTING_REQUIRED
from authority_receipt import (
    ReceiptError,
    ReplayLedger,
    mint_receipt,
    substrate_binding_valid,
)

DATA_CONTROLLER = "DATA_CONTROLLER"
COUNSEL_OR_RIGHTS_AUTHORITY = "COUNSEL_OR_RIGHTS_AUTHORITY"
AUTHORITY_TYPES = {DATA_CONTROLLER, COUNSEL_OR_RIGHTS_AUTHORITY}

# Verification states an evidence record may carry. Only AUTHORITY_EVIDENCED is
# routable; IDENTITY_EVIDENCED means the person/entity is known but authority is
# not established.
IDENTITY_EVIDENCED = "IDENTITY_EVIDENCED"
AUTHORITY_EVIDENCED = "AUTHORITY_EVIDENCED"
VERIFICATION_STATES = {IDENTITY_EVIDENCED, AUTHORITY_EVIDENCED}

# Intermediate lifecycle state (Section 12).
ROUTING_RESOLVED = "ROUTING_RESOLVED"

_BASIS_FOR_CLASS = {
    DATA_CONTROLLER: BASIS_CONTROLLER,
    COUNSEL_OR_RIGHTS_AUTHORITY: BASIS_COUNSEL,
}

_REQUIRED_EVIDENCE_FIELDS = (
    "authority_evidence_id",
    "authority_type",
    "subject_identity",
    "authority_scope",
    "source_type",
    "source_reference",
    "source_digest",
    "effective_from",
    "verification_state",
)


class EvidenceError(ValueError):
    """An authority evidence record is malformed — reject, do not ingest."""


def validate_evidence(record: dict[str, Any]) -> None:
    """Structural validation. Rejects unknown authority types and missing
    fields. Does not establish that the underlying legal fact is true — only
    that the record is well formed and names a real source."""
    if not isinstance(record, dict):
        raise EvidenceError("evidence record is not an object")
    missing = [f for f in _REQUIRED_EVIDENCE_FIELDS if f not in record]
    if missing:
        raise EvidenceError(f"missing required fields: {missing}")
    if record["authority_type"] not in AUTHORITY_TYPES:
        raise EvidenceError(f"unknown authority_type: {record['authority_type']!r}")
    if record["verification_state"] not in VERIFICATION_STATES:
        raise EvidenceError(f"unknown verification_state: {record['verification_state']!r}")
    scope = record["authority_scope"]
    if not isinstance(scope, dict) or "asset_ids" not in scope or "requirement_ids" not in scope:
        raise EvidenceError("authority_scope must carry asset_ids and requirement_ids")
    for field_name in ("asset_ids", "requirement_ids"):
        value = scope[field_name]
        if value == "ALL":
            continue
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise EvidenceError(
                f'authority_scope.{field_name} must be "ALL" or a list of id strings'
            )
    for k in ("subject_identity", "source_reference", "source_digest"):
        if not isinstance(record[k], str) or not record[k].strip():
            raise EvidenceError(
                f"{k} must be a non-empty string (a real, named source is required)"
            )


def source_digest_matches(record: dict[str, Any], document_bytes: bytes) -> bool:
    """True iff the recorded source_digest equals sha256 of the actual document
    bytes. A document altered after ingestion fails this (attack 11)."""
    return sha256_hex(document_bytes) == record.get("source_digest")


def source_artifact_intact(record: dict[str, Any], artifact_dir: Path) -> bool:
    """True iff the retained source artifact for this record is on file and its
    bytes still hash to the recorded source_digest. Ingestion retains the
    artifact bytes under `<artifact_dir>/<source_digest>`; routing eligibility
    re-verifies them here, so a source document altered or removed after
    ingestion stops routing (fail closed) instead of surviving as an
    unverifiable digest string."""
    digest = record.get("source_digest")
    if not isinstance(digest, str) or not digest.strip():
        return False
    if "/" in digest or "\\" in digest or ".." in digest:
        return False
    artifact = artifact_dir / digest
    if not artifact.is_file():
        return False
    try:
        return source_digest_matches(record, artifact.read_bytes())
    except OSError:
        return False


def _parse_z(s: Any) -> datetime | None:
    """Strict Z-suffixed ISO-8601 UTC instant, or None. Anything the format
    does not exactly match — offsets, fractional seconds, garbage after a
    lexicographically large prefix — is not comparable and fails closed."""
    if not isinstance(s, str):
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def in_effect(record: dict[str, Any], instant: str | None) -> bool:
    """Temporal + revocation gate (invariant I12). Fails closed when the instant
    cannot be established, any timestamp fails strict UTC parsing, or the record
    is revoked/expired. Comparison is on parsed datetimes, never raw strings."""
    if record.get("revoked_at"):
        return False
    now = _parse_z(instant)
    if now is None:
        return False
    frm = _parse_z(record.get("effective_from"))
    if frm is None or now < frm:
        return False
    eu = record.get("effective_until")
    if eu is not None:
        eu_dt = _parse_z(eu)
        if eu_dt is None or now >= eu_dt:
            return False
    return True


def _scope_covers(record: dict[str, Any], request: dict[str, Any]) -> bool:
    scope = record["authority_scope"]
    assets = scope["asset_ids"]
    reqs = scope["requirement_ids"]
    req_assets = set(request.get("covered_asset_ids", []))
    if assets != "ALL":
        if not isinstance(assets, list) or not req_assets.issubset(set(assets)):
            return False
    if reqs != "ALL":
        if not isinstance(reqs, list) or request.get("requirement_id") not in reqs:
            return False
    return True


def evidence_covers_request(
    record: dict[str, Any], request: dict[str, Any], instant: str | None
) -> bool:
    """All conditions for an evidence record to legitimately resolve a request."""
    if record.get("verification_state") != AUTHORITY_EVIDENCED:  # I2
        return False
    basis = _BASIS_FOR_CLASS.get(record["authority_type"])
    if basis is None or request.get("routing_basis") != basis:  # I4
        return False
    if request.get("routing_state") != ROUTING_REQUIRED:
        return False
    if not in_effect(record, instant):  # I12
        return False
    return _scope_covers(record, request)  # I3


@dataclass
class RouteResult:
    request_final_state: dict[str, str]
    transitions: list[dict[str, Any]] = field(default_factory=list)
    rights_assertions_created: int = 0
    recipients_invented: int = 0


def route(
    requests: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    *,
    substrate_identity: str,
    substrate_digest: str,
    key: bytes,
    eval_instant: str | None,
    replay: ReplayLedger | None = None,
) -> RouteResult:
    """Derive transitions. Deterministic in request and evidence order.

    A fully resolvable request produces two receipted transitions:
    ROUTING_REQUIRED -> ROUTING_RESOLVED -> READY_TO_SEND. rights_assertion is
    never touched (I7); no recipient is fabricated (I10) — the recipient is the
    evidenced subject_identity from a real record or nothing.
    """
    result = RouteResult(
        request_final_state={
            request.get("request_id", ""): request.get("routing_state", ROUTING_REQUIRED)
            for request in requests
        }
    )
    if not substrate_binding_valid(substrate_identity, substrate_digest):
        return result
    replay = replay or ReplayLedger()
    verified_evidence = sorted(
        (e for e in evidence), key=lambda e: e.get("authority_evidence_id", "")
    )

    for request in requests:
        rid = request.get("request_id", "")
        state = request.get("routing_state", ROUTING_REQUIRED)
        result.request_final_state[rid] = state
        if state != ROUTING_REQUIRED:
            continue
        match = next(
            (e for e in verified_evidence if evidence_covers_request(e, request, eval_instant)),
            None,
        )
        if match is None:
            continue
        # I7 guard: never resolve a request that already carries a rights
        # assertion, and never create one.
        if request.get("rights_assertion") is not None:
            continue

        subject = match.get("subject_identity", "")
        scope = match["authority_scope"]
        ev_id = match["authority_evidence_id"]
        ev_digest = match["source_digest"]
        # Mint-then-consume atomically per request: both receipts are minted
        # first, then consumed against the replay ledger as ONE batch under a
        # single ledger lock. If either receipt is a replay (already consumed
        # in a prior evaluation against a persistent ledger), NEITHER is
        # recorded and the whole request stays in its prior state — a request
        # never half-advances, even against a concurrent evaluation racing on
        # the same persistent ledger (fail closed).
        minted = []
        for prior, new in ((ROUTING_REQUIRED, ROUTING_RESOLVED), (ROUTING_RESOLVED, READY_TO_SEND)):
            minted.append(
                mint_receipt(
                    key,
                    request_id=rid,
                    prior_state=prior,
                    new_state=new,
                    authority_subject=subject,
                    authority_evidence_id=ev_id,
                    evidence_digest=ev_digest,
                    authority_scope=scope,
                    substrate_identity=substrate_identity,
                    substrate_critical_set_digest=substrate_digest,
                    decision="ALLOW",
                    decision_reason=f"{match['authority_type']} evidence covers {rid} in scope",
                    created_at=eval_instant or "",
                )
            )
        try:
            replay.consume_many([receipt["receipt_id"] for receipt in minted])
        except ReceiptError:
            continue
        result.transitions.extend(minted)
        result.request_final_state[rid] = minted[-1]["new_state"]

    return result


def derived_counts(
    base_requests: list[dict[str, Any]], final_state: dict[str, str]
) -> dict[str, int]:
    """Aggregate counters as a pure function of the request records overlaid
    with routing transitions (invariant I8). Never stored, always recomputed."""
    routing_required = 0
    ready_to_send = 0
    counsel = 0
    controller = 0
    for r in base_requests:
        rid = r.get("request_id", "")
        st = final_state.get(rid, r.get("routing_state"))
        if st == READY_TO_SEND:
            ready_to_send += 1
        elif st == ROUTING_REQUIRED:
            routing_required += 1
            if r.get("routing_basis") == BASIS_COUNSEL:
                counsel += 1
            elif r.get("routing_basis") == BASIS_CONTROLLER:
                controller += 1
    return {
        "routing_required": routing_required,
        "ready_to_send": ready_to_send,
        "no_evidenced_counsel_identity": counsel,
        "no_appointed_controller": controller,
    }
