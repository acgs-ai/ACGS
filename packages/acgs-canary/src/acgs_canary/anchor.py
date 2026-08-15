"""External anchoring — the answer to publisher self-attestation.

The anchor-of-record is EXTERNAL timestamp evidence (RFC 3161 or
OpenTimestamps). A repository commit or Hugging Face mirror is
supplementary metadata only and never satisfies the independent-anchor
requirement by itself: the mirror is owned by the same party the anchor
exists to constrain.

R0 implements the interface, the canonical anchor bundle, state tracking,
and a fixture-backed verifier for tests. It deliberately does NOT
implement a production RFC 3161 / OpenTimestamps client: no fake timestamp
authority, and no self-signed timestamp, can be represented as production
evidence. Production adapters arrive with R1 and must verify real TSA
signatures / Bitcoin attestations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from .canonical import canonical_bytes, canonical_sha256_hex
from .errors import AnchorError
from .protocol import protocol_hash

BUNDLE_SCHEMA = "acgs_canary_anchor_bundle/v1"

KIND_RFC3161 = "rfc3161"
KIND_OTS = "opentimestamps"
KIND_MIRROR = "mirror"
_INDEPENDENT_KINDS = frozenset({KIND_RFC3161, KIND_OTS})
_ALL_KINDS = _INDEPENDENT_KINDS | {KIND_MIRROR}

STATE_REQUESTED = "requested"
STATE_SUBMITTED = "submitted"
STATE_CONFIRMED = "confirmed"
STATE_FAILED = "failed"
STATE_INVALID = "expired_or_invalid"
_STATES = frozenset(
    {STATE_REQUESTED, STATE_SUBMITTED, STATE_CONFIRMED, STATE_FAILED, STATE_INVALID}
)


def build_anchor_bundle(
    *,
    ledger_head_hash: str,
    pool_manifest_sha256: str,
    protocol_sha256: str,
    commitment_roots_hex: list[str],
    created_at: str,
) -> dict[str, Any]:
    """The canonical payload whose hash gets timestamped.

    Binds everything the design requires anchored: the ledger head, the
    pool manifest, T1 commitment roots (roots only — no licensee data),
    and the frozen protocol hash.
    """
    bundle = {
        "schema": BUNDLE_SCHEMA,
        "ledger_head_hash": ledger_head_hash,
        "pool_manifest_sha256": pool_manifest_sha256,
        "protocol_sha256": protocol_sha256,
        "commitment_roots_hex": sorted(commitment_roots_hex),
        "created_at": created_at,
    }
    validate_bundle(bundle)
    return bundle


_BUNDLE_FIELDS = frozenset(
    {
        "schema",
        "ledger_head_hash",
        "pool_manifest_sha256",
        "protocol_sha256",
        "commitment_roots_hex",
        "created_at",
    }
)


def validate_bundle(bundle: dict[str, Any]) -> None:
    """Fail-closed structural validation of a supplied anchor bundle.

    Bundles reach hashing/recording paths from outside
    :func:`build_anchor_bundle` (e.g. read back from disk), so every field
    is enforced here: exact field set, digest formats, sorted commitment
    roots, and a parseable creation time. An incomplete dictionary must
    never be hashable or recordable.
    """
    if not isinstance(bundle, dict) or bundle.get("schema") != BUNDLE_SCHEMA:
        raise AnchorError("not an anchor bundle")
    keys = set(bundle)
    if keys != _BUNDLE_FIELDS:
        raise AnchorError(
            "anchor bundle field set mismatch "
            f"(missing {sorted(_BUNDLE_FIELDS - keys)}, unknown {sorted(keys - _BUNDLE_FIELDS)})"
        )
    for field in ("ledger_head_hash", "pool_manifest_sha256", "protocol_sha256"):
        _require_hex64(bundle[field], field)
    # Frozen-protocol binding: a bundle citing a foreign protocol identity
    # must never be hashable, serializable, or recordable — otherwise a
    # bundle built outside anchor-prepare could be anchored for a current
    # ledger head while binding a different protocol than the ledger and
    # package enforce (manifests and ledgers already refuse this).
    if bundle["protocol_sha256"] != protocol_hash():
        raise AnchorError(
            "anchor bundle is bound to a foreign protocol identity; refusing to hash or record it"
        )
    roots = bundle["commitment_roots_hex"]
    if not isinstance(roots, list):
        raise AnchorError("commitment_roots_hex must be a list")
    for root in roots:
        _require_hex64(root, "commitment_root")
    if roots != sorted(roots):
        raise AnchorError("commitment_roots_hex must be sorted (canonical order)")
    created_at = bundle["created_at"]
    if not isinstance(created_at, str):
        raise AnchorError("created_at must be an ISO-8601 string")
    _parse_ts(created_at, "created_at")


def bundle_hash(bundle: dict[str, Any]) -> str:
    validate_bundle(bundle)
    return canonical_sha256_hex(bundle)


def _require_hex64(value: Any, field: str) -> None:
    if not (isinstance(value, str) and len(value) == 64):
        raise AnchorError(f"{field} must be 64 hex chars")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise AnchorError(f"{field} is not hex") from exc


@dataclass(frozen=True)
class AnchorEvidence:
    """One piece of anchor evidence for a bundle hash."""

    kind: str
    state: str
    bundle_sha256: str
    evidence_ref: str  # opaque pointer (fixture id, TSA response path, OTS proof path)
    anchored_at: str | None  # asserted anchor time, verification-dependent
    production: bool  # True only for real external evidence (never in R0)

    def __post_init__(self) -> None:
        if self.kind not in _ALL_KINDS:
            raise AnchorError(f"unknown anchor kind: {self.kind!r}")
        if self.state not in _STATES:
            raise AnchorError(f"unknown anchor state: {self.state!r}")
        _require_hex64(self.bundle_sha256, "bundle_sha256")
        # production gates the "anchored" vs "anchored-non-production"
        # label: a truthy non-bool (e.g. the string "false" from a JSON-ish
        # boundary) must never be accepted and later read as production.
        if not isinstance(self.production, bool):
            raise AnchorError("production must be exactly a bool")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "state": self.state,
            "bundle_sha256": self.bundle_sha256,
            "evidence_ref": self.evidence_ref,
            "anchored_at": self.anchored_at,
            "production": self.production,
        }


class AnchorVerifier(Protocol):
    """Adapter interface. Production implementations must verify real TSA
    signatures / OTS Bitcoin attestations; R0 ships only FixtureVerifier."""

    def verify(self, evidence: AnchorEvidence, bundle: dict[str, Any]) -> bool: ...


class FixtureVerifier:
    """Test-only verifier over recorded fixtures.

    Explicitly non-production: it refuses evidence marked production=True,
    so a fixture can never masquerade as real external evidence, and
    evidence it confirms stays labeled non-production.
    """

    production_safe = False

    def __init__(self, fixtures: dict[str, dict[str, Any]]) -> None:
        # fixtures: evidence_ref -> {"bundle_sha256": ..., "anchored_at": ...}
        self._fixtures = fixtures

    def verify(self, evidence: AnchorEvidence, bundle: dict[str, Any]) -> bool:
        if evidence.production:
            raise AnchorError(
                "FixtureVerifier cannot verify production evidence; "
                "a real RFC3161/OTS verifier is required"
            )
        fx = self._fixtures.get(evidence.evidence_ref)
        if fx is None:
            return False
        if fx.get("bundle_sha256") != bundle_hash(bundle):
            return False
        if fx.get("bundle_sha256") != evidence.bundle_sha256:
            return False
        # The anchor time must be the recorded fixture time: evidence
        # asserting a different (e.g. earlier) anchored_at is a forgery,
        # not a confirmation. Fixtures without a recorded time verify only
        # evidence that likewise asserts none.
        if fx.get("anchored_at") != evidence.anchored_at:
            return False
        return evidence.state == STATE_CONFIRMED


class ProductionAnchorUnavailable:
    """R0 placeholder for the production adapter slot: always refuses.

    Prevents any code path from treating R0 as capable of producing
    production anchor evidence.
    """

    production_safe = True

    def verify(self, evidence: AnchorEvidence, bundle: dict[str, Any]) -> bool:
        raise AnchorError(
            "production anchor verification is not available in R0; "
            "RFC3161/OpenTimestamps adapters arrive with R1"
        )


def _parse_ts(value: str, field: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AnchorError(f"{field} is not an ISO-8601 timestamp") from exc
    if dt.tzinfo is None:
        raise AnchorError(f"{field} must be timezone-aware")
    return dt.astimezone(UTC)


def parse_anchor_time(value: str) -> datetime:
    """Parse an asserted anchor time; refuses malformed or naive timestamps.

    Used by the ledger's verified labeling path: confirmed evidence without
    a parseable, timezone-aware anchor time can never be labeled anchored.
    """
    return _parse_ts(value, "anchored_at")


def anchor_predates(
    evidence: AnchorEvidence,
    bundle: dict[str, Any],
    *,
    observation_time: str,
    verifier: AnchorVerifier,
) -> bool:
    """The dispute-time question: does confirmed independent evidence for
    this bundle predate the observation?

    Fail closed: mirror evidence never satisfies this; unconfirmed or
    unverifiable evidence never satisfies this.
    """
    if evidence.kind not in _INDEPENDENT_KINDS:
        raise AnchorError(
            "mirror metadata is supplementary only; it cannot satisfy the "
            "independent-anchor requirement"
        )
    if evidence.state != STATE_CONFIRMED:
        return False
    if evidence.anchored_at is None:
        return False
    # Bind the evidence to THIS bundle before consulting the verifier:
    # a verifier that only validates the timestamp proof named by the
    # evidence would otherwise let confirmed evidence for bundle A be
    # reused to answer the dispute question for bundle B.
    if evidence.bundle_sha256 != bundle_hash(bundle):
        return False
    if not verifier.verify(evidence, bundle):
        return False
    anchored = _parse_ts(evidence.anchored_at, "anchored_at")
    observed = _parse_ts(observation_time, "observation_time")
    return anchored < observed


# NOTE: there is deliberately no free-standing evidence-label helper here.
# Evidence labels ("publisher-testimony" / "anchor-entry-recorded" /
# "anchored" / "anchored-non-production") are emitted only by the ledger:
# the structural fold caps at "anchor-entry-recorded", and "anchored"
# requires AcceptanceLedger.anchored_issuance_state running a real verifier.
# A label derived from evidence metadata alone would be fabricable.


def serialize_bundle(bundle: dict[str, Any]) -> bytes:
    validate_bundle(bundle)
    return canonical_bytes(bundle)
