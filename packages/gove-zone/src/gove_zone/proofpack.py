"""ACGS Proof Pack: enterprise evidence bundle for one governed action.

A **proof pack** is a portable, self-describing directory of evidence that one
governed action was policy-checked before execution and that the record of that
check is intact. It is built for three audiences at once:

- **engineers** get machine-readable JSON artifacts plus a one-command verify;
- **auditors** get a per-file integrity manifest (``evidence.json``) and a
  human-readable ``verification-summary.md`` stating exactly what is and is
  not proven;
- **regulators** get a plain-language summary section with no jargon.

Layout (schema ``acgs/proof-pack/v1``)::

    proofpack/
    ├── evidence.json             # manifest: action, actor, policy, sha256 digests
    ├── decision-receipt.json     # the Decision Receipt, verbatim
    ├── audit-chain.json          # the hash-linked audit events (chain order)
    ├── replay-report.json        # decision re-derivation result (or not_available)
    └── verification-summary.md   # human-readable summary for auditors/regulators

Relationship to the conformance pack (``gove-zone proofpack``) and the offline
verifier (:mod:`gove_zone.verifier`): this module packages the evidence of a
*specific* governed action, while the conformance pack demonstrates the gate
matrix. Verification here **reuses** :func:`gove_zone.verifier.verify_proof_pack`
verbatim — the pack is materialised into the ``gove-zone/proof-pack/v1`` shape
in a temporary directory and handed to the existing hardened verifier, so there
is exactly one receipt/chain verification code path in the codebase.

Independence (mirrors verifier.py §5.4): module-scope imports are restricted to
the receipt/verify surface. The decision-replay tier needs the policy engine;
those imports are **lazy**, performed only when replay material is supplied.
A static AST guard test pins this boundary.

Fail-closed: :func:`verify_pack` never raises — every failure path resolves to
``valid=False`` with a stable reason code. :func:`generate_proof_pack` refuses
to mint an evidence bundle from inconsistent inputs (broken chain, unanchored
or binding-broken receipt, failed replay): an evidence bundle that contradicts
itself is worse than none.

Leak-safety: the pack carries the receipt, the audit events, and a replay
*report* — never the raw arguments or the replay side store. Re-deriving the
decisions requires the relying party to supply the policy bundle and side
store out-of-band at verify time.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gove_zone.audit import GENESIS_HASH, ChainHashAuditStore
from gove_zone.decision import sha256_json
from gove_zone.receipt import DecisionReceipt
from gove_zone.verifier import (
    SCHEMA_VERSION as INNER_SCHEMA_VERSION,
)
from gove_zone.verifier import (
    ProofPackVerificationResult,
    verify_proof_pack,
)

if TYPE_CHECKING:
    from gove_zone.revocation import RevocationList

PACK_SCHEMA_VERSION = "acgs/proof-pack/v1"
GENERATED_WITH = "acgs proofpack generate (gove_zone.proofpack)"

EVIDENCE_FILE = "evidence.json"
RECEIPT_FILE = "decision-receipt.json"
AUDIT_CHAIN_FILE = "audit-chain.json"
REPLAY_REPORT_FILE = "replay-report.json"
SUMMARY_FILE = "verification-summary.md"

# The artifacts whose digests evidence.json binds. evidence.json cannot contain
# its own digest (self-reference), so it is the manifest, not a member.
ARTIFACT_FILES = (RECEIPT_FILE, AUDIT_CHAIN_FILE, REPLAY_REPORT_FILE, SUMMARY_FILE)

# Decisions whose receipts self-validate as executable ("accept" verdicts in the
# offline verifier's vocabulary). DENY/ESCALATE receipts are evidence of a block,
# and verify() raises on them by design — they are declared "reject".
_ACCEPT_DECISIONS = frozenset({"allow", "transform"})


class PackGenerationError(Exception):
    """Raised when the inputs cannot honestly be packaged as evidence."""


class PackRejectionReason(StrEnum):
    """Stable, machine-readable pack-level failure codes.

    Failures found by the inner receipt/chain verifier surface their own codes
    verbatim (see :class:`gove_zone.verifier.ProofPackRejectionReason` and
    :class:`gove_zone.errors.ReceiptRejectionReason`); these cover the ACGS
    pack envelope (evidence manifest, artifact integrity, cross-binding,
    replay re-derivation).
    """

    PACK_NOT_FOUND = "PACK_NOT_FOUND"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    EVIDENCE_MALFORMED = "EVIDENCE_MALFORMED"
    SCHEMA_VERSION_MISSING = "SCHEMA_VERSION_MISSING"
    SCHEMA_VERSION_UNSUPPORTED = "SCHEMA_VERSION_UNSUPPORTED"
    ARTIFACT_MISSING = "ARTIFACT_MISSING"
    ARTIFACT_DIGEST_MISMATCH = "ARTIFACT_DIGEST_MISMATCH"
    RECEIPT_BINDING_MISMATCH = "RECEIPT_BINDING_MISMATCH"
    EVIDENCE_BINDING_MISMATCH = "EVIDENCE_BINDING_MISMATCH"
    SUMMARY_BINDING_MISMATCH = "SUMMARY_BINDING_MISMATCH"
    AUDIT_CHAIN_MALFORMED = "AUDIT_CHAIN_MALFORMED"
    AUDIT_BINDING_MISMATCH = "AUDIT_BINDING_MISMATCH"
    REPLAY_REPORT_MALFORMED = "REPLAY_REPORT_MALFORMED"
    REPLAY_MATERIAL_MALFORMED = "REPLAY_MATERIAL_MALFORMED"
    REPLAY_MISMATCH = "REPLAY_MISMATCH"
    VERIFIER_ERROR = "VERIFIER_ERROR"


@dataclass(frozen=True)
class PackVerificationResult:
    """Structured, fail-closed verification verdict for one ACGS proof pack.

    ``valid`` is the single gate a relying party keys on. ``integrity_status``
    is the artifact-digest verdict (``intact`` / ``tampered`` / ``incomplete``).
    ``receipt_and_chain`` is the untouched inner verdict from
    :func:`gove_zone.verifier.verify_proof_pack`. ``replay_status`` is one of
    ``recorded`` (a generate-time report is present but not re-derived),
    ``reverified`` (re-derived now from out-of-band material), ``failed``,
    or ``not_available``.
    """

    valid: bool
    schema_version: str | None
    integrity_status: str  # "intact" | "tampered" | "incomplete" | "unknown"
    receipt_and_chain: ProofPackVerificationResult | None
    replay_status: str
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "schema_version": self.schema_version,
            "integrity_status": self.integrity_status,
            "receipt_and_chain": (
                self.receipt_and_chain.to_dict() if self.receipt_and_chain else None
            ),
            "replay_status": self.replay_status,
            "reasons": list(self.reasons),
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dump_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _declared_verdict(receipt: DecisionReceipt) -> str:
    return "accept" if receipt.decision in _ACCEPT_DECISIONS else "reject"


def _receipt_evidence_sections(receipt: DecisionReceipt) -> dict[str, dict[str, Any]]:
    """The evidence.json sections that are DERIVED from the receipt.

    Single source of truth for both generation (these sections are written into
    ``evidence.json``) and verification (tier 3 re-derives them from the
    hash-protected receipt and requires strict equality). ``evidence.json``
    cannot carry its own digest, so every receipt-derived claim it makes must be
    re-checkable against the receipt — this helper is what makes a forged
    ``governed_action`` / ``actor`` / ``policy`` section detectable.
    """
    return {
        "governed_action": {
            "proposed_action": receipt.proposed_action,
            "declared_goal": receipt.declared_goal,
            "execution_boundary": receipt.execution_boundary,
            "decision": receipt.decision,
            "matched_rules": list(receipt.matched_rules),
        },
        "actor": {
            "id": receipt.actor,
            "tenant_id": receipt.tenant_id,
            "authority": receipt.authority,
            "validator_id": receipt.validator_id,
            "validator_role": receipt.validator_role,
        },
        "policy": {
            "bundle_id": receipt.policy_bundle_id,
            "version": receipt.policy_version,
            "hash": receipt.policy_hash,
        },
        "receipt": {
            "receipt_id": receipt.receipt_id,
            "request_id": receipt.request_id,
            "receipt_hash": receipt.receipt_hash,
            "audit_event_hash": receipt.audit_event_hash,
            "signature_algorithm": receipt.signature_algorithm,
            "signing_key_id": receipt.signing_key_id,
        },
    }


# --- generation ---------------------------------------------------------------


def _run_replay(audit_path: Path, policy_bundle: Path, side_store: Path) -> dict[str, Any]:
    """Re-derive every decision in the chain (lazy engine import)."""
    from gove_zone.policy import RuleSetPolicy
    from gove_zone.replay import replay_bundle
    from gove_zone.replay_store import ReplaySideStore

    policy = RuleSetPolicy.load(policy_bundle)
    side = ReplaySideStore(side_store)
    return replay_bundle(ChainHashAuditStore(audit_path), side, policy)


def generate_proof_pack(
    out_dir: str | Path,
    *,
    receipt_path: str | Path,
    audit_path: str | Path,
    policy_bundle: str | Path | None = None,
    side_store: str | Path | None = None,
    now_iso: str | None = None,
    force: bool = False,
    constitution_path: str | Path | None = None,
    constitution_registry_id: str | None = None,
) -> dict[str, Any]:
    """Generate an ACGS proof pack for one governed action.

    Args:
        out_dir: directory to create (must not already contain a pack unless
            ``force``).
        receipt_path: the governed action's Decision Receipt JSON.
        audit_path: the audit chain JSONL the receipt is anchored in.
        policy_bundle: optional RuleSetPolicy bundle JSON. Together with
            ``side_store`` it enables the decision-replay tier.
        side_store: optional replay side store JSONL (raw retained arguments).
        now_iso: injected generation timestamp for deterministic output;
            defaults to the wall clock.
        force: overwrite pack files already present in ``out_dir``.
        constitution_path: optional path to the governing constitution JSON. When
            supplied, its canonical-JSON SHA-256 (``sha256_json`` — the same
            canonicalization used for every other hash) is stamped into the
            OPTIONAL ``evidence.constitution`` block so a relying party can cross-
            check it against a trusted constitution-hash registry at verify time.
            Omitted -> the ``constitution`` key is absent (frozen-v1 back-compat).
        constitution_registry_id: optional identifier of the registry the
            constitution hash is expected to appear in; recorded verbatim under
            ``evidence.constitution.registry_id`` when a constitution is stamped.

    Returns:
        A summary dict: ``{"status": "pass", "output_directory": ..., "files",
        "preflight"}``.

    Raises:
        PackGenerationError: when the inputs are inconsistent — broken chain,
            malformed or unanchored receipt, broken receipt-hash binding, or a
            failed replay. Fail-closed: an evidence bundle is only minted from
            inputs that actually cohere.
    """
    receipt_path = Path(receipt_path)
    audit_path = Path(audit_path)
    out = Path(out_dir)

    if (policy_bundle is None) != (side_store is None):
        raise PackGenerationError("replay material requires BOTH --policy-bundle and --side-store")

    # --- pre-flight: refuse to package evidence that contradicts itself -------
    try:
        receipt = DecisionReceipt.from_json(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise PackGenerationError(f"cannot load receipt {receipt_path}: {exc}") from exc

    if not receipt.receipt_hash or receipt.compute_hash() != receipt.receipt_hash:
        raise PackGenerationError(
            "receipt_hash binding is broken: the receipt's bound fields do not "
            "re-hash to receipt_hash — refusing to package tampered input"
        )

    store = ChainHashAuditStore(audit_path)
    try:
        chain = store.verify_chain()
        events = list(store.iter_events())
    except Exception as exc:  # noqa: BLE001 — unreadable chain must not become evidence
        raise PackGenerationError(f"cannot read audit chain {audit_path}: {exc}") from exc
    if not chain["valid"]:
        raise PackGenerationError(
            f"audit chain fails verification ({len(chain['failures'])} failure(s)) — "
            "refusing to package a broken chain as evidence"
        )
    event_hashes = {e.get("event_hash") for e in events}
    if receipt.audit_event_hash not in event_hashes:
        raise PackGenerationError(
            "receipt is not anchored in the supplied audit chain "
            "(audit_event_hash not found) — refusing to package unanchored evidence"
        )

    replay_report: dict[str, Any]
    if policy_bundle is not None and side_store is not None:
        try:
            replay_result = _run_replay(audit_path, Path(policy_bundle), Path(side_store))
        except Exception as exc:  # noqa: BLE001 — malformed replay material is a refusal
            raise PackGenerationError(f"cannot run decision replay: {exc}") from exc
        if not replay_result.get("valid"):
            raise PackGenerationError(
                "decision replay FAILED: the re-derived decisions do not match the "
                "recorded chain — refusing to package contradictory evidence"
            )
        replay_report = {
            "schema_version": PACK_SCHEMA_VERSION,
            "status": "verified",
            "note": (
                "Every decision in the audit chain was re-derived from the retained "
                "raw arguments at generation time and byte-matched the recorded "
                "decision. Re-derivation at verify time requires the policy bundle "
                "and side store, supplied out-of-band (they are not in this pack)."
            ),
            "result": replay_result,
        }
    else:
        replay_report = {
            "schema_version": PACK_SCHEMA_VERSION,
            "status": "not_available",
            "note": (
                "No replay material (policy bundle + side store) was supplied at "
                "generation time, so decisions were not re-derived. Receipt and "
                "audit-chain integrity are still fully verifiable offline."
            ),
            "result": None,
        }

    # --- write the pack --------------------------------------------------------
    out.mkdir(parents=True, exist_ok=True)
    if not force:
        existing = [n for n in (EVIDENCE_FILE, *ARTIFACT_FILES) if (out / n).exists()]
        if existing:
            raise PackGenerationError(
                f"refusing to overwrite existing pack files in {out}: "
                f"{', '.join(existing)} (pass force=True / --force)"
            )

    from datetime import UTC, datetime

    if now_iso is None:
        now_iso = datetime.now(UTC).isoformat()
    else:
        try:
            datetime.fromisoformat(now_iso)
        except ValueError as exc:
            raise PackGenerationError(
                f"--now-iso is not a valid ISO-8601 timestamp: {exc}"
            ) from exc

    (out / RECEIPT_FILE).write_text(receipt.to_json() + "\n", encoding="utf-8", newline="\n")

    _dump_json(
        out / AUDIT_CHAIN_FILE,
        {
            "schema_version": PACK_SCHEMA_VERSION,
            "genesis_hash": GENESIS_HASH,
            "event_count": len(events),
            "last_hash": chain["last_hash"],
            "events": events,
        },
    )

    _dump_json(out / REPLAY_REPORT_FILE, replay_report)

    (out / SUMMARY_FILE).write_text(
        _render_summary(
            receipt=receipt,
            chain=chain,
            event_count=len(events),
            replay_report=replay_report,
            now_iso=now_iso,
        ),
        encoding="utf-8",
        newline="\n",
    )

    artifacts = {
        name: {
            "sha256": _sha256_file(out / name),
            "bytes": (out / name).stat().st_size,
        }
        for name in ARTIFACT_FILES
    }
    evidence = {
        "schema_version": PACK_SCHEMA_VERSION,
        "generated_at": now_iso,
        "generated_with": GENERATED_WITH,
        **_receipt_evidence_sections(receipt),
        "audit": {
            "event_count": len(events),
            "last_hash": chain["last_hash"],
        },
        "artifacts": artifacts,
        "how_to_verify": "acgs proofpack verify <pack-dir> [--verifier-key <pubkey>]",
    }
    # Optional, additive constitution stamp. Only present when a constitution
    # source is supplied, so existing packs/fixtures are byte-identical.
    if constitution_path is not None:
        try:
            constitution = json.loads(Path(constitution_path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise PackGenerationError(
                f"cannot load constitution {constitution_path}: {exc}"
            ) from exc
        constitution_block: dict[str, Any] = {"hash": sha256_json(constitution)}
        if constitution_registry_id is not None:
            constitution_block["registry_id"] = constitution_registry_id
        evidence["constitution"] = constitution_block
    _dump_json(out / EVIDENCE_FILE, evidence)

    return {
        "status": "pass",
        "output_directory": str(out),
        "files": [EVIDENCE_FILE, *ARTIFACT_FILES],
        "preflight": {
            "receipt_binding_intact": True,
            "audit_chain_valid": True,
            "receipt_anchored": True,
            "replay": replay_report["status"],
        },
    }


# --- human-readable summary -----------------------------------------------------


def _render_summary(
    *,
    receipt: DecisionReceipt,
    chain: dict[str, Any],
    event_count: int,
    replay_report: dict[str, Any],
    now_iso: str,
) -> str:
    signed = receipt.signature_algorithm != "none"
    decision = receipt.decision.upper()
    decision_line = (
        f"**{decision}** (executable)"
        if receipt.decision in _ACCEPT_DECISIONS
        else (
            f"**{decision}** (blocked — this receipt proves the action was NOT "
            "allowed to run as requested)"
        )
    )
    chain_line = f"{'PASS' if chain['valid'] else 'FAIL'} ({event_count} event(s), hash-linked)"
    replay_status = replay_report["status"]
    replay_line = {
        "verified": (
            "PASS (generator attestation) — every recorded decision was re-derived "
            "from retained raw arguments at generation time and matched the audit "
            "chain byte-for-byte. Re-derive independently at verify time with "
            "`--policy-bundle`/`--side-store`."
        ),
        "not_available": (
            "NOT AVAILABLE — no replay material was supplied at generation time; "
            "receipt and chain integrity remain independently verifiable."
        ),
    }[replay_status]
    signature_line = (
        f"signed ({receipt.signature_algorithm}, key `{receipt.signing_key_id}`) — "
        "verification requires the relying party's own copy of the public key "
        "(`--verifier-key`), never a key shipped inside this pack"
        if signed
        else (
            "UNSIGNED (development posture) — the receipt is tamper-evident via "
            "`receipt_hash` but carries no cryptographic signature; do not treat "
            "an unsigned pack as production evidence"
        )
    )

    return f"""# ACGS Proof Pack — Verification Summary

Generated: {now_iso}
Schema: `{PACK_SCHEMA_VERSION}`

## What this pack is

This directory is a self-contained evidence bundle for **one governed action**.
It documents that the action was checked against policy **before** execution,
what the decision was, and that the record of that decision is intact. It can
be verified offline, without access to the system that produced it, with:

```
acgs proofpack verify <this-directory>
```

## Outcome at a glance

| Check | Result |
|---|---|
| Governance decision | {decision_line} |
| Receipt integrity (`receipt_hash` binding) | PASS at generation time |
| Audit chain integrity | {chain_line} |
| Receipt anchored in audit chain | PASS at generation time |
| Decision replay (re-derivation) | {replay_line} |
| Signature | {signature_line} |

## The governed action

- **Action**: `{receipt.proposed_action}`
- **Declared goal**: {receipt.declared_goal or "(none declared)"}
- **Actor**: `{receipt.actor}` (tenant `{receipt.tenant_id}`)
- **Authority**: {receipt.authority or "(none recorded)"}
- **Execution boundary**: `{receipt.execution_boundary}`
- **Policy**: `{receipt.policy_bundle_id}` version `{receipt.policy_version}`
  (hash `{receipt.policy_hash}`)
- **Receipt**: `{receipt.receipt_id}` (request `{receipt.request_id}`)

## For engineers

- `decision-receipt.json` — the Decision Receipt. Its `receipt_hash` is a
  SHA-256 over the canonical JSON of every bound field (actor, action,
  argument hash, policy hash, decision, authority, ...). Change any field and
  the hash no longer matches.
- `audit-chain.json` — the audit events in chain order. Each event's
  `event_hash` is SHA-256 over the event minus the hash itself, and each
  `previous_hash` links to the prior event, back to a 64-zero genesis hash.
- `replay-report.json` — whether decisions were re-derived from retained raw
  arguments at generation time. Raw arguments are **not** in this pack.
- `evidence.json` — SHA-256 digests of the other four files, plus the action /
  actor / policy summary. Verification recomputes the digests AND re-derives
  every receipt-derived field from the hash-protected receipt, so an edit to
  any artifact — or to evidence.json's own descriptive sections — is detected.

## For auditors

What a passing verification **proves**:

1. The Decision Receipt's bound fields are exactly as issued (hash binding).
2. The audit chain is internally consistent and the receipt is anchored to a
   specific event in it.
3. `evidence.json`'s action / actor / policy sections and this summary's body
   (everything above the trailing generator footer) are re-derived from the
   hash-bound receipt and chain at verify time — a rewritten summary body or
   evidence file fails verification even if every file digest is recomputed
   to match.

What it does **not** prove:

- That the chain was not truncated after the anchored event (supply an
  out-of-band last-hash anchor to close this).
- That the clock or identity claims inside the receipt are true — those are
  attestations of the issuing system.
- The generation timestamp and the replay report's "verified at generation
  time" status are generator attestations: a consistent forgery of those two
  fields is not detectable offline. Independent replay re-derivation requires
  the policy bundle and side store, supplied out-of-band at verify time.
- An unsigned pack does not prove **who** issued the receipt. Only a signed
  receipt, checked against a public key you obtained independently of this
  pack, proves issuer identity.
- Which tool generated this pack. The trailing "Generated by ..." footer (and
  `generated_with` in `evidence.json`) is an unauthenticated generator
  attestation: it is not derived from the hash-bound receipt or chain, and
  offline verification accepts any known generator identity in its place, so
  it must not be read as authenticated provenance.

## For regulators (plain language)

Before this software action was carried out, an automated policy check decided
whether it was permitted. This bundle is the tamper-evident record of that
check: the decision itself (`{decision}`), the rule set used, who requested
it, and a cryptographic chain of log entries it belongs to. Anyone with this
folder and the free verification tool can re-check — without trusting the
operator — that none of these records were altered after the fact. It is the
software equivalent of a stamped, page-numbered logbook entry.

---
Generated by `{GENERATED_WITH}`.
"""


# --- verification ---------------------------------------------------------------


def _fail(
    reason: str,
    *,
    schema_version: str | None = None,
    integrity_status: str = "unknown",
) -> PackVerificationResult:
    return PackVerificationResult(
        valid=False,
        schema_version=schema_version,
        integrity_status=integrity_status,
        receipt_and_chain=None,
        replay_status="not_available",
        reasons=[reason],
    )


def verify_pack(
    pack_dir: str | Path,
    *,
    verifier: Any = None,
    require_signature: bool | None = None,
    now_iso: str | None = None,
    revoked_keys: RevocationList | None = None,
    policy_bundle: str | Path | None = None,
    side_store: str | Path | None = None,
) -> PackVerificationResult:
    """Verify an ACGS proof pack offline. Never raises; fail-closed.

    Verification tiers:

    1. **Integrity** — recompute the SHA-256 of every artifact and compare to
       ``evidence.json``. Any mismatch or missing file fails the pack.
    2. **Receipt + chain** — the receipt and audit events are materialised into
       the ``gove-zone/proof-pack/v1`` shape in a temporary directory and handed
       to :func:`gove_zone.verifier.verify_proof_pack` (single verification code
       path; same signature posture, anchoring, and fail-closed semantics).
    3. **Cross-binding** — ``evidence.json``'s recorded receipt hash and chain
       tail must match the artifacts they describe.
    4. **Replay (optional)** — when ``policy_bundle`` and ``side_store`` are
       supplied out-of-band, every decision is re-derived now; a recorded
       generate-time replay report alone is never treated as re-verification.

    Args mirror :func:`gove_zone.verifier.verify_proof_pack` for the trust
    anchor (``verifier``, ``require_signature``, ``now_iso``, ``revoked_keys``).
    """
    try:
        return _verify_pack_inner(
            Path(pack_dir),
            verifier=verifier,
            require_signature=require_signature,
            now_iso=now_iso,
            revoked_keys=revoked_keys,
            policy_bundle=policy_bundle,
            side_store=side_store,
        )
    except Exception:  # noqa: BLE001 — fail-closed: never let an exception become "accept".
        return _fail(PackRejectionReason.VERIFIER_ERROR)


def _verify_pack_inner(
    root: Path,
    *,
    verifier: Any,
    require_signature: bool | None,
    now_iso: str | None,
    revoked_keys: RevocationList | None,
    policy_bundle: str | Path | None,
    side_store: str | Path | None,
) -> PackVerificationResult:
    if not root.is_dir():
        return _fail(PackRejectionReason.PACK_NOT_FOUND)

    evidence_path = root / EVIDENCE_FILE
    if not evidence_path.is_file():
        return _fail(PackRejectionReason.EVIDENCE_MISSING)
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        if not isinstance(evidence, dict):
            raise ValueError("evidence is not an object")
    except (ValueError, OSError):
        return _fail(PackRejectionReason.EVIDENCE_MALFORMED)

    schema_version = evidence.get("schema_version")
    if not schema_version:
        return _fail(PackRejectionReason.SCHEMA_VERSION_MISSING)
    if schema_version != PACK_SCHEMA_VERSION:
        return _fail(PackRejectionReason.SCHEMA_VERSION_UNSUPPORTED, schema_version=schema_version)

    reasons: list[str] = []

    # Parse the replay report up front: tier 3 re-renders the summary from its
    # status and tier 4 reports it. A malformed report fails closed here.
    report_doc: dict[str, Any] | None = None
    report_path = root / REPLAY_REPORT_FILE
    if report_path.is_file():
        try:
            parsed = json.loads(report_path.read_text(encoding="utf-8"))
            if not isinstance(parsed, dict) or parsed.get("status") not in {
                "verified",
                "not_available",
            }:
                raise ValueError("unexpected replay report shape")
            report_doc = parsed
        except (ValueError, OSError):
            reasons.append(PackRejectionReason.REPLAY_REPORT_MALFORMED)

    # --- tier 1: artifact integrity -----------------------------------------
    declared = evidence.get("artifacts")
    declared = declared if isinstance(declared, dict) else {}
    integrity_status = "intact"
    for name in ARTIFACT_FILES:
        entry = declared.get(name)
        expected = entry.get("sha256") if isinstance(entry, dict) else None
        path = root / name
        if not path.is_file() or not expected:
            integrity_status = "incomplete"
            if PackRejectionReason.ARTIFACT_MISSING not in reasons:
                reasons.append(PackRejectionReason.ARTIFACT_MISSING)
            continue
        if _sha256_file(path) != expected:
            if integrity_status != "incomplete":
                integrity_status = "tampered"
            if PackRejectionReason.ARTIFACT_DIGEST_MISMATCH not in reasons:
                reasons.append(PackRejectionReason.ARTIFACT_DIGEST_MISMATCH)

    # --- tier 2: receipt + chain via the existing hardened verifier ----------
    inner: ProofPackVerificationResult | None = None
    receipt_path = root / RECEIPT_FILE
    chain_path = root / AUDIT_CHAIN_FILE
    if receipt_path.is_file() and chain_path.is_file():
        try:
            receipt = DecisionReceipt.from_json(receipt_path.read_text(encoding="utf-8"))
            chain_doc = json.loads(chain_path.read_text(encoding="utf-8"))
            events = chain_doc["events"]
            if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
                raise ValueError("audit-chain.json events must be a list of objects")
        except (ValueError, KeyError, TypeError, OSError):
            reasons.append(PackRejectionReason.AUDIT_CHAIN_MALFORMED)
        else:
            with tempfile.TemporaryDirectory(prefix="acgs-proofpack-") as tmp:
                inner = _run_inner_verifier(
                    Path(tmp),
                    receipt=receipt,
                    events=events,
                    verifier=verifier,
                    require_signature=require_signature,
                    now_iso=now_iso,
                    revoked_keys=revoked_keys,
                )
            reasons.extend(r for r in inner.reasons if r not in reasons)

            # --- tier 3: evidence cross-binding ------------------------------
            # evidence.json cannot carry its own digest, so EVERY receipt-derived
            # claim it makes is re-derived here from the hash-protected receipt
            # and compared strictly. A forged governed_action / actor / policy
            # section in evidence.json must fail the pack even though the other
            # four artifacts are untouched.
            expected_sections = _receipt_evidence_sections(receipt)
            if evidence.get("receipt") != expected_sections["receipt"]:
                reasons.append(PackRejectionReason.RECEIPT_BINDING_MISMATCH)
            for section in ("governed_action", "actor", "policy"):
                if (
                    evidence.get(section) != expected_sections[section]
                    and PackRejectionReason.EVIDENCE_BINDING_MISMATCH not in reasons
                ):
                    reasons.append(PackRejectionReason.EVIDENCE_BINDING_MISMATCH)
            audit_meta = evidence.get("audit", {})
            audit_meta = audit_meta if isinstance(audit_meta, dict) else {}
            chain_last = chain_doc.get("last_hash")
            actual_last = events[-1].get("event_hash") if events else GENESIS_HASH
            if (
                audit_meta.get("last_hash") != actual_last
                or chain_last != actual_last
                or audit_meta.get("event_count") != len(events)
                or chain_doc.get("event_count") != len(events)
            ):
                reasons.append(PackRejectionReason.AUDIT_BINDING_MISMATCH)

            # The summary is deterministic given the receipt, the chain, and the
            # replay status, so it is re-rendered here and byte-compared — the
            # auditor/regulator prose cannot be rewritten even by an attacker who
            # recomputes every evidence digest. Rendered with chain valid=True
            # because generation refuses to write a pack from an invalid chain;
            # a chain broken after generation is caught by the inner verifier.
            summary_path = root / SUMMARY_FILE
            if report_doc is not None and summary_path.is_file():
                try:
                    expected_summary = _render_summary(
                        receipt=receipt,
                        chain={"valid": True},
                        event_count=len(events),
                        replay_report=report_doc,
                        now_iso=str(evidence.get("generated_at")),
                    )
                    if summary_path.read_text(encoding="utf-8") != expected_summary:
                        reasons.append(PackRejectionReason.SUMMARY_BINDING_MISMATCH)
                except Exception:  # noqa: BLE001 — an unrenderable summary is a mismatch, never a pass.
                    reasons.append(PackRejectionReason.SUMMARY_BINDING_MISMATCH)
    else:
        # Missing artifacts already recorded in tier 1; the inner tiers cannot run.
        if PackRejectionReason.ARTIFACT_MISSING not in reasons:
            reasons.append(PackRejectionReason.ARTIFACT_MISSING)

    # --- tier 4: replay -------------------------------------------------------
    replay_status = "not_available"
    if report_doc is not None and report_doc.get("status") == "verified":
        # A recorded generate-time report is an ATTESTATION ("recorded"), never
        # treated as re-verification; only an out-of-band re-run upgrades it.
        replay_status = "recorded"

    if (policy_bundle is None) != (side_store is None):
        reasons.append(PackRejectionReason.REPLAY_MATERIAL_MALFORMED)
    elif policy_bundle is not None and side_store is not None:
        replay_status = _reverify_replay(root, Path(policy_bundle), Path(side_store), reasons)

    valid = (
        integrity_status == "intact"
        and inner is not None
        and inner.valid
        and replay_status != "failed"
        and not reasons
    )
    return PackVerificationResult(
        valid=valid,
        schema_version=schema_version,
        integrity_status=integrity_status,
        receipt_and_chain=inner,
        replay_status=replay_status,
        reasons=reasons,
    )


def _run_inner_verifier(
    tmp: Path,
    *,
    receipt: DecisionReceipt,
    events: list[dict[str, Any]],
    verifier: Any,
    require_signature: bool | None,
    now_iso: str | None,
    revoked_keys: RevocationList | None,
) -> ProofPackVerificationResult:
    """Materialise the gove-zone/proof-pack/v1 shape and reuse its verifier.

    ``event_hash`` covers the canonical JSON of the parsed event dict, not the
    original line bytes, so round-tripping events through ``audit-chain.json``
    preserves verifiability exactly.
    """
    (tmp / "audit.jsonl").write_text(
        "".join(
            json.dumps(e, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
            for e in events
        ),
        encoding="utf-8",
        newline="\n",
    )
    (tmp / "receipt.json").write_text(receipt.to_json() + "\n", encoding="utf-8", newline="\n")
    manifest = {
        "schema_version": INNER_SCHEMA_VERSION,
        "audit_chain": "audit.jsonl",
        "receipts": [
            {
                "name": "decision",
                "file": "receipt.json",
                "declared_verdict": _declared_verdict(receipt),
                "reason_code": None,
            }
        ],
        "replay": None,
        "consumption_ledger": None,
    }
    (tmp / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8", newline="\n"
    )
    return verify_proof_pack(
        tmp,
        verifier=verifier,
        require_signature=require_signature,
        now_iso=now_iso,
        revoked_keys=revoked_keys,
    )


def _reverify_replay(root: Path, policy_bundle: Path, side_store: Path, reasons: list[str]) -> str:
    """Re-derive decisions now from out-of-band material (lazy engine import)."""
    try:
        chain_doc = json.loads((root / AUDIT_CHAIN_FILE).read_text(encoding="utf-8"))
        events = chain_doc["events"]
        with tempfile.TemporaryDirectory(prefix="acgs-replay-") as tmp:
            audit_path = Path(tmp) / "audit.jsonl"
            audit_path.write_text(
                "".join(
                    json.dumps(e, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
                    for e in events
                ),
                encoding="utf-8",
                newline="\n",
            )
            result = _run_replay(audit_path, policy_bundle, side_store)
    except Exception:  # noqa: BLE001 — malformed replay material is fail-closed.
        reasons.append(PackRejectionReason.REPLAY_MATERIAL_MALFORMED)
        return "failed"
    if not result.get("valid"):
        reasons.append(PackRejectionReason.REPLAY_MISMATCH)
        return "failed"
    return "reverified"
