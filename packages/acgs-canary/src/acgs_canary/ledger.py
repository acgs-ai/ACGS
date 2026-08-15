"""Acceptance ledger — append-only, hash-chained issuance receipts.

Model
-----
The ledger is a JSONL file of canonical entries. Lifecycle states are
**append-only state-transition entries**, never mutations of prior lines:

    variant.prepared          (publisher intends to issue variant V)
    variant.issuer_signed     (issuer signature over the prepared entry hash)
    variant.countersigned     (licensee countersignature binding the issuer
                               signature — signature-substitution proof)
    anchor.recorded           (external timestamp evidence for a chain head)

Evidentiary honesty (normative, from the approved design):
- an entry without the licensee countersignature is NEVER a completed T1
  issuance — ``issuance_state`` reports it as incomplete;
- unanchored publisher-held entries are labeled ``publisher-testimony``;
  only externally anchored heads upgrade to ``anchored``;
- the ledger proves what the publisher recorded, not what any licensee
  did — attribution language lives in the dispute runbook, not here.

Chain integrity
---------------
Every entry embeds: ledger_id, protocol hash, seq, prev entry hash, and
its own entry hash over the canonical body. Verification rejects duplicate
seqs, forks, prev-hash substitution, malformed lines, unknown critical
fields, duplicate variant issuance, and cross-ledger signature replay
(signatures bind ledger_id + protocol + role + purpose). A torn tail
(crash mid-append: final line incomplete) is distinguished from mid-chain
corruption and is recoverable only by an explicit, logged truncation.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import secrets as pysecrets
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import anchor as anchor_mod
from . import signing as sig
from .canonical import canonical_bytes
from .errors import AnchorError, LedgerError, LedgerStateError
from .protocol import protocol_hash
from .store import CanaryStoreBackend

SCHEMA = "acgs_canary_ledger/v1"

KIND_PREPARED = "variant.prepared"
KIND_ISSUER_SIGNED = "variant.issuer_signed"
KIND_COUNTERSIGNED = "variant.countersigned"
KIND_ANCHOR = "anchor.recorded"
_KINDS = frozenset({KIND_PREPARED, KIND_ISSUER_SIGNED, KIND_COUNTERSIGNED, KIND_ANCHOR})

_GENESIS_PREV = "0" * 64

_LREF_RE = re.compile(r"^lref_[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VARIANT_ID_RE = re.compile(r"^vt_[0-9a-f]{32}$")  # protocol: vt_ + 128-bit CSPRNG hex


def _is_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.match(value) is not None


def _require_sha256_hex(value: Any, field: str) -> None:
    if not _is_sha256_hex(value):
        raise LedgerStateError(f"{field} must be a 64-char lowercase hex SHA-256 digest")


def _t1_bindings_valid(acceptance_ref: Any, delivery: Any) -> bool:
    """Structural validity of the T1 acceptance/delivery bindings.

    A completed T1 issuance must be able to name the accepted document and
    the delivery channel; empty or malformed objects bind nothing.
    """
    if not isinstance(acceptance_ref, dict) or not isinstance(delivery, dict):
        return False
    if set(acceptance_ref) != {"kind", "doc_hash"}:
        return False
    kind = acceptance_ref["kind"]
    if not isinstance(kind, str) or not kind.strip():
        return False
    if not _is_sha256_hex(acceptance_ref["doc_hash"]):
        return False
    if not ({"channel", "ref"} <= set(delivery) <= {"channel", "ref", "countersign_ref"}):
        return False
    for key in ("channel", "ref"):
        if not isinstance(delivery[key], str) or not delivery[key].strip():
            return False
    if "countersign_ref" in delivery and not _is_sha256_hex(delivery["countersign_ref"]):
        return False
    return True


_COMMON_FIELDS = frozenset(
    {
        "schema",
        "ledger_id",
        "protocol_sha256",
        "seq",
        "prev",
        "kind",
        "timestamp",
        "body",
        "entry_hash",
    }
)


# Exact body field sets per entry kind: the append-only chain means a
# hand-minted entry with an extra (or missing) body field, its entry_hash
# recomputed, would otherwise verify forever. Unknown critical fields are
# rejected, per the protocol's verification rules.
_GENESIS_BODY_FIELDS = frozenset({"kind_detail", "operator", "ledger_id_confirm"})
_PREPARED_BODY_FIELDS = frozenset(
    {
        "variant_id",
        "tier",
        "variant_tree_sha256",
        "source_tree_sha256",
        "canary_commitment_hex",
        "allocation_manifest_sha256",
        "licensee_ref",
        "acceptance_ref",
        "delivery",
    }
)
_BODY_FIELDS_BY_KIND = {
    KIND_ISSUER_SIGNED: frozenset({"target_entry_hash", "signature"}),
    KIND_COUNTERSIGNED: frozenset({"issuer_entry_hash", "signature"}),
    KIND_ANCHOR: frozenset(
        {
            "anchored_head_hash",
            "bundle_sha256",
            "evidence_kind",
            "evidence_state",
            "evidence_ref",
            "production",
        }
    ),
}


def _expected_body_fields(kind: str, seq: int) -> frozenset[str]:
    if kind == KIND_PREPARED:
        return _GENESIS_BODY_FIELDS if seq == 0 else _PREPARED_BODY_FIELDS
    return _BODY_FIELDS_BY_KIND[kind]


@dataclass(frozen=True)
class VerifyReport:
    entries: int
    head_hash: str
    torn_tail: bool


class AcceptanceLedger:
    """One JSONL ledger file. The path should live inside the restricted
    store directory (the ledger holds no raw secrets, but it is a private
    operational record until anchored heads are published)."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    # -- creation ----------------------------------------------------------

    @classmethod
    def create(
        cls, path: Path, *, protocol_sha256: str, operator: str, timestamp: str
    ) -> AcceptanceLedger:
        path = Path(path)
        if path.exists():
            raise LedgerError("ledger already exists; refusing to overwrite")
        if protocol_sha256 != protocol_hash():
            raise LedgerError(
                "ledger protocol identity does not match this package's frozen "
                "protocol; refusing to create a ledger bound to a foreign protocol"
            )
        ledger = cls(path)
        genesis_body = {
            "kind_detail": "genesis",
            "operator": operator,
            "ledger_id_confirm": None,
        }
        ledger_id = f"lg_{pysecrets.token_hex(16)}"
        genesis_body["ledger_id_confirm"] = ledger_id
        entry = _make_entry(
            ledger_id=ledger_id,
            protocol_sha256=protocol_sha256,
            seq=0,
            prev=_GENESIS_PREV,
            kind=KIND_PREPARED,
            timestamp=timestamp,
            body=genesis_body,
        )
        _append_line(path, entry, create=True)
        return ledger

    # -- raw IO ------------------------------------------------------------

    def _read_lines(self) -> tuple[list[dict[str, Any]], bool]:
        """Parse all complete entries. Returns (entries, torn_tail)."""
        if not self._path.exists():
            raise LedgerError("ledger file does not exist")
        raw = self._path.read_bytes()
        torn = False
        entries: list[dict[str, Any]] = []
        if not raw:
            raise LedgerError("ledger file is empty")
        lines = raw.split(b"\n")
        trailing = lines[-1]
        body_lines = lines[:-1]
        if trailing:
            # No trailing newline: the final line may be a torn append.
            torn = True
        for i, line in enumerate(body_lines):
            if not line:
                raise LedgerError(f"blank line at index {i}")
            entries.append(_parse_entry(line, index=i))
        if torn:
            try:
                entries.append(_parse_entry(trailing, index=len(body_lines)))
                # Parsed fine — it is a complete entry missing only the
                # newline; still reported as torn so the operator reseals.
            except LedgerError:
                pass  # genuinely torn tail: excluded from entries
        return entries, torn

    # -- verification ------------------------------------------------------

    def verify(self, *, allow_torn_tail: bool = False) -> VerifyReport:
        entries, torn = self._read_lines()
        if torn and not allow_torn_tail:
            raise LedgerError("torn tail detected; run explicit tail recovery before use")
        if not entries:
            raise LedgerError("no complete entries")
        ledger_id = entries[0]["ledger_id"]
        protocol = entries[0]["protocol_sha256"]
        if protocol != protocol_hash():
            raise LedgerError(
                "ledger is bound to an unexpected protocol identity; entries "
                "repeating a foreign genesis protocol hash do not verify against "
                "the protocol this package enforces"
            )
        if entries[0]["seq"] != 0 or entries[0]["prev"] != _GENESIS_PREV:
            raise LedgerError("genesis entry malformed")
        if entries[0]["body"].get("ledger_id_confirm") != ledger_id:
            raise LedgerError("genesis ledger_id confirmation mismatch")
        prev_hash = None
        prepared_variants: set[str] = set()
        for i, e in enumerate(entries):
            if e["ledger_id"] != ledger_id:
                raise LedgerError(f"entry {i}: foreign ledger_id (cross-ledger splice)")
            if e["protocol_sha256"] != protocol:
                raise LedgerError(f"entry {i}: protocol hash changed mid-chain")
            if e["seq"] != i:
                raise LedgerError(f"entry {i}: sequence violation (found {e['seq']})")
            if i > 0 and e["prev"] != prev_hash:
                raise LedgerError(f"entry {i}: prev-hash mismatch (fork or splice)")
            recomputed = _entry_hash(e)
            if recomputed != e["entry_hash"]:
                raise LedgerError(f"entry {i}: entry hash mismatch (tampered)")
            prev_hash = e["entry_hash"]
            if e["kind"] == KIND_PREPARED and i > 0:
                vid = e["body"]["variant_id"]
                if vid in prepared_variants:
                    raise LedgerError(f"entry {i}: duplicate issuance of {vid}")
                prepared_variants.add(vid)
        self._verify_signatures(entries, ledger_id, protocol)
        return VerifyReport(entries=len(entries), head_hash=prev_hash or "", torn_tail=torn)

    def _verify_signatures(
        self, entries: list[dict[str, Any]], ledger_id: str, protocol: str
    ) -> None:
        by_hash = {e["entry_hash"]: e for e in entries}
        for i, e in enumerate(entries):
            if e["kind"] == KIND_ISSUER_SIGNED:
                target = by_hash.get(e["body"]["target_entry_hash"])
                if target is None or target["kind"] != KIND_PREPARED:
                    raise LedgerError(f"entry {i}: issuer signature targets no prepared entry")
                ok = sig.verify(
                    e["body"]["signature"],
                    ledger_id=ledger_id,
                    protocol_sha256=protocol,
                    role=sig.ROLE_ISSUER,
                    purpose=sig.PURPOSE_ISSUE,
                    payload=bytes.fromhex(target["entry_hash"]),
                )
                if not ok:
                    raise LedgerError(f"entry {i}: issuer signature invalid")
            elif e["kind"] == KIND_COUNTERSIGNED:
                issuer_entry = by_hash.get(e["body"]["issuer_entry_hash"])
                if issuer_entry is None or issuer_entry["kind"] != KIND_ISSUER_SIGNED:
                    raise LedgerError(f"entry {i}: countersignature targets no issuer-signed entry")
                # Countersignature binds the ISSUER SIGNATURE ENTRY hash,
                # so substituting a different issuer signature invalidates it.
                ok = sig.verify(
                    e["body"]["signature"],
                    ledger_id=ledger_id,
                    protocol_sha256=protocol,
                    role=sig.ROLE_LICENSEE,
                    purpose=sig.PURPOSE_COUNTERSIGN,
                    payload=bytes.fromhex(issuer_entry["entry_hash"]),
                )
                if not ok:
                    raise LedgerError(f"entry {i}: countersignature invalid")

    # -- append operations -------------------------------------------------

    def _head(self) -> dict[str, Any]:
        report_entries, torn = self._read_lines()
        if torn:
            raise LedgerError("torn tail detected; refusing to append")
        if not report_entries:
            raise LedgerError("empty ledger")
        return report_entries[-1]

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        """Cross-process lock serializing verify → head selection → append.

        Without it, two concurrent appenders can both pass ``verify()``,
        read the same head, and write entries sharing a seq/prev — a
        permanent sequence violation, not a recoverable torn tail.
        """
        lock_path = self._path.with_name(self._path.name + ".lock")
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _append(
        self,
        kind: str,
        body: dict[str, Any],
        *,
        timestamp: str,
        precondition: Callable[[list[dict[str, Any]]], None] | None = None,
    ) -> dict[str, Any]:
        with self._exclusive_lock():
            self.verify()
            head = self._head()
            if precondition is not None:
                # Semantic preconditions (e.g. no duplicate variant issuance)
                # must be re-checked INSIDE the verify-and-append transaction:
                # a check done before taking the lock can be invalidated by a
                # concurrent appender that wins the lock first.
                entries, _ = self._read_lines()
                precondition(entries)
            entry = _make_entry(
                ledger_id=head["ledger_id"],
                protocol_sha256=head["protocol_sha256"],
                seq=head["seq"] + 1,
                prev=head["entry_hash"],
                kind=kind,
                timestamp=timestamp,
                body=body,
            )
            _append_line(self._path, entry, create=False)
        return entry

    def append_prepared(
        self,
        *,
        variant_id: str,
        tier: str,
        variant_tree_sha256: str | None,
        source_tree_sha256: str,
        canary_commitment_hex: str,
        allocation_manifest_sha256: str,
        licensee_ref: str | None,
        acceptance_ref: dict[str, str] | None,
        delivery: dict[str, str] | None,
        timestamp: str,
    ) -> dict[str, Any]:
        if not (isinstance(variant_id, str) and _VARIANT_ID_RE.match(variant_id)):
            # The variant id is the permanent, append-only lookup key: a raw
            # identifier written here (an email address, a contract name)
            # would breach the protocol's non-identifying variant-id
            # boundary forever. Library callers bypassing the CLI get the
            # same validation manifests enforce.
            raise LedgerStateError(
                "variant_id must be vt_ + 32 lowercase hex chars (128-bit CSPRNG); "
                "raw identifiers are refused"
            )
        if tier not in ("T0", "T1"):
            # The protocol defines exactly two tier namespaces. Anything
            # else (a typo, a future value) would fall through the T1
            # checks and be appended without licensee/delivery bindings,
            # then verify as valid publisher testimony forever.
            raise LedgerStateError(f"unknown tier: {tier!r}; the protocol defines only T0 and T1")
        if tier == "T1":
            if licensee_ref is None:
                raise LedgerStateError("T1 preparation requires a licensee reference")
            if acceptance_ref is None or delivery is None:
                raise LedgerStateError(
                    "T1 preparation requires acceptance_ref and delivery bindings"
                )
            if not _t1_bindings_valid(acceptance_ref, delivery):
                raise LedgerStateError(
                    "T1 acceptance_ref must bind {kind, doc_hash(sha256 hex)} and "
                    "delivery must bind {channel, ref[, countersign_ref(sha256 hex)]}; "
                    "empty or malformed bindings attest nothing"
                )
        if licensee_ref is not None and not _LREF_RE.match(licensee_ref):
            # The ledger is append-only: a raw identity (name, email) written
            # here could never be de-linked by destroying the HMAC key, so
            # only opaque lref_ references produced by licensee.licensee_ref
            # are accepted (crypto-shredding property, design §5.1).
            raise LedgerStateError(
                "licensee_ref must be an opaque lref_ reference "
                "(HMAC-derived, 64 hex chars); raw identity is refused"
            )
        if variant_tree_sha256 is not None:
            _require_sha256_hex(variant_tree_sha256, "variant_tree_sha256")
        # Every digest binding must be cryptographically addressable: an
        # entry carrying arbitrary strings here could be signed, countersigned
        # and verified while binding no source, canary set, or allocation.
        _require_sha256_hex(source_tree_sha256, "source_tree_sha256")
        _require_sha256_hex(canary_commitment_hex, "canary_commitment_hex")
        _require_sha256_hex(allocation_manifest_sha256, "allocation_manifest_sha256")

        def _no_duplicate_issuance(entries: list[dict[str, Any]]) -> None:
            for e in entries:
                if (
                    e["kind"] == KIND_PREPARED
                    and e["seq"] > 0
                    and e["body"]["variant_id"] == variant_id
                ):
                    raise LedgerError(f"duplicate issuance of {variant_id}")

        return self._append(
            KIND_PREPARED,
            {
                "variant_id": variant_id,
                "tier": tier,
                "variant_tree_sha256": variant_tree_sha256,
                "source_tree_sha256": source_tree_sha256,
                "canary_commitment_hex": canary_commitment_hex,
                "allocation_manifest_sha256": allocation_manifest_sha256,
                "licensee_ref": licensee_ref,
                "acceptance_ref": acceptance_ref,
                "delivery": delivery,
            },
            timestamp=timestamp,
            precondition=_no_duplicate_issuance,
        )

    def append_issuer_signature(
        self,
        *,
        target_entry_hash: str,
        key: sig.BoundKey,
        timestamp: str,
        production: bool = False,
    ) -> dict[str, Any]:
        sig.enforce_production_policy(key, production=production)
        head_entries, _ = self._read_lines()
        target = next((e for e in head_entries if e["entry_hash"] == target_entry_hash), None)
        if target is None or target["kind"] != KIND_PREPARED or target["seq"] == 0:
            raise LedgerStateError("issuer signature target must be a prepared entry")
        signature = sig.sign(
            key,
            ledger_id=target["ledger_id"],
            protocol_sha256=target["protocol_sha256"],
            role=sig.ROLE_ISSUER,
            purpose=sig.PURPOSE_ISSUE,
            payload=bytes.fromhex(target_entry_hash),
        )
        return self._append(
            KIND_ISSUER_SIGNED,
            {"target_entry_hash": target_entry_hash, "signature": signature},
            timestamp=timestamp,
        )

    def append_licensee_countersignature(
        self, *, issuer_entry_hash: str, key: sig.BoundKey, timestamp: str
    ) -> dict[str, Any]:
        entries, _ = self._read_lines()
        issuer_entry = next((e for e in entries if e["entry_hash"] == issuer_entry_hash), None)
        if issuer_entry is None or issuer_entry["kind"] != KIND_ISSUER_SIGNED:
            raise LedgerStateError("countersignature target must be an issuer-signed entry")
        signature = sig.sign(
            key,
            ledger_id=issuer_entry["ledger_id"],
            protocol_sha256=issuer_entry["protocol_sha256"],
            role=sig.ROLE_LICENSEE,
            purpose=sig.PURPOSE_COUNTERSIGN,
            payload=bytes.fromhex(issuer_entry_hash),
        )
        return self._append(
            KIND_COUNTERSIGNED,
            {"issuer_entry_hash": issuer_entry_hash, "signature": signature},
            timestamp=timestamp,
        )

    def append_anchor(
        self,
        *,
        bundle: dict[str, Any],
        evidence: anchor_mod.AnchorEvidence,
        timestamp: str,
    ) -> dict[str, Any]:
        """Record an anchor entry, bound to a validated bundle.

        Recording an entry NEVER by itself upgrades evidentiary standing —
        the ledger cannot verify external evidence; only
        :meth:`anchored_issuance_state` (which runs a real verifier) may
        emit an "anchored" label. What this method DOES enforce:

        - the bundle is well-formed and its ``ledger_head_hash`` is an
          entry actually present in this chain;
        - the evidence is of an independent kind (mirror refused);
        - ``evidence.bundle_sha256`` equals the recomputed bundle hash.
        """
        if evidence.kind not in (anchor_mod.KIND_RFC3161, anchor_mod.KIND_OTS):
            raise LedgerStateError(
                "only independent anchor kinds may be recorded; "
                "mirror metadata is supplementary and does not belong here"
            )
        recomputed = anchor_mod.bundle_hash(bundle)  # validates schema
        if evidence.bundle_sha256 != recomputed:
            raise LedgerStateError("evidence does not match the bundle hash")
        head_hash = bundle["ledger_head_hash"]
        entries, _ = self._read_lines()
        if not any(e["entry_hash"] == head_hash for e in entries):
            raise LedgerStateError("anchor bundle's ledger_head_hash is not an entry in this chain")
        return self._append(
            KIND_ANCHOR,
            {
                "anchored_head_hash": head_hash,
                "bundle_sha256": recomputed,
                "evidence_kind": evidence.kind,
                "evidence_state": evidence.state,
                "evidence_ref": evidence.evidence_ref,
                "production": evidence.production,
            },
            timestamp=timestamp,
        )

    # -- derived state -----------------------------------------------------

    def issuance_state(self, variant_id: str) -> dict[str, Any]:
        """Fold the chain into the variant's lifecycle state. FAIL-CLOSED:
        the full chain (hashes, sequence, signatures) is verified first, so
        a forged countersignature can never surface as completion.

        States: prepared → issuer-signed → countersigned. A T1 variant
        without a valid countersignature is NEVER "completed".

        Evidence labeling is deliberately conservative: this method emits
        only "publisher-testimony" or "anchor-entry-recorded" — the ledger
        cannot verify external evidence, so a recorded anchor entry stays
        explicitly unverified here. The "anchored" label exists only on the
        verified path, :meth:`anchored_issuance_state`.
        """
        self.verify()
        entries, _ = self._read_lines()
        prepared = None
        issuer_signed = None
        issuer_signed_hashes: set[str] = set()
        countersigned = None
        anchored_hashes: set[str] = set()
        covered: set[str] = set()
        for e in entries:
            if (
                e["kind"] == KIND_PREPARED
                and e["seq"] > 0
                and e["body"]["variant_id"] == variant_id
            ):
                prepared = e
            elif e["kind"] == KIND_ISSUER_SIGNED and prepared is not None:
                if e["body"]["target_entry_hash"] == prepared["entry_hash"]:
                    # Track EVERY issuer signature over the prepared entry,
                    # not just the latest: an issuer-signature retry appended
                    # before the licensee countersigns the original must not
                    # orphan a valid countersignature over the earlier entry.
                    issuer_signed = e
                    issuer_signed_hashes.add(e["entry_hash"])
            elif e["kind"] == KIND_COUNTERSIGNED and issuer_signed_hashes:
                if e["body"]["issuer_entry_hash"] in issuer_signed_hashes:
                    countersigned = e
            elif e["kind"] == KIND_ANCHOR:
                anchored_hashes.add(e["body"]["anchored_head_hash"])
        # An anchor over entry hash H covers every entry at seq <= seq(H).
        if anchored_hashes:
            max_anchored_seq = max(e["seq"] for e in entries if e["entry_hash"] in anchored_hashes)
            covered = {e["entry_hash"] for e in entries if e["seq"] <= max_anchored_seq}
        if prepared is None:
            raise LedgerError(f"variant not in ledger: {variant_id}")
        state = "prepared"
        if issuer_signed is not None:
            state = "issuer-signed"
        if countersigned is not None:
            state = "countersigned"
        state_entry = countersigned or issuer_signed or prepared
        anchor_entry_recorded = state_entry["entry_hash"] in covered
        # Completed T1 issuance requires the countersignature AND the
        # delivery bindings in the prepared body: a countersignature over an
        # entry with no delivered tree or acceptance artifact does not
        # establish the delivery callers rely on. The bindings are checked
        # STRUCTURALLY, not just for presence — empty or malformed objects
        # (e.g. acceptance_ref={}) attest no document, channel, or tree.
        body = prepared["body"]
        delivery_bound = _is_sha256_hex(body.get("variant_tree_sha256")) and _t1_bindings_valid(
            body.get("acceptance_ref"), body.get("delivery")
        )
        completed_t1 = body["tier"] == "T1" and countersigned is not None and delivery_bound
        return {
            "variant_id": variant_id,
            "state": state,
            "completed_t1_issuance": completed_t1,
            "anchor_entry_recorded": anchor_entry_recorded,
            "state_entry_hash": state_entry["entry_hash"],
            "evidence_label": (
                "anchor-entry-recorded" if anchor_entry_recorded else "publisher-testimony"
            ),
        }

    def anchored_issuance_state(
        self,
        variant_id: str,
        *,
        bundle: dict[str, Any],
        evidence: anchor_mod.AnchorEvidence,
        verifier: anchor_mod.AnchorVerifier,
    ) -> dict[str, Any]:
        """The ONLY path that can emit an "anchored" evidence label.

        Runs the structural fold (which verifies the chain), then verifies
        the external evidence through the supplied verifier: independent
        kind, confirmed state, evidence bound to the bundle hash, bundle's
        head present in the chain and matching a recorded anchor entry.

        Fixture / non-production evidence yields
        "anchored-non-production" — it never reads as real anchoring.
        """
        state = self.issuance_state(variant_id)
        if not state["anchor_entry_recorded"]:
            return state
        recomputed = anchor_mod.bundle_hash(bundle)
        entries, _ = self._read_lines()
        recorded = [
            e
            for e in entries
            if e["kind"] == KIND_ANCHOR and e["body"]["bundle_sha256"] == recomputed
        ]
        if not recorded:
            return state
        if bundle["ledger_head_hash"] != recorded[-1]["body"]["anchored_head_hash"]:
            return state
        # Bind the VERIFIED anchor to the state entry it must cover: an
        # older confirmed anchor whose head precedes the variant's current
        # state entry proves nothing about that state — without this check,
        # an unverifiable later anchor could set anchor_entry_recorded while
        # the verified bundle predates the state it is claimed to anchor.
        by_hash = {e["entry_hash"]: e for e in entries}
        head_entry = by_hash.get(bundle["ledger_head_hash"])
        state_entry = by_hash.get(state["state_entry_hash"])
        if head_entry is None or state_entry is None:
            return state
        if head_entry["seq"] < state_entry["seq"]:
            return state
        if evidence.kind not in (anchor_mod.KIND_RFC3161, anchor_mod.KIND_OTS):
            return state
        if evidence.state != anchor_mod.STATE_CONFIRMED:
            return state
        if evidence.bundle_sha256 != recomputed:
            return state
        # An anchor is a TIMESTAMP: confirmed evidence carrying no parseable,
        # timezone-aware anchor time proves nothing about when the bundle
        # existed and must never surface as anchored (in either label), even
        # if a permissive verifier would confirm it.
        if evidence.anchored_at is None:
            return state
        try:
            anchor_mod.parse_anchor_time(evidence.anchored_at)
        except AnchorError:
            return state
        if not verifier.verify(evidence, bundle):
            return state
        state["evidence_label"] = "anchored" if evidence.production else "anchored-non-production"
        return state

    def recover_torn_tail(self) -> bool:
        """Explicit torn-tail recovery: drop the incomplete final line.

        Only removes a line that fails to parse as a complete entry; a
        parseable final line missing its newline is resealed instead.
        Returns True if a repair was performed.
        """
        raw = self._path.read_bytes()
        if raw.endswith(b"\n"):
            return False
        lines = raw.split(b"\n")
        tail = lines[-1]
        try:
            _parse_entry(tail, index=len(lines) - 1)
        except LedgerError:
            repaired = b"\n".join(lines[:-1]) + b"\n"
            _atomic_rewrite(self._path, repaired)
            return True
        _atomic_rewrite(self._path, raw + b"\n")
        return True


# -- entry construction ----------------------------------------------------


def _make_entry(
    *,
    ledger_id: str,
    protocol_sha256: str,
    seq: int,
    prev: str,
    kind: str,
    timestamp: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    if kind not in _KINDS:
        raise LedgerError(f"unknown entry kind: {kind!r}")
    entry = {
        "schema": SCHEMA,
        "ledger_id": ledger_id,
        "protocol_sha256": protocol_sha256,
        "seq": seq,
        "prev": prev,
        "kind": kind,
        "timestamp": timestamp,
        "body": body,
    }
    entry["entry_hash"] = _entry_hash(entry)
    return entry


def _entry_hash(entry: dict[str, Any]) -> str:
    core = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(canonical_bytes(core)).hexdigest()


def _parse_entry(line: bytes, *, index: int) -> dict[str, Any]:
    import json

    try:
        entry = json.loads(line)
    except Exception as exc:
        raise LedgerError(f"entry {index}: malformed JSON") from exc
    if not isinstance(entry, dict):
        raise LedgerError(f"entry {index}: not an object")
    keys = set(entry)
    if keys != _COMMON_FIELDS:
        raise LedgerError(
            f"entry {index}: field set mismatch "
            f"(missing {sorted(_COMMON_FIELDS - keys)}, unknown {sorted(keys - _COMMON_FIELDS)})"
        )
    if entry["schema"] != SCHEMA:
        raise LedgerError(f"entry {index}: schema mismatch")
    if entry["kind"] not in _KINDS:
        raise LedgerError(f"entry {index}: unknown kind")
    if not isinstance(entry["seq"], int) or entry["seq"] < 0:
        raise LedgerError(f"entry {index}: illegal seq")
    body = entry["body"]
    if not isinstance(body, dict):
        raise LedgerError(f"entry {index}: body is not an object")
    expected = _expected_body_fields(entry["kind"], entry["seq"])
    body_keys = set(body)
    if body_keys != expected:
        raise LedgerError(
            f"entry {index}: body field set mismatch for {entry['kind']} "
            f"(missing {sorted(expected - body_keys)}, unknown {sorted(body_keys - expected)})"
        )
    if entry["kind"] == KIND_ANCHOR and not isinstance(body["production"], bool):
        raise LedgerError(f"entry {index}: anchor body production must be a bool")
    if entry["kind"] == KIND_PREPARED and entry["seq"] > 0:
        _validate_prepared_body_values(body, index=index)
    if canonical_bytes(entry) != line:
        raise LedgerError(f"entry {index}: non-canonical encoding")
    return entry


def _validate_prepared_body_values(body: dict[str, Any], *, index: int) -> None:
    """Re-apply the append-time value validators when parsing from disk.

    Exact field NAMES alone are not fail-closed: a canonical hand-minted
    prepared entry with tier "T2", non-SHA digests, a raw-identifier
    variant_id, or a raw-identity licensee_ref (entry_hash recomputed)
    would otherwise pass verify() forever and surface from
    issuance_state() as publisher testimony.
    """

    def _fail(msg: str) -> None:
        raise LedgerError(f"entry {index}: {msg}")

    vid = body["variant_id"]
    if not (isinstance(vid, str) and _VARIANT_ID_RE.match(vid)):
        _fail("variant_id must be vt_ + 32 lowercase hex chars")
    tier = body["tier"]
    if tier not in ("T0", "T1"):
        _fail(f"unknown tier {tier!r}; the protocol defines only T0 and T1")
    if body["variant_tree_sha256"] is not None and not _is_sha256_hex(body["variant_tree_sha256"]):
        _fail("variant_tree_sha256 must be null or a 64-char lowercase hex SHA-256 digest")
    for field in ("source_tree_sha256", "canary_commitment_hex", "allocation_manifest_sha256"):
        if not _is_sha256_hex(body[field]):
            _fail(f"{field} must be a 64-char lowercase hex SHA-256 digest")
    lref = body["licensee_ref"]
    if lref is not None and not (isinstance(lref, str) and _LREF_RE.match(lref)):
        _fail("licensee_ref must be an opaque lref_ reference")
    if tier == "T1" and lref is None:
        _fail("T1 prepared entry missing licensee_ref")


def _append_line(path: Path, entry: dict[str, Any], *, create: bool) -> None:
    data = canonical_bytes(entry) + b"\n"
    flags = os.O_WRONLY | os.O_APPEND | (os.O_CREAT | os.O_EXCL if create else 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_rewrite(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-ledger-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def ledger_path(store: CanaryStoreBackend) -> Path:
    """Default ledger location inside a RestrictedFileStore."""
    from .store import RestrictedFileStore

    if not isinstance(store, RestrictedFileStore):
        raise LedgerError("file ledger requires the restricted file store")
    return store.path / "acceptance-ledger.jsonl"
