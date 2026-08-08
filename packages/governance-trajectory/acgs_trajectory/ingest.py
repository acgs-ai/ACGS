"""Ingestion orchestrator (Phase 1).

Ties the foundation together for one session:

    read raw -> secret scan (V5) -> parse (version boundary) -> materialize
    -> validate V1-V6 -> resolve fail-closed status -> archive + manifest

Nothing here evaluates, scores, labels, or ranks. Status resolution is the
deterministic ladder from the schema spec: quarantined > incomplete > complete.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import validate
from .adapter import SourceAdapter, read_jsonl
from .materialize import materialize, stamp_normalized_digest
from .raw_store import RawStore
from .secrets_scan import allowed_findings, quarantine_findings, scan_text

COLLECTOR_VERSION = "0.1.0"


@dataclass
class IngestResult:
    record: dict[str, Any]
    status: str  # complete | incomplete | quarantined
    reasons: list[str] = field(default_factory=list)
    raw_ref: Any = None
    manifest_entry: dict[str, Any] | None = None


def ingest_text(
    raw_text: str,
    *,
    store: RawStore | None = None,
    captured_at: str,
    repo_git: dict[str, Any] | None = None,
    collector_version: str = COLLECTOR_VERSION,
    adapter: SourceAdapter | None = None,
) -> IngestResult:
    """Ingest one session transcript given as text. ``captured_at`` is injected
    (no wall-clock inside), keeping ingestion deterministic (R6)."""
    adapter = adapter or SourceAdapter()
    raw_bytes = raw_text.encode("utf-8")

    # V5 FIRST: secret detection at the ingestion edge, before archive (D7).
    # H4: only quarantine-worthy tiers force quarantine; placeholders/fixtures
    # are recorded as non-blocking notes (fail-closed, but not over-quarantining).
    secret_findings = scan_text(raw_text)
    quarantine_secrets = quarantine_findings(secret_findings)
    note_secrets = allowed_findings(secret_findings)

    records = read_jsonl(raw_text)
    parsed = adapter.parse(records)

    reasons: list[str] = []
    reasons += validate.v5_secret(quarantine_secrets)
    note_reasons = [f"note:{f.as_reason()}" for f in note_secrets]

    # version / unknown-type boundary -> quarantine (fail closed)
    if not parsed.version_ok:
        reasons.append(f"V6:unsupported_version:{parsed.version}")
    for t in parsed.unknown_types:
        reasons.append(f"V6:unknown_record_type:{t}")

    quarantine = bool(quarantine_secrets) or not parsed.version_ok or bool(parsed.unknown_types)

    # archive raw (authoritative, unmodified). Quarantined raw goes to the
    # restricted store and is NEVER redacted (D7).
    raw_ref = manifest_entry = None
    if store is not None:
        raw_ref = store.put_raw(raw_bytes, record_count=len(records), quarantine=quarantine)
        if quarantine:
            store.log_incident(
                f"{captured_at} QUARANTINE {raw_ref.sha256} reasons={reasons}"
            )
    else:
        # no store: synthesize a ref so the record is still well-formed
        from .canonical import sha256_hex
        from .raw_store import RawRef

        raw_ref = RawRef(
            uri=f"raw/{sha256_hex(raw_bytes)[:2]}/{sha256_hex(raw_bytes)}.jsonl",
            sha256=sha256_hex(raw_bytes),
            byte_len=len(raw_bytes),
            record_count=len(records),
        )

    record = materialize(
        parsed,
        raw_ref,
        captured_at=captured_at,
        collector_version=collector_version,
        repo_git=repo_git,
    )

    # V1-V4, V6 deterministic checks
    reasons += validate.v1_causal_graph(parsed)
    reasons += validate.v2_block_integrity(parsed)
    reasons += validate.v3_provenance(record, parsed)
    reasons += validate.v4_tamper(record, raw_bytes)
    reasons += validate.v6_schema(record)

    status = _resolve_status(quarantine, reasons)
    record["integrity"]["status"] = status
    # notes are informational (placeholders/fixtures) — recorded but never gating.
    record["integrity"]["reasons"] = sorted(set(reasons + note_reasons))
    stamp_normalized_digest(record)

    # provenance registry (hash-chained manifest)
    if store is not None:
        manifest_entry = store.append_manifest(
            {
                "trajectory_id": record["trajectory_id"],
                "raw_sha256": raw_ref.sha256,
                "raw_uri": raw_ref.uri,
                "normalized_sha256": record["integrity"]["normalized_sha256"],
                "captured_at": captured_at,
                "status": status,
            }
        )
        record["provenance"]["registry_ref"] = {
            "entry_sha256": manifest_entry["entry_sha256"],
            "prev_entry_sha256": manifest_entry["prev_entry_sha256"],
        }
        stamp_normalized_digest(record)

    return IngestResult(
        record=record,
        status=status,
        reasons=record["integrity"]["reasons"],
        raw_ref=raw_ref,
        manifest_entry=manifest_entry,
    )


def _resolve_status(quarantine: bool, reasons: list[str]) -> str:
    # safety net: a real secret reason ("secret:...") or version/type breach forces
    # quarantine even if the flag were somehow dropped. Notes ("note:secret:...")
    # start with "note:" and are intentionally excluded.
    if quarantine or any(
        r.startswith("secret:") or "unsupported_version" in r or "unknown_record_type" in r
        for r in reasons
    ):
        return "quarantined"
    if reasons:
        return "incomplete"
    return "complete"
