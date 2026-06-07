"""The persistent knowledge graph.

The graph is the single source of truth and the single mutator of domain
objects. Adds are idempotent with dedup-merge semantics and every mutating add
returns a ``(stored, was_new)`` tuple so the orchestration loop can count
genuinely new nodes per wave and detect convergence ("loop until dry").

Refuted claims are never deleted — they persist as tombstones so re-discovery
in a later wave is recognized (``was_new=False``) and skipped by verification.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from delve.domain import Citation, Claim, ClaimStatus, Finding, Gap, GapStatus


def _merge_citations(a: tuple[Citation, ...], b: tuple[Citation, ...]) -> tuple[Citation, ...]:
    """Union two citation tuples by id, returned sorted by id (deterministic)."""
    by_id: dict[str, Citation] = {c.id: c for c in a}
    for c in b:
        by_id.setdefault(c.id, c)
    return tuple(by_id[k] for k in sorted(by_id))


@dataclass
class KnowledgeGraph:
    """A persistent, deduplicating store of citations, findings, claims, gaps."""

    question: str = ""
    wave: int = 0
    citations: dict[str, Citation] = field(default_factory=dict)
    findings: dict[str, Finding] = field(default_factory=dict)
    claims: dict[str, Claim] = field(default_factory=dict)
    gaps: dict[str, Gap] = field(default_factory=dict)

    # --- mutating adds (return was_new) ---------------------------------

    def add_citation(self, citation: Citation) -> tuple[Citation, bool]:
        cid = citation.id
        if cid in self.citations:
            return self.citations[cid], False
        self.citations[cid] = citation
        return citation, True

    def add_finding(self, finding: Finding) -> tuple[Finding, bool]:
        for c in finding.citations:
            self.add_citation(c)
        fid = finding.id
        if fid in self.findings:
            return self.findings[fid], False
        self.findings[fid] = finding
        return finding, True

    def add_claim(self, claim: Claim) -> tuple[Claim, bool]:
        """Add a claim, merging support + provenance if it already exists.

        Merge keeps the existing status (a refuted tombstone stays refuted) and
        the earliest ``first_seen_wave``; it unions support citations and
        finding provenance. Returns ``was_new=False`` for a re-discovery.
        """
        for c in claim.support:
            self.add_citation(c)
        cid = claim.id
        existing = self.claims.get(cid)
        if existing is None:
            self.claims[cid] = claim
            return claim, True
        merged = replace(
            existing,
            support=_merge_citations(existing.support, claim.support),
            finding_ids=tuple(sorted(set(existing.finding_ids) | set(claim.finding_ids))),
            first_seen_wave=min(existing.first_seen_wave, claim.first_seen_wave),
        )
        self.claims[cid] = merged
        return merged, False

    def add_gap(self, gap: Gap) -> tuple[Gap, bool]:
        gid = gap.id
        if gid in self.gaps:
            return self.gaps[gid], False
        self.gaps[gid] = gap
        return gap, True

    # --- status transitions ---------------------------------------------

    def set_claim_status(self, claim_id: str, status: ClaimStatus, reason: str = "") -> Claim:
        existing = self.claims[claim_id]
        updated = replace(existing, status=status, verdict_reason=reason)
        self.claims[claim_id] = updated
        return updated

    def close_gap(self, gap_id: str) -> Gap:
        existing = self.gaps[gap_id]
        updated = replace(existing, status=GapStatus.CLOSED)
        self.gaps[gap_id] = updated
        return updated

    # --- queries (all deterministic, sorted by id) ----------------------

    def open_gaps(self) -> list[Gap]:
        return [self.gaps[k] for k in sorted(self.gaps) if self.gaps[k].status is GapStatus.OPEN]

    def claims_by_status(self, status: ClaimStatus) -> list[Claim]:
        return [self.claims[k] for k in sorted(self.claims) if self.claims[k].status is status]

    def unverified_claims(self) -> list[Claim]:
        return self.claims_by_status(ClaimStatus.UNVERIFIED)

    def supported_claims(self) -> list[Claim]:
        return self.claims_by_status(ClaimStatus.SUPPORTED)

    def stats(self) -> dict[str, int]:
        return {
            "citations": len(self.citations),
            "findings": len(self.findings),
            "claims": len(self.claims),
            "claims_unverified": len(self.claims_by_status(ClaimStatus.UNVERIFIED)),
            "claims_supported": len(self.claims_by_status(ClaimStatus.SUPPORTED)),
            "claims_refuted": len(self.claims_by_status(ClaimStatus.REFUTED)),
            "gaps": len(self.gaps),
            "gaps_open": len(self.open_gaps()),
            "wave": self.wave,
        }

    # --- serialization (deterministic key ordering) ---------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "question": self.question,
            "wave": self.wave,
            "citations": [self.citations[k].to_dict() for k in sorted(self.citations)],
            "findings": [self.findings[k].to_dict() for k in sorted(self.findings)],
            "claims": [self.claims[k].to_dict() for k in sorted(self.claims)],
            "gaps": [self.gaps[k].to_dict() for k in sorted(self.gaps)],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KnowledgeGraph:
        graph = cls(question=data.get("question", ""), wave=int(data.get("wave", 0)))
        for c in data.get("citations", []):
            graph.add_citation(Citation.from_dict(c))
        for f in data.get("findings", []):
            graph.add_finding(Finding.from_dict(f))
        for cl in data.get("claims", []):
            claim = Claim.from_dict(cl)
            graph.claims[claim.id] = claim  # preserve status verbatim, no merge on load
        for g in data.get("gaps", []):
            gap = Gap.from_dict(g)
            graph.gaps[gap.id] = gap
        return graph

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)

    def save(self, path: str | Path) -> None:
        """Atomically write the graph to ``path`` (tmp file + os.replace)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(self.to_json())
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    @classmethod
    def load(cls, path: str | Path) -> KnowledgeGraph:
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))
