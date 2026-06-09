"""The self-deepening research loop.

Each wave: derive queries from the question + open gaps, *close* those gaps
(they have now been investigated — this is what lets the loop reach a real
fixed point rather than running to the cap), fan out search into findings,
extract claims from genuinely-new findings, adversarially verify every
unverified claim, then ask a completeness critic what is still missing.

Convergence: a wave is "dry" when it adds no new claims and no new gaps *and*
suffered no parse failures. ``patience`` consecutive dry waves stop the run;
``max_waves`` is the hard ``max_iterations`` backstop.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from delve.analysis import Analyst, ParseError
from delve.backends.base import SearchClient, SupportsUsage
from delve.domain import ClaimStatus, Finding
from delve.graph import KnowledgeGraph

_T = TypeVar("_T")
_R = TypeVar("_R")


@dataclass
class ResearchConfig:
    max_waves: int = 4
    patience: int = 1  # stop after this many consecutive dry waves
    search_limit: int = 5
    queries_per_wave: int = 4
    verify_samples: int = 1
    max_workers: int = 1  # >1 fans out search concurrently (order preserved)
    graph_path: str | Path | None = None
    trajectory_path: str | Path | None = None


@dataclass(frozen=True)
class RunResult:
    graph: KnowledgeGraph
    waves: int
    converged: bool
    events: list[dict[str, Any]]
    usage: dict[str, Any] = field(default_factory=dict)


@dataclass
class Engine:
    search: SearchClient
    analyst: Analyst
    config: ResearchConfig = field(default_factory=ResearchConfig)
    graph: KnowledgeGraph = field(default_factory=KnowledgeGraph)
    events: list[dict[str, Any]] = field(default_factory=list)
    extracted: set[str] = field(default_factory=set)  # finding ids already extracted

    def _emit(self, etype: str, **data: Any) -> None:
        event = {"wave": self.graph.wave, "type": etype, **data}
        self.events.append(event)
        if self.config.trajectory_path is not None:
            tp = Path(self.config.trajectory_path)
            tp.parent.mkdir(parents=True, exist_ok=True)
            with tp.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    def _fan_out(self, items: Sequence[_T], fn: Callable[[_T], _R]) -> list[_R]:
        if self.config.max_workers <= 1 or len(items) <= 1:
            return [fn(x) for x in items]
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as pool:
            return list(pool.map(fn, items))  # map preserves input order

    def run(self, question: str) -> RunResult:
        self.graph.question = question
        self._emit("run_start", question=question)
        consecutive_dry = 0
        converged = False
        wave = 0
        for wave in range(1, self.config.max_waves + 1):
            self.graph.wave = wave
            self._emit("wave_start")
            parse_failed = False

            # 1. derive queries from question + open gaps, then close those gaps.
            open_gaps = self.graph.open_gaps()
            try:
                queries = self.analyst.derive_queries(
                    question, open_gaps, wave=wave, limit=self.config.queries_per_wave
                )
            except ParseError as exc:
                parse_failed = True
                queries = []
                self._emit("parse_error", op="derive_queries", detail=str(exc))
            if not queries:
                queries = [question]
            self._emit("queries", queries=queries)
            for gap in open_gaps:
                self.graph.close_gap(gap.id)

            # 2. fan out search into findings.
            hit_lists = self._fan_out(
                queries, lambda q: self.search.search(q, limit=self.config.search_limit)
            )
            new_findings: list[Finding] = []
            for query, hits in zip(queries, hit_lists, strict=True):
                for hit in hits:
                    finding = Finding(
                        text=hit.snippet or hit.title or hit.url,
                        query=query,
                        wave=wave,
                        citations=(hit.to_citation(),),
                    )
                    _, is_new = self.graph.add_finding(finding)
                    if is_new:
                        new_findings.append(finding)
            self._emit("search", queries=len(queries), new_findings=len(new_findings))

            # 3. extract claims from findings not yet *successfully* extracted.
            #    Gating on extraction success (not finding novelty) means a parse
            #    failure leaves those findings pending and retries them next wave,
            #    instead of orphaning their claims behind the dedup gate.
            new_claims = 0
            pending = [
                self.graph.findings[k]
                for k in sorted(self.graph.findings)
                if k not in self.extracted
            ]
            if pending:
                try:
                    claims = self.analyst.extract_claims(pending, wave=wave)
                except ParseError as exc:
                    parse_failed = True
                    self._emit("parse_error", op="extract_claims", detail=str(exc))
                else:
                    for finding in pending:
                        self.extracted.add(finding.id)  # mark extracted only on success
                    for claim in claims:
                        _, is_new = self.graph.add_claim(claim)
                        if is_new:
                            new_claims += 1
            self._emit("claims", new_claims=new_claims, pending_findings=len(pending))

            # 4. adversarially verify every still-unverified claim.
            for claim in self.graph.unverified_claims():
                if not claim.support:
                    self.graph.set_claim_status(
                        claim.id, ClaimStatus.REFUTED, "no supporting sources"
                    )
                    self._emit("verdict", claim=claim.id, status="refuted", reason="no sources")
                    continue
                try:
                    verdict = self.analyst.verify_claim(claim, samples=self.config.verify_samples)
                except ParseError as exc:
                    parse_failed = True
                    self._emit("parse_error", op="verify_claim", claim=claim.id, detail=str(exc))
                    continue  # leave unverified; a later wave retries
                status = ClaimStatus.SUPPORTED if verdict.supported else ClaimStatus.REFUTED
                self.graph.set_claim_status(claim.id, status, verdict.reason)
                self._emit("verdict", claim=claim.id, status=status.value, reason=verdict.reason)

            # 5. completeness critic proposes new gaps.
            new_gaps = 0
            try:
                proposed = self.analyst.propose_gaps(question, self.graph, wave=wave)
            except ParseError as exc:
                parse_failed = True
                proposed = []
                self._emit("parse_error", op="propose_gaps", detail=str(exc))
            for gap in proposed:
                _, is_new = self.graph.add_gap(gap)
                if is_new:
                    new_gaps += 1
            self._emit("gaps", new_gaps=new_gaps)

            if self.config.graph_path is not None:
                self.graph.save(self.config.graph_path)

            # 6. convergence — dryness, not exhaustion of the cap.
            dry = new_claims == 0 and new_gaps == 0 and not parse_failed
            self._emit(
                "wave_end",
                new_claims=new_claims,
                new_gaps=new_gaps,
                dry=dry,
                parse_failed=parse_failed,
            )
            if dry:
                consecutive_dry += 1
                if consecutive_dry >= self.config.patience:
                    converged = True
                    break
            else:
                consecutive_dry = 0

        usage = (
            self.analyst.llm.get_usage_summary()
            if isinstance(self.analyst.llm, SupportsUsage)
            else {}
        )
        self._emit("run_end", waves=wave, converged=converged, usage=usage)
        return RunResult(
            graph=self.graph,
            waves=wave,
            converged=converged,
            events=self.events,
            usage=usage,
        )
