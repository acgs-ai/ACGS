"""Command-line entrypoint: ``delve run "<question>"``.

Defaults to the offline fake backends so the command runs end-to-end with no
API keys; pass ``--llm anthropic --search exa`` (with the matching extras and
keys) for real research. ``--resume`` loads a persisted graph and deepens it
further — the across-session persistence payoff.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from delve.analysis import Analyst
from delve.backends import make_llm, make_search
from delve.brief import render_brief
from delve.engine import Engine, ResearchConfig
from delve.graph import KnowledgeGraph


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="delve", description="Self-deepening research engine.")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Research a question and emit a brief.")
    run.add_argument("question", nargs="?", default=None, help="The research question.")
    run.add_argument("--llm", default="fake", help="LLM backend (default: fake).")
    run.add_argument("--search", default="fake", help="Search backend (default: fake).")
    run.add_argument("--max-waves", type=int, default=4)
    run.add_argument("--queries", type=int, default=4, help="Queries per wave.")
    run.add_argument("--search-limit", type=int, default=5)
    run.add_argument("--verify-samples", type=int, default=1)
    run.add_argument("--workers", type=int, default=1, help="Concurrent search fan-out.")
    run.add_argument("--out", type=Path, default=None, help="Write the brief here (else stdout).")
    run.add_argument("--graph", type=Path, default=None, help="Persist the knowledge graph here.")
    run.add_argument("--trace", type=Path, default=None, help="Append-only JSONL trajectory log.")
    run.add_argument("--resume", type=Path, default=None, help="Load + deepen an existing graph.")
    return parser


def _cmd_run(args: argparse.Namespace) -> int:
    if args.resume is not None:
        if not args.resume.exists():
            print(f"error: resume path does not exist: {args.resume}", file=sys.stderr)
            return 2
        graph = KnowledgeGraph.load(args.resume)
        if args.graph is None:
            args.graph = args.resume  # persist back to the same file by default
    else:
        graph = KnowledgeGraph()

    question = args.question or graph.question
    if not question:
        print("error: a question is required (positional arg or a resumed graph).", file=sys.stderr)
        return 2
    if args.verify_samples < 1:
        print("error: --verify-samples must be >= 1.", file=sys.stderr)
        return 2

    config = ResearchConfig(
        max_waves=args.max_waves,
        queries_per_wave=args.queries,
        search_limit=args.search_limit,
        verify_samples=args.verify_samples,
        max_workers=args.workers,
        graph_path=args.graph,
        trajectory_path=args.trace,
    )
    engine = Engine(
        search=make_search(args.search),
        analyst=Analyst(make_llm(args.llm)),
        config=config,
        graph=graph,
        # Treat findings already in a resumed graph as extracted, so resume only
        # extracts genuinely-new findings instead of re-batching the whole history.
        extracted=set(graph.findings),
    )
    result = engine.run(question)
    brief = render_brief(result.graph)

    if args.out is not None:
        args.out.write_text(brief, encoding="utf-8")
        print(f"Wrote brief to {args.out}", file=sys.stderr)
    else:
        print(brief)

    stats = result.graph.stats()
    calls = result.usage.get("total_calls", 0)
    print(
        f"[delve] {stats['claims_supported']} supported · {stats['claims_refuted']} refuted · "
        f"{stats['gaps_open']} open gaps · {result.waves} waves · "
        f"converged={result.converged} · llm_calls={calls}",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    return 1  # pragma: no cover - argparse enforces a valid subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
