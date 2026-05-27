"""CLI adapter for Admission Gate v0.1.

Usage::

    python -m governance.admission.cli decide \
        --request admission_request.json \
        --policy policy_bundle.json \
        --out admission_decision.json

    python -m governance.admission.cli verify \
        --request admission_request.json \
        --decision admission_decision.json \
        --policy policy_bundle.json

Exit codes:

    0 — allow
    0 — verify ok
    10 — deny
    11 — transform
    12 — require_review
    20 — verify failed (replay error)
    2  — argument / file error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from governance.admission.gate import decide
from governance.admission.policy import load_policy_bundle
from governance.admission.replay import (
    ReplayError,
    verify_decision,
    verify_decision_with_execution,
)

_DECISION_EXIT = {"allow": 0, "deny": 10, "transform": 11, "require_review": 12}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="acgs-admission", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_dec = sub.add_parser("decide", help="evaluate an admission request")
    p_dec.add_argument("--request", required=True, help="path to admission request JSON")
    p_dec.add_argument("--policy", required=True, help="path to policy bundle JSON")
    p_dec.add_argument("--out", required=True, help="path to write decision JSON")
    p_dec.add_argument("--quiet", action="store_true", help="suppress stdout (still writes --out)")

    p_ver = sub.add_parser("verify", help="verify a decision receipt")
    p_ver.add_argument("--request", required=True)
    p_ver.add_argument("--decision", required=True)
    p_ver.add_argument("--policy", required=True)
    p_ver.add_argument("--execution-events", default=None, help="optional path to JSON list of execution events")
    p_ver.add_argument("--review-receipts", default=None, help="optional path to JSON list of human-review receipts")

    args = parser.parse_args(argv)
    if args.cmd == "decide":
        return _cmd_decide(args)
    if args.cmd == "verify":
        return _cmd_verify(args)
    parser.error(f"unknown command {args.cmd!r}")
    return 2


def _cmd_decide(args: argparse.Namespace) -> int:
    request = _load_json(args.request)
    bundle = load_policy_bundle(args.policy)
    decision = decide(request, policy_bundle=bundle)
    Path(args.out).write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    if not args.quiet:
        print(
            json.dumps(
                {
                    "decision": decision["decision"],
                    "reason_code": decision["reason_code"],
                    "decision_id": decision["decision_id"],
                    "receipt_id": decision["receipt"]["receipt_id"],
                    "out": args.out,
                },
                indent=2,
            )
        )
    return _DECISION_EXIT[decision["decision"]]


def _cmd_verify(args: argparse.Namespace) -> int:
    request = _load_json(args.request)
    decision = _load_json(args.decision)
    bundle = load_policy_bundle(args.policy)
    events = _load_json(args.execution_events) if args.execution_events else None
    reviews = _load_json(args.review_receipts) if args.review_receipts else None
    try:
        if events is not None or reviews is not None:
            report = verify_decision_with_execution(
                request=request,
                decision=decision,
                policy_bundle=bundle,
                execution_events=events,
                human_review_receipts=reviews,
            )
        else:
            report = verify_decision(request=request, decision=decision, policy_bundle=bundle)
    except ReplayError as exc:
        print(json.dumps({"ok": False, "code": exc.code, "message": str(exc)}, indent=2), file=sys.stderr)
        return 20
    print(json.dumps({"ok": True, **{k: v for k, v in report.items() if k != "ok"}}, indent=2))
    return 0


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


if __name__ == "__main__":
    raise SystemExit(main())
