from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from acgs_cft_governance_pack import evaluate_plan, load_policies, write_evidence_jsonl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acgs-cft-govern",
        description="Evaluate Terraform plan JSON against ACGS CFT governance controls.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate = subparsers.add_parser("evaluate", help="Evaluate a Terraform plan JSON file.")
    evaluate.add_argument("--plan", required=True, type=Path, help="Path to terraform show -json output.")
    evaluate.add_argument(
        "--policy-dir",
        type=Path,
        default=Path("policies"),
        help="Directory containing YAML policy files.",
    )
    evaluate.add_argument(
        "--policy",
        action="append",
        type=Path,
        default=[],
        help="Additional YAML policy file. Can be passed more than once.",
    )
    evaluate.add_argument("--actor", required=True, help="Actor id recorded in the evidence bundle.")
    evaluate.add_argument("--role", required=True, help="Actor role recorded in the evidence bundle.")
    evaluate.add_argument("--tenant", default="default", help="Tenant or environment scope.")
    evaluate.add_argument("--out", type=Path, help="Evidence JSONL output path.")
    evaluate.add_argument("--pretty", action="store_true", help="Print formatted evaluation output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "evaluate":
        return 1

    with args.plan.open("r", encoding="utf-8") as handle:
        plan = json.load(handle)

    policies = load_policies(args.policy_dir, args.policy)
    evidence = evaluate_plan(
        plan,
        policies,
        actor_id=args.actor,
        actor_role=args.role,
        tenant=args.tenant,
    )

    if args.out:
        write_evidence_jsonl(args.out, evidence)

    if args.pretty:
        print(json.dumps(evidence, indent=2, sort_keys=True))
    else:
        print(f"{evidence['decision'].upper()}: {evidence['reason']}", file=sys.stderr)
        print(f"plan_hash={evidence['plan_hash']}", file=sys.stderr)
        print(f"merkle_root={evidence['merkle_root']}", file=sys.stderr)

    return 0 if evidence["decision"] == "allow" else 2
