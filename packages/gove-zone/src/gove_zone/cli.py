"""Installed command-line tools for Gove Zone runtime evidence."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from gove_zone.audit import ChainHashAuditStore
from gove_zone.benchmark_adapters import load_benchmark_suite
from gove_zone.decision import Decision
from gove_zone.evaluation import evaluate_policy_scenarios
from gove_zone.integration import (
    GateMode,
    GateModeError,
    current_gate_mode,
    emit_receipt_for_hook,
    resolve_gate_mode_path,
)
from gove_zone.policy import RuleSetPolicy
from gove_zone.setup import (
    detect_environment,
    generate_config,
    instructions,
    validate_dependencies,
)


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True, ensure_ascii=False))


def _find_event(
    store: ChainHashAuditStore,
    event_id: str,
) -> dict[str, Any] | None:
    for event in store.iter_events():
        if event.get("event_id") == event_id:
            return event
    return None


def _replay(args: argparse.Namespace) -> int:
    base: dict[str, Any] = {
        "event_id": args.event,
        "expected_audit_hash": args.audit_hash,
    }

    if args.audit is None:
        _emit(
            {
                **base,
                "status": "hash-only",
                "verified": False,
                "reason": "provide --audit PATH to verify the full chain",
            }
        )
        return 0

    audit_path = Path(args.audit)
    store = ChainHashAuditStore(audit_path)
    chain = store.verify_chain()
    event = _find_event(store, args.event)
    actual_hash = event.get("event_hash") if event is not None else None
    hash_matches = args.audit_hash is None or actual_hash == args.audit_hash
    verified = bool(chain["valid"] and event is not None and hash_matches)

    _emit(
        {
            **base,
            "audit": str(audit_path),
            "status": "verified" if verified else "failed",
            "verified": verified,
            "chain_valid": chain["valid"],
            "checked": chain["checked"],
            "event_found": event is not None,
            "actual_audit_hash": actual_hash,
            "decision": event.get("decision") if event is not None else None,
            "policy_version": (event.get("policy_version") if event is not None else None),
            "failures": chain["failures"],
        }
    )
    return 0 if verified else 1


def _setup(args: argparse.Namespace) -> int:
    if args.format == "json":
        _emit(
            {
                "environment": detect_environment().to_dict(),
                "config": generate_config(enforce=args.enforce),
            }
        )
    else:
        sys.stdout.write(instructions(enforce=args.enforce))
    return 0


def _doctor(args: argparse.Namespace) -> int:
    env = detect_environment()
    report = validate_dependencies()
    _emit(
        {
            "ok": report.ok,
            "gate_mode": env.gate_mode,
            "environment": env.to_dict(),
            "checks": report.checks,
        }
    )
    return 0 if report.ok else 1


def _gate(args: argparse.Namespace) -> int:
    """Evaluate one runtime-hook payload through the gate adapter.

    Reads a JSON object from --event-file or stdin and emits the resulting
    Receipt (or null on observe-mode failure) as JSON. When --policy-bundle is
    supplied, DENY and ESCALATE decisions exit non-zero so hook hosts can block
    the side effect before it runs.
    """
    if args.event_file:
        payload_text = Path(args.event_file).read_text(encoding="utf-8")
    else:
        payload_text = sys.stdin.read()

    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        print(f"gate: invalid JSON: {exc}", file=sys.stderr)
        return 2

    policy = None
    if args.policy_bundle:
        try:
            policy = RuleSetPolicy.load(args.policy_bundle)
        except Exception as exc:  # noqa: BLE001 — invalid gate config must block hooks
            print(f"gate: failed to load policy bundle: {exc}", file=sys.stderr)
            return 2

    try:
        receipt = emit_receipt_for_hook(
            payload,
            action_kind=args.action_kind,
            actor=args.actor,
            run_id=args.run_id,
            policy=policy,
        )
    except GateModeError as exc:
        print(f"gate (enforce): {exc}", file=sys.stderr)
        return 2

    blocked = receipt is not None and receipt.record.decision in {
        Decision.DENY,
        Decision.ESCALATE,
    }
    _emit(
        {
            "gate_mode": current_gate_mode().value,
            "policy_bundle": str(args.policy_bundle) if args.policy_bundle else None,
            "decision": receipt.record.decision.value if receipt is not None else None,
            "blocked": blocked,
            "receipt": receipt.to_dict() if receipt is not None else None,
        }
    )
    if receipt is None:
        return 1
    return 1 if blocked else 0


def _enable(args: argparse.Namespace) -> int:
    """Flip the gate mode for this project by writing ``.gove-zone/gate.mode``.

    Provides a single, agent-followable surface — no env-var juggling, no
    settings.json edits — to turn the gate from observe (fail-open) into
    enforce (fail-closed) or back again.
    """
    mode = GateMode.ENFORCE if args.enforce else GateMode.OBSERVE
    path = resolve_gate_mode_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(mode.value + "\n", encoding="utf-8")
    _emit(
        {
            "gate_mode": mode.value,
            "gate_mode_path": str(path),
            "effective": current_gate_mode().value,
            "note": "env var GOVE_ZONE_GATE_MODE overrides this file when set",
        }
    )
    return 0


def _policy_inspect(args: argparse.Namespace) -> int:
    policy = RuleSetPolicy.load(args.bundle)
    _emit(
        {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "rule_count": len(policy.rules),
            "rules": [
                {
                    "id": rule.rule_id,
                    "effect": rule.effect.value,
                    "tools": sorted(rule.tools),
                    "path_prefix": list(rule.path_prefix),
                }
                for rule in policy.rules
            ],
        }
    )
    return 0


def _policy_export(args: argparse.Namespace) -> int:
    policy = RuleSetPolicy.load(args.bundle)
    output = Path(args.output)
    policy.dump(output)
    _emit(
        {
            "output": str(output),
            "policy_id": policy.policy_id,
            "version": policy.version,
            "rule_count": len(policy.rules),
        }
    )
    return 0


def _eval(args: argparse.Namespace) -> int:
    policy = RuleSetPolicy.load(args.bundle)
    dataset, scenarios = load_benchmark_suite(
        args.scenarios,
        benchmark_format=args.benchmark_format,
    )
    report = evaluate_policy_scenarios(policy, scenarios, dataset=dataset)
    _emit(report.to_dict())
    return 0 if report.failed == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gove-zone",
        description="Gove Zone runtime governance: replay, setup, doctor, gate.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    replay = subparsers.add_parser(
        "replay",
        help="verify a governed action against an audit JSONL chain",
    )
    replay.add_argument("--event", required=True, help="event_id to replay")
    replay.add_argument(
        "--audit",
        help="path to audit.jsonl; omitted command returns hash-only evidence",
    )
    replay.add_argument(
        "--audit-hash",
        help="expected audit event hash from a receipt or console action",
    )
    replay.set_defaults(func=_replay)

    setup = subparsers.add_parser(
        "setup",
        help="emit copy-paste setup instructions for the detected host runtime",
    )
    setup.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="output format (default: markdown)",
    )
    setup.add_argument(
        "--enforce",
        action="store_true",
        help="render the enforce-mode (fail-closed) variant",
    )
    setup.set_defaults(func=_setup)

    doctor = subparsers.add_parser(
        "doctor",
        help="validate gove-zone install + audit writability; exit 1 on issues",
    )
    doctor.set_defaults(func=_doctor)

    gate = subparsers.add_parser(
        "gate",
        help="run one runtime-hook payload through the integration adapter",
    )
    gate.add_argument(
        "--event-file",
        help="path to a JSON file with the hook payload (default: stdin)",
    )
    gate.add_argument(
        "--action-kind",
        default="edit",
        help="action_kind tag attached to the receipt (default: edit)",
    )
    gate.add_argument(
        "--actor",
        default="gove-zone-cli",
        help="actor identity recorded in the receipt",
    )
    gate.add_argument(
        "--run-id",
        default=None,
        help="optional run/session id tag for the receipt",
    )
    gate.add_argument(
        "--policy-bundle",
        help=(
            "optional RuleSetPolicy JSON bundle; DENY/ESCALATE exits non-zero "
            "after the receipt is written"
        ),
    )
    gate.set_defaults(func=_gate)

    enable = subparsers.add_parser(
        "enable",
        help="set this project's gate mode (writes .gove-zone/gate.mode)",
    )
    mode_group = enable.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--enforce",
        dest="enforce",
        action="store_true",
        help="enable fail-closed enforcement for this project",
    )
    mode_group.add_argument(
        "--observe",
        dest="enforce",
        action="store_false",
        help="revert to observe-only (fail-open) mode for this project",
    )
    enable.set_defaults(func=_enable)

    policy = subparsers.add_parser(
        "policy",
        help="inspect and canonicalize RuleSetPolicy bundles",
    )
    policy_subparsers = policy.add_subparsers(dest="policy_command", required=True)

    inspect_policy = policy_subparsers.add_parser(
        "inspect",
        help="summarize a policy bundle without executing it",
    )
    inspect_policy.add_argument(
        "--bundle",
        required=True,
        help="path to a RuleSetPolicy JSON bundle",
    )
    inspect_policy.set_defaults(func=_policy_inspect)

    export_policy = policy_subparsers.add_parser(
        "export",
        help="write a canonical RuleSetPolicy JSON bundle",
    )
    export_policy.add_argument(
        "--bundle",
        required=True,
        help="path to a RuleSetPolicy JSON bundle",
    )
    export_policy.add_argument(
        "--output",
        required=True,
        help="path for the canonical JSON bundle",
    )
    export_policy.set_defaults(func=_policy_export)

    eval_parser = subparsers.add_parser(
        "eval",
        help="replay a policy bundle against benchmark-style scenario fixtures",
    )
    eval_parser.add_argument(
        "--bundle",
        required=True,
        help="path to a RuleSetPolicy JSON bundle",
    )
    eval_parser.add_argument(
        "--scenarios",
        required=True,
        help="path to an evaluation fixture JSON file",
    )
    eval_parser.add_argument(
        "--benchmark-format",
        choices=["generic", "agentdojo", "injecagent", "toolemu"],
        default="generic",
        help="fixture adapter format (default: generic)",
    )
    eval_parser.set_defaults(func=_eval)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
