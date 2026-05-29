"""Installed command-line tools for Gove Zone runtime evidence."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from gove_zone import __version__
from gove_zone.audit import ChainHashAuditStore
from gove_zone.benchmark_adapters import load_benchmark_suite
from gove_zone.decision import Decision
from gove_zone.evaluation import evaluate_policy_scenarios
from gove_zone.integration import (
    GateMode,
    GateModeError,
    current_gate_mode,
    emit_receipts_for_hook,
    resolve_gate_mode_path,
)
from gove_zone.policy import RuleSetPolicy
from gove_zone.setup import (
    detect_environment,
    generate_config,
    instructions,
    validate_dependencies,
)
from gove_zone.smoke import run_smoke


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
        receipts = emit_receipts_for_hook(
            payload,
            action_kind=args.action_kind,
            actor=args.actor,
            run_id=args.run_id,
            policy=policy,
        )
    except GateModeError as exc:
        print(f"gate (enforce): {exc}", file=sys.stderr)
        return 2

    blocking_receipts = [
        receipt
        for receipt in (receipts or ())
        if receipt.record.decision in {Decision.DENY, Decision.ESCALATE}
    ]
    primary_receipt = (
        blocking_receipts[0] if blocking_receipts else (receipts[-1] if receipts else None)
    )
    blocked = bool(blocking_receipts)
    _emit(
        {
            "gate_mode": current_gate_mode().value,
            "policy_bundle": str(args.policy_bundle) if args.policy_bundle else None,
            "decision": (
                primary_receipt.record.decision.value if primary_receipt is not None else None
            ),
            "blocked": blocked,
            "receipt": primary_receipt.to_dict() if primary_receipt is not None else None,
            "receipts": [receipt.to_dict() for receipt in (receipts or ())],
            "receipt_count": len(receipts or ()),
        }
    )
    if not receipts:
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


def _smoke(args: argparse.Namespace) -> int:
    report = run_smoke(args.audit)
    _emit(report)
    return 0 if report["status"] == "pass" else 1


def _proofpack(args: argparse.Namespace) -> int:
    import shutil

    from gove_zone.audit import ChainHashAuditStore
    from gove_zone.errors import ReceiptValidationError
    from gove_zone.executor import execute_with_receipt
    from gove_zone.policy import RuleSetPolicy
    from gove_zone.tenant import TenantPolicyStore, evaluate_tenant_action

    # 1. Setup output directory
    dist_dir = Path("dist-govern-zone-proofpack")
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    dist_dir.mkdir(parents=True, exist_ok=True)

    receipts_dir = dist_dir / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)

    # 2. Setup Tenant Policy Store
    tenant_store_dir = dist_dir / "tenant_store"
    tenant_store = TenantPolicyStore(tenant_store_dir)

    policy = RuleSetPolicy.from_dict(
        {
            "id": "compliance-ruleset/v1",
            "rules": [
                {
                    "id": "BLOCK_SSH_KEY_ACCESS",
                    "effect": "deny",
                    "tools": ["runtime.file.write"],
                    "path_prefix": "id_rsa",
                    "reason": "Direct access to SSH keys is strictly forbidden",
                }
            ],
        }
    )
    tenant_store.store_bundle("tenant-A", policy)

    # 3. Setup Audit Store
    audit_path = dist_dir / "audit.jsonl"
    audit_store = ChainHashAuditStore(audit_path)

    # Results tracker
    conformance_results = {
        "allowed_action_executed": False,
        "denied_action_blocked": False,
        "transformed_action_executed": False,
        "missing_receipt_blocked": False,
        "tampered_receipt_blocked": False,
        "audit_chain_verified": False,
    }

    # Helper dummy side effects
    class DummyTool:
        def __init__(self) -> None:
            self.called = False
            self.args: dict[str, Any] = {}

        def run(self, **kwargs: Any) -> str:
            self.called = True
            self.args = kwargs
            return "executed"

    # --- Scenario 1: Allowed Action ---
    tool = DummyTool()
    allowed_args = {"path": "public_report.txt", "content": "All safe"}
    allowed_receipt = evaluate_tenant_action(
        store=tenant_store,
        tenant_id="tenant-A",
        requester_tenant_id="tenant-A",
        action="runtime.file.write",
        args=allowed_args,
        goal="Write compliance report",
        execution_boundary="local-sandbox",
        request_id="req-allowed",
        actor="compliance-officer",
        audit_store=audit_store,
    )
    (receipts_dir / "allowed_receipt.json").write_text(allowed_receipt.to_json(), encoding="utf-8")
    res = execute_with_receipt(
        tool_fn=tool.run,
        args=allowed_args,
        receipt=allowed_receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
    )
    conformance_results["allowed_action_executed"] = res == "executed" and tool.called

    # --- Scenario 2: Denied Action ---
    tool_denied = DummyTool()
    denied_args = {"path": "id_rsa", "content": "compromised"}
    denied_receipt = evaluate_tenant_action(
        store=tenant_store,
        tenant_id="tenant-A",
        requester_tenant_id="tenant-A",
        action="runtime.file.write",
        args=denied_args,
        goal="Attempt key exfiltration",
        execution_boundary="local-sandbox",
        request_id="req-denied",
        actor="compromised-agent",
        audit_store=audit_store,
    )
    (receipts_dir / "denied_receipt.json").write_text(denied_receipt.to_json(), encoding="utf-8")
    try:
        execute_with_receipt(
            tool_fn=tool_denied.run,
            args=denied_args,
            receipt=denied_receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
        )
    except ReceiptValidationError:
        conformance_results["denied_action_blocked"] = not tool_denied.called

    # --- Scenario 3: Transformed Action ---
    from gove_zone.tenant import TransformPolicy

    transform_store = TenantPolicyStore(dist_dir / "transform_tenant_store")
    transform_store.store_bundle("tenant-A", TransformPolicy())

    tool_transformed = DummyTool()
    original_args = {"path": "untransformed.txt", "content": "safe"}
    transformed_receipt = evaluate_tenant_action(
        store=transform_store,
        tenant_id="tenant-A",
        requester_tenant_id="tenant-A",
        action="runtime.file.write",
        args=original_args,
        goal="Write file with transform",
        execution_boundary="local-sandbox",
        request_id="req-transformed",
        actor="compliance-officer",
        audit_store=audit_store,
    )
    (receipts_dir / "transformed_receipt.json").write_text(
        transformed_receipt.to_json(), encoding="utf-8"
    )

    # Executing original arguments fails with transform mismatch
    mismatch_blocked = False
    try:
        execute_with_receipt(
            tool_fn=tool_transformed.run,
            args=original_args,
            receipt=transformed_receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
        )
    except ReceiptValidationError:
        mismatch_blocked = True

    # Executing transformed args succeeds
    res_t = execute_with_receipt(
        tool_fn=tool_transformed.run,
        args={"path": "transformed.txt", "content": "safe"},
        receipt=transformed_receipt,
        expected_tenant_id="tenant-A",
        expected_execution_boundary="local-sandbox",
        expected_action="runtime.file.write",
    )
    conformance_results["transformed_action_executed"] = (
        mismatch_blocked
        and res_t == "executed"
        and tool_transformed.called
        and tool_transformed.args.get("path") == "transformed.txt"
    )

    # --- Scenario 4: Blocked Path (No Receipt) ---
    tool_no_receipt = DummyTool()
    try:
        execute_with_receipt(
            tool_fn=tool_no_receipt.run,
            args={"path": "public_report.txt"},
            receipt=None,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
        )
    except ReceiptValidationError:
        conformance_results["missing_receipt_blocked"] = not tool_no_receipt.called

    # --- Scenario 5: Blocked Path (Tampered Tenant ID) ---
    tool_tampered = DummyTool()
    import dataclasses

    tampered_receipt = dataclasses.replace(allowed_receipt, tenant_id="tenant-B")
    try:
        execute_with_receipt(
            tool_fn=tool_tampered.run,
            args=allowed_args,
            receipt=tampered_receipt,
            expected_tenant_id="tenant-A",
            expected_execution_boundary="local-sandbox",
            expected_action="runtime.file.write",
        )
    except ReceiptValidationError:
        conformance_results["tampered_receipt_blocked"] = not tool_tampered.called

    # 4. Audit Chain verification
    verification = audit_store.verify_chain()
    conformance_results["audit_chain_verified"] = verification["valid"]

    # Write verification.json
    (dist_dir / "verification.json").write_text(
        json.dumps(verification, indent=2), encoding="utf-8"
    )

    # Write conformance-results.json
    (dist_dir / "conformance-results.json").write_text(
        json.dumps(conformance_results, indent=2), encoding="utf-8"
    )

    # Write limitations.md
    limitations_content = """# Conformance Proof Pack Limitations & Disclaimers

- **Status**: Alpha (`0.1.0.dev0`).
- **Scope**: Local proof and production-shaped foundation only.
- **Certification**: NOT production-certified, NOT compliance-certified.
  Do not claim live production deployment or regulatory compliance without direct evidence.
- This conformance proof pack provides local verification that no-receipt and
  tampered-receipt execution paths fail closed. It does not constitute evidence
  of compliance with any security framework, law, or regulatory body.
"""
    (dist_dir / "limitations.md").write_text(limitations_content, encoding="utf-8")

    # Write manifest.json
    manifest = {
        "version": "0.1.0.dev0",
        "files": [
            "manifest.json",
            "receipts/allowed_receipt.json",
            "receipts/denied_receipt.json",
            "receipts/transformed_receipt.json",
            "audit.jsonl",
            "verification.json",
            "conformance-results.json",
            "limitations.md",
        ],
    }
    (dist_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    _emit(
        {
            "status": "pass",
            "output_directory": str(dist_dir),
            "results": conformance_results,
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gove-zone",
        description="Gove Zone runtime governance: replay, setup, doctor, gate.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show program's version number and exit",
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

    smoke = subparsers.add_parser(
        "smoke",
        help="run a local allow/deny/audit smoke proof for the runtime kernel",
    )
    smoke.add_argument(
        "--audit",
        help="optional path to retain the smoke audit JSONL as evidence",
    )
    smoke.set_defaults(func=_smoke)

    proofpack = subparsers.add_parser(
        "proofpack",
        help=(
            "generate a conformance proof pack folder with allowed, "
            "denied, and transformed evidence"
        ),
    )
    proofpack.set_defaults(func=_proofpack)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
