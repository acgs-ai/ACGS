"""Installed command-line tools for Gove Zone runtime evidence."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from gove_zone import __version__
from gove_zone.audit import ChainHashAuditStore
from gove_zone.benchmark_adapters import load_benchmark_suite
from gove_zone.consumption import ReceiptConsumptionLedger
from gove_zone.decision import Decision
from gove_zone.errors import AuditError, ConsumptionLedgerError
from gove_zone.evaluation import evaluate_policy_scenarios
from gove_zone.integration import (
    GateMode,
    GateModeError,
    current_gate_mode,
    emit_receipts_for_hook,
    resolve_gate_mode_path,
)
from gove_zone.policy import Policy, RuleSetPolicy
from gove_zone.replay import replay_from_side_store
from gove_zone.replay_store import ReplaySideStore
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


def _rederive(
    event: dict[str, Any] | None,
    side_record: dict[str, Any] | None,
    policy: Policy,
) -> dict[str, Any]:
    """Attempt true re-derivation and return the JSON-ready re-derivation block.

    ``attempted`` is False when there is no usable raw side record (missing or
    redacted), so the caller can fall back to today's event-only exit semantics.
    """
    if side_record is None or event is None:
        return {
            "attempted": False,
            "rederived": False,
            "rederivation_status": "no-side-record",
            "replayed_decision": None,
            "policy_version_match": False,
        }
    if side_record.get("redacted") is True:
        return {
            "attempted": False,
            "rederived": False,
            "rederivation_status": "redacted",
            "replayed_decision": None,
            "policy_version_match": False,
        }

    result = replay_from_side_store(event, side_record, policy)
    if not result.argument_hash_match:
        status = "argument-hash-mismatch"
    elif not result.policy_version_match:
        status = "policy-version-mismatch"
    elif result.matches:
        status = "verified"
    else:
        status = "decision-mismatch"
    return {
        "attempted": True,
        "rederived": result.re_derived and result.matches,
        "rederivation_status": status,
        "replayed_decision": result.replayed_decision.value,
        "policy_version_match": result.policy_version_match,
    }


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

    payload: dict[str, Any] = {
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

    side_store_path = getattr(args, "side_store", None)
    policy_bundle = getattr(args, "policy_bundle", None)

    # Re-derivation surface. Loading the bundle is a hook-style configuration
    # step: an invalid bundle exits 2 (mirrors `_gate`), never an allow.
    policy: Policy | None = None
    if policy_bundle is not None:
        try:
            policy = RuleSetPolicy.load(policy_bundle)
        except Exception as exc:  # noqa: BLE001 — bad replay config must not pass
            print(f"replay: failed to load policy bundle: {exc}", file=sys.stderr)
            return 2

    rederivation_attempted = False
    if side_store_path is not None and policy is not None:
        side_record = ReplaySideStore(side_store_path).get(args.event)
        block = _rederive(event, side_record, policy)
        rederivation_attempted = bool(block.pop("attempted"))
        payload.update(block)

    _emit(payload)

    rederived = bool(payload.get("rederived", False))
    overall = verified and (rederived if rederivation_attempted else True)
    return 0 if overall else 1


def _verify_ledger(args: argparse.Namespace) -> int:
    """Verify the tamper-evidence hash chain of a consumption ledger.

    Mirrors ``replay --audit``'s chain-verification surface for the
    enforcement-side single-use record: prints the
    :meth:`~gove_zone.consumption.ReceiptConsumptionLedger.verify_ledger`
    report and exits non-zero when the ledger is not ``valid``. A corrupt /
    unreadable ledger exits 2 (it cannot be verified), distinct from a readable
    ledger that fails integrity (exit 1).

    With ``--audit PATH`` it also reconciles every burn against that audit
    chain (forged-burn detection via
    :meth:`~gove_zone.consumption.ReceiptConsumptionLedger.reconcile`) and
    folds the reconcile result into the exit code.
    """
    ledger = ReceiptConsumptionLedger(Path(args.ledger))
    try:
        report = ledger.verify_ledger(expected_last_hash=args.expected_last_hash)
    except ConsumptionLedgerError as exc:
        print(f"verify-ledger: {exc}", file=sys.stderr)
        return 2

    payload: dict[str, Any] = {
        "ledger": str(args.ledger),
        "valid": report["valid"],
        "checked": report["checked"],
        "unverified_legacy": report["unverified_legacy"],
        "last_hash": report["last_hash"],
        "failures": report["failures"],
    }

    reconcile_ok = True
    if args.audit is not None:
        try:
            recon = ledger.reconcile(ChainHashAuditStore(Path(args.audit)))
        except (ConsumptionLedgerError, AuditError) as exc:
            # reconcile() walks the audit chain via iter_events(), which raises
            # AuditChainError (an AuditError) on a corrupt/malformed audit log —
            # report it fail-closed instead of crashing with a raw traceback.
            print(f"verify-ledger: {exc}", file=sys.stderr)
            return 2
        reconcile_ok = recon["valid"]
        payload["reconcile"] = {
            "valid": recon["valid"],
            "checked": recon["checked"],
            "audit_events": recon["audit_events"],
            "unmatched": recon["unmatched"],
        }

    _emit(payload)
    return 0 if (report["valid"] and reconcile_ok) else 1


def _prune_ledger(args: argparse.Namespace) -> int:
    """TTL-prune a consumption ledger: drop expired burned entries.

    Calls :meth:`~gove_zone.consumption.ReceiptConsumptionLedger.prune`, which
    removes only entries whose receipt has already expired, re-chains the
    survivors, and advances the prune watermark (clock-rollback defense) plus
    the high-water-mark. Checkpointing is auto-detected from a ``<ledger>.hwm``
    sidecar so prune keeps an existing high-water-mark consistent with the
    re-chained tail. A corrupt / unreadable ledger (or an unparseable ``--now``)
    exits 2 and prunes nothing — fail-closed.
    """
    ledger_path = Path(args.ledger)
    checkpoint = ledger_path.with_suffix(ledger_path.suffix + ".hwm").exists()
    ledger = ReceiptConsumptionLedger(ledger_path, checkpoint=checkpoint)

    now = None
    if args.now is not None:
        try:
            now = datetime.fromisoformat(args.now)
        except (ValueError, TypeError) as exc:
            print(f"prune-ledger: unparseable --now {args.now!r}: {exc}", file=sys.stderr)
            return 2

    try:
        report = ledger.prune(now=now)
    except ConsumptionLedgerError as exc:
        print(f"prune-ledger: {exc}", file=sys.stderr)
        return 2

    _emit(
        {
            "ledger": str(args.ledger),
            "pruned": report["pruned"],
            "kept": report["kept"],
            "last_hash": report["last_hash"],
            "watermark": report["watermark"],
        }
    )
    return 0


def _approve_escalation(args: argparse.Namespace) -> int:
    """Approve a parked governed-MCP escalation and mint an ALLOW receipt.

    Wraps :func:`gove_zone.escalation.approve_escalation` for the local stdio
    gateway pilot: reads the gateway config and a pending-escalation descriptor
    (emitted by ``GovernedGateway.pending_descriptor``), mints a signed approval
    receipt with the config's *distinct* validator, appends the approval to the
    audit chain, and prints the receipt plus its ``approval_audit_hash`` — the
    value the gateway pins as ``expected_audit_hash`` at resume. Single-use is
    enforced at the resume gate by the gateway's
    :class:`~gove_zone.consumption.ReceiptConsumptionLedger`, not here.

    A missing/invalid config, descriptor, or a self-validation clash exits 2
    (fail-closed) and mints nothing.
    """
    from gove_zone.adapters.mcp_gateway import load_gateway_config, pending_from_dict
    from gove_zone.errors import ReceiptValidationError
    from gove_zone.escalation import approve_escalation

    try:
        config = load_gateway_config(Path(args.config))
        descriptor = json.loads(Path(args.pending).read_text(encoding="utf-8"))
        pending = pending_from_dict(descriptor)
    except (OSError, ValueError, KeyError) as exc:
        print(f"approve-escalation: {exc}", file=sys.stderr)
        return 2

    store = ChainHashAuditStore(config.audit_path)
    try:
        receipt = approve_escalation(
            pending,
            validator=config.validator,
            authority=config.authority,
            tenant_id=config.tenant_id,
            execution_boundary=config.execution_boundary,
            policy_bundle_id=config.policy_bundle_id,
            policy_hash=config.policy.version,
            audit=store,
            expires_at=args.expires_at or "",
            signer=config.profile.signer,
        )
    except ReceiptValidationError as exc:
        print(f"approve-escalation: {exc}", file=sys.stderr)
        return 2

    _emit(
        {
            "pending_event_id": pending.record.event_id,
            "approval_audit_hash": receipt.audit_event_hash,
            "receipt": receipt.to_dict(),
        }
    )
    return 0


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
    settings.json edits — to pin the (default) fail-closed enforce mode or
    explicitly opt into observe (fail-open).
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
    # This conformance proofpack exercises the allow/deny/transform/tamper gate
    # behavior with UNSIGNED receipts — it runs the gate in explicit dev mode
    # (require_signature=False) so it stays self-contained and key-free. The
    # production profile (signed receipts, the default for execute_with_receipt)
    # is demonstrated separately in examples/receipt-gated-execution/demo.py.
    import shutil

    from gove_zone.audit import ChainHashAuditStore
    from gove_zone.errors import ReceiptValidationError
    from gove_zone.executor import execute_with_receipt
    from gove_zone.policy import RuleSetPolicy
    from gove_zone.receipt import Validator
    from gove_zone.tenant import TenantPolicyStore, evaluate_tenant_action

    council = Validator("constitutional-council")

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
        validator=council,
        authority="tenant-A/write-grant",
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
        expected_actor="compliance-officer",
        require_signature=False,  # dev-mode conformance proofpack (unsigned)
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
        validator=council,
        authority="tenant-A/write-grant",
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
            expected_actor="compromised-agent",
            require_signature=False,  # dev-mode conformance proofpack (unsigned)
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
        validator=council,
        authority="tenant-A/write-grant",
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
            expected_actor="compliance-officer",
            require_signature=False,  # dev-mode conformance proofpack (unsigned)
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
        expected_actor="compliance-officer",
        require_signature=False,  # dev-mode conformance proofpack (unsigned)
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
            expected_actor="compliance-officer",
            require_signature=False,  # dev-mode conformance proofpack (unsigned)
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
            expected_actor="compliance-officer",
            require_signature=False,  # dev-mode conformance proofpack (unsigned)
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
    limitations_content = f"""# Conformance Proof Pack Limitations & Disclaimers

- **Status**: Alpha (`{__version__}`).
- **Scope**: Local proof and production-shaped foundation only.
- **Certification**: NOT production-certified, NOT compliance-certified.
  Do not claim live production deployment or regulatory compliance without direct evidence.
- This conformance proof pack provides local verification that no-receipt and
  tampered-receipt execution paths fail closed. It does not constitute evidence
  of compliance with any security framework, law, or regulatory body.
"""
    (dist_dir / "limitations.md").write_text(limitations_content, encoding="utf-8")

    # Remove the audit append lock file so the pack directory contains exactly
    # the files listed in the manifest; the lock only guards concurrent appends
    # during generation and carries no evidence value.
    lock_path = dist_dir / "audit.jsonl.lock"
    if lock_path.exists():
        lock_path.unlink()

    # Write manifest.json
    #
    # Structured manifest the offline verifier (verify_proof_pack) can read: a
    # `receipts` array with one structured entry per receipt file actually written,
    # each carrying its declared verdict, plus an explicit `audit_chain` pointer so
    # accept receipts can be anchored against the pack's own chain. The declared
    # verdicts below mirror what `DecisionReceipt.verify()` observes for each file
    # (allow/transform self-validate => "accept"; the deny receipt raises
    # DENIED_RECEIPT => "reject"). reason_code is left null on the reject entry so
    # the verifier only requires an observed reject, not a brittle reason match.
    # The pack is dev-mode UNSIGNED (require_signature=False), so `verify-proofpack`
    # passes without a --verifier-key.
    manifest = {
        "version": __version__,
        "schema_version": "gove-zone/proof-pack/v1",
        "audit_chain": "audit.jsonl",
        "receipts": [
            {
                "name": "allowed",
                "file": "receipts/allowed_receipt.json",
                "declared_verdict": "accept",
                "reason_code": None,
            },
            {
                "name": "denied",
                "file": "receipts/denied_receipt.json",
                "declared_verdict": "reject",
                "reason_code": None,
            },
            {
                "name": "transformed",
                "file": "receipts/transformed_receipt.json",
                "declared_verdict": "accept",
                "reason_code": None,
            },
        ],
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


def _verify_proofpack(args: argparse.Namespace) -> int:
    # Offline, standalone proof-pack verification (B4 §8). Fail-closed: any error
    # folds into valid=False inside verify_proof_pack, so exit 1 on a non-valid pack.
    from gove_zone.verifier import verify_proof_pack

    verifier = None
    if args.verifier_key:
        # Out-of-band trust anchor: the relying party supplies the public key
        # SEPARATELY, never from the pack — a key shipped beside the signer is not
        # independent trust (see docs/PROOF_PATH.md). Raw 32-byte Ed25519 public key.
        from gove_zone.signing import Ed25519Signer

        try:
            raw = Path(args.verifier_key).read_bytes()
            signer = Ed25519Signer.from_public_bytes(raw, key_id=args.key_id or None)
        except Exception as exc:  # noqa: BLE001 — bad trust anchor must not verify anything
            print(f"verify-proofpack: cannot load --verifier-key: {exc}", file=sys.stderr)
            return 2
        verifier = {signer.key_id: signer}

    revoked_keys = None
    if getattr(args, "revoked_keys", None):
        # Out-of-band revocation list: revoked signing key_ids, supplied SEPARATELY
        # by the relying party. Fail-closed — an unreadable/malformed list must not
        # silently degrade to "no revocation applied" (exit 2, same as a bad anchor).
        from gove_zone.revocation import RevocationList

        try:
            revoked_keys = RevocationList.from_json(args.revoked_keys)
        except Exception as exc:  # noqa: BLE001 — a broken revocation list must not verify anything
            print(f"verify-proofpack: cannot load --revoked-keys: {exc}", file=sys.stderr)
            return 2

    result = verify_proof_pack(
        args.pack_dir, verifier=verifier, now_iso=args.now_iso, revoked_keys=revoked_keys
    )
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.valid else 1


def _tool_call_from_hook_payload(payload: Mapping[str, Any]) -> Any:
    """Map a host PreToolUse tool-call payload to a :class:`ToolCall`.

    The governed-loop-v2 reference monitor (``.claude/hooks/loop-pretool-guard.sh``)
    passes the Claude Code PreToolUse JSON — ``{tool_name, tool_input, ...}`` — on
    stdin. ``tool_name`` is the real host tool ("Bash", "Write", "Edit", "Read"),
    which is what the policy's ``tools:`` field must match; the discriminating
    content lives in ``tool_input`` (``command`` for Bash, ``file_path`` for
    Write/Edit), which we surface as ``state.command`` / ``state.path`` for the
    policy's ``state_contains`` matcher. Keying rules on the real tool name (not a
    synthetic ``shell.exec`` / ``git.push``) is what closes the shell-bypass hole.
    """
    from gove_zone.tool import ToolCall

    tool_name = str(payload.get("tool_name", "")).strip()
    if not tool_name:
        raise ValueError("payload missing tool_name")
    raw_input = payload.get("tool_input") or {}
    if not isinstance(raw_input, Mapping):
        raise ValueError("tool_input must be a JSON object")
    command = raw_input.get("command")
    path = raw_input.get("file_path") or raw_input.get("path") or raw_input.get("notebook_path")
    state = {
        "command": command if isinstance(command, str) else "",
        "path": path if isinstance(path, str) else "",
    }
    return ToolCall(name=tool_name, args=dict(raw_input), state=state)


def _validate(args: argparse.Namespace) -> int:
    """Evaluate one PreToolUse tool-call payload against a YAML build-guard policy.

    Reads the host's tool-call JSON (``{tool_name, tool_input}``) from stdin (or
    ``--event-file``), maps it to a :class:`ToolCall`, and evaluates it against the
    :class:`YAMLPolicy` at ``--policy``. Exit 0 iff the decision is ALLOW; DENY and
    ESCALATE exit 2 so a ``... || deny`` PreToolUse hook blocks the side effect.

    FAIL-CLOSED on a real governance failure — an unparseable payload, a missing
    ``tool_name``, or a policy file that is PRESENT BUT BROKEN (bad YAML / invalid
    schema) — exits 2 and denies: an action that cannot be evaluated against a
    policy that is supposed to exist is never allowed.

    GRACEFUL-DEGRADE on tooling absence only: if PyYAML (the optional ``yaml``
    extra) is not installed, the policy layer cannot run AT ALL. That is tooling
    absence, not a policy denial, so it exits 0 (allow) with a stderr advisory
    rather than denying every call and bricking the loop. This is safe because the
    calling PreToolUse hook's coarse regex backstop and the settings.json
    deny-rules remain in force and independently block the catastrophic cases
    (recursive-force rm, pipe-to-shell, permission-skip, force-push); only the
    policy's additive rules (secret-file writes, push escalation) are lost until
    ``yaml`` is installed. A missing optional dep must never be a governance
    failure. This asymmetry is deliberate.
    """
    from gove_zone.decision import Decision

    # 1) Read + map the request. Any read/parse error is a fail-closed deny.
    try:
        if args.event_file:
            payload_text = Path(args.event_file).read_text(encoding="utf-8")
        else:
            payload_text = sys.stdin.read()
        payload = json.loads(payload_text)
        if not isinstance(payload, dict):
            raise ValueError("tool-call payload must be a JSON object")
        call = _tool_call_from_hook_payload(payload)
    except Exception as exc:  # noqa: BLE001 — an unreadable request is denied
        print(f"validate: fail-closed deny (bad request): {exc}", file=sys.stderr)
        return 2

    # 2) Load the YAML policy. Distinguish tooling-absence (PyYAML missing ->
    #    degrade to allow) from a present-but-broken policy (-> fail closed).
    try:
        from gove_zone.yaml_policy import YAMLPolicy

        policy = YAMLPolicy.load_yaml(args.policy)
    except ModuleNotFoundError as exc:
        print(
            "validate: PyYAML not installed; build-guard policy layer inactive "
            f"(install gove-zone[yaml] to enforce it). Allowing. [{exc}]",
            file=sys.stderr,
        )
        return 0
    except Exception as exc:  # noqa: BLE001 — a broken/missing policy denies
        print(f"validate: fail-closed deny (policy load): {exc}", file=sys.stderr)
        return 2

    # 3) Evaluate. ALLOW -> 0; DENY/ESCALATE -> 2 (the hook's `|| deny`).
    try:
        record = policy.evaluate(call)
    except Exception as exc:  # noqa: BLE001 — an evaluation error denies
        print(f"validate: fail-closed deny (evaluate): {exc}", file=sys.stderr)
        return 2

    allowed = record.decision is Decision.ALLOW
    _emit(
        {
            "policy": str(args.policy),
            "policy_version": policy.version,
            "tool": call.name,
            "decision": record.decision.value,
            "allowed": allowed,
            "matched_rules": list(record.matched_rules),
            "reason": record.reason,
        }
    )
    return 0 if allowed else 2


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
    replay.add_argument(
        "--side-store",
        help=(
            "path to a ReplaySideStore JSONL; with --policy-bundle, re-runs the "
            "policy against the retained raw args for true decision re-derivation"
        ),
    )
    replay.add_argument(
        "--policy-bundle",
        help=(
            "RuleSetPolicy JSON bundle used to re-derive the decision; invalid "
            "bundles exit 2 (re-derivation needs --side-store too)"
        ),
    )
    replay.set_defaults(func=_replay)

    verify_ledger = subparsers.add_parser(
        "verify-ledger",
        help="verify the tamper-evidence hash chain of a consumption ledger",
    )
    verify_ledger.add_argument(
        "--ledger",
        required=True,
        help="path to the consumption ledger JSONL to verify",
    )
    verify_ledger.add_argument(
        "--expected-last-hash",
        default=None,
        help=(
            "optional external high-water-mark (last entry_hash); a mismatch "
            "flags tail truncation, which chaining alone cannot detect"
        ),
    )
    verify_ledger.add_argument(
        "--audit",
        default=None,
        help=(
            "optional audit JSONL path; also reconciles every burn against the "
            "chain's event_hashes (forged-burn detection) and folds the result "
            "into the exit code"
        ),
    )
    verify_ledger.set_defaults(func=_verify_ledger)

    prune_ledger = subparsers.add_parser(
        "prune-ledger",
        help="TTL-prune a consumption ledger (drop expired burned entries)",
    )
    prune_ledger.add_argument(
        "--ledger",
        required=True,
        help="path to the consumption ledger JSONL to prune",
    )
    prune_ledger.add_argument(
        "--now",
        default=None,
        help=(
            "optional ISO-8601 timezone-aware cutoff (default: current UTC time); "
            "burned entries whose receipt expired strictly before this are removed, "
            "and the prune watermark advances to the latest expiry removed. A future "
            "value also prunes not-yet-expired entries — use deliberately"
        ),
    )
    prune_ledger.set_defaults(func=_prune_ledger)

    approve = subparsers.add_parser(
        "approve-escalation",
        help="approve a parked governed-MCP escalation and mint an ALLOW receipt",
    )
    approve.add_argument(
        "--config",
        required=True,
        help="path to the gateway JSON config (tenant/boundary/policy/validator/signer/audit)",
    )
    approve.add_argument(
        "--pending",
        required=True,
        help=(
            "path to a pending-escalation descriptor JSON "
            "(GovernedGateway.pending_descriptor output): the ESCALATE record + args"
        ),
    )
    approve.add_argument(
        "--expires-at",
        default=None,
        help="optional ISO-8601 expiry bounding the FIRST use of the approval receipt",
    )
    approve.set_defaults(func=_approve_escalation)

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

    validate = subparsers.add_parser(
        "validate",
        help=(
            "evaluate a PreToolUse tool-call payload against a YAML build-guard "
            "policy; exit 0 iff ALLOW, else 2 (fail-closed)"
        ),
    )
    validate.add_argument(
        "--policy",
        required=True,
        help="path to a YAML policy bundle (loaded via YAMLPolicy.load_yaml)",
    )
    validate.add_argument(
        "--stdin",
        action="store_true",
        help="read the tool-call JSON from stdin (the default when no --event-file)",
    )
    validate.add_argument(
        "--event-file",
        help="path to a JSON file with the tool-call payload (default: stdin)",
    )
    validate.set_defaults(func=_validate)

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

    verify_proofpack = subparsers.add_parser(
        "verify-proofpack",
        help=("verify a proof-pack directory offline (fail-closed); exit 0 iff valid, else 1"),
    )
    verify_proofpack.add_argument(
        "pack_dir",
        help="path to a gove-zone/proof-pack/v1 directory (contains manifest.json)",
    )
    verify_proofpack.add_argument(
        "--now-iso",
        default=None,
        help="injected ISO-8601 clock for deterministic receipt-expiry checks",
    )
    verify_proofpack.add_argument(
        "--verifier-key",
        default=None,
        help=(
            "path to a raw 32-byte Ed25519 PUBLIC key, supplied out-of-band, used to "
            "verify signed receipts. Omit for unsigned (dev) packs; a signed pack "
            "without this fails closed (SIGNED_RECEIPT_NO_VERIFIER)."
        ),
    )
    verify_proofpack.add_argument(
        "--key-id",
        default=None,
        help="key_id the --verifier-key registers as (must match the receipt's signing_key_id)",
    )
    verify_proofpack.add_argument(
        "--revoked-keys",
        default=None,
        help=(
            "path to a JSON revocation list of revoked signing key_ids, supplied "
            "out-of-band. A signed receipt whose signing_key_id is revoked fails "
            "closed (SIGNING_KEY_REVOKED). Omit to apply no revocation."
        ),
    )
    verify_proofpack.set_defaults(func=_verify_proofpack)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
