"""Installed command-line tools for Gove Zone runtime evidence."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gove_zone import __version__
from gove_zone.adapters import AdapterError, normalize_governance_request
from gove_zone.audit import ChainHashAuditStore
from gove_zone.decision import sha256_json
from gove_zone.errors import ReceiptVerificationError
from gove_zone.foundation import (
    DecisionReceipt,
    GovernanceEngine,
    GovernanceRequest,
    GovernedExecutor,
    PolicyBundleBinding,
    StaticPolicyBundleRegistry,
    verify_decision_receipt,
)
from gove_zone.policy import BoundaryPolicy

DEFAULT_TENANT_ID = "tenant-alpha"
DEFAULT_POLICY_BUNDLE_ID = "local-boundary"
DEFAULT_BOUNDARY = {"environment": "local", "side_effects": "guarded"}
ALPHA_LIMITATIONS = [
    "local unsigned receipt placeholder only",
    "no production certification or compliance certification",
    "static in-process policy bundle registry",
    "Unix fcntl audit locking only",
]


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


def _policy_binding() -> PolicyBundleBinding:
    policy = BoundaryPolicy(
        forbidden_keywords=["secret", "/etc/shadow", "id_rsa", "~/.ssh"],
        rule_id="LOCAL-BOUNDARY",
    )
    return PolicyBundleBinding(
        tenant_id=DEFAULT_TENANT_ID,
        policy_bundle_id=DEFAULT_POLICY_BUNDLE_ID,
        policy_version=policy.version,
        constitutional_hash=sha256_json(
            {
                "tenant_id": DEFAULT_TENANT_ID,
                "policy_bundle_id": DEFAULT_POLICY_BUNDLE_ID,
                "policy_version": policy.version,
                "forbidden_keywords": ["secret", "/etc/shadow", "id_rsa", "~/.ssh"],
            }
        ),
        policy=policy,
    )


def _engine(audit_path: Path) -> tuple[GovernanceEngine, ChainHashAuditStore, PolicyBundleBinding]:
    binding = _policy_binding()
    audit = ChainHashAuditStore(audit_path)
    engine = GovernanceEngine(
        policy_registry=StaticPolicyBundleRegistry([binding]),
        audit=audit,
    )
    return engine, audit, binding


def _request(body: str, request_id: str) -> GovernanceRequest:
    return GovernanceRequest(
        request_id=request_id,
        tenant_id=DEFAULT_TENANT_ID,
        actor={"id": "gove-zone-cli"},
        subject={"id": "local-proof"},
        proposed_action={"tool": "message.send", "args": {"body": body}},
        declared_goal="produce local receipt-gated execution proof",
        execution_boundary=dict(DEFAULT_BOUNDARY),
        policy_bundle_id=DEFAULT_POLICY_BUNDLE_ID,
    )


def _executor() -> tuple[GovernedExecutor, list[str]]:
    executor = GovernedExecutor()
    executed: list[str] = []

    @executor.tool("message.send")
    def send(body: str) -> str:
        executed.append(body)
        return "sent:" + body

    return executor, executed


def _run_conformance(audit_path: Path) -> dict[str, Any]:
    engine, audit, binding = _engine(audit_path)
    executor, executed = _executor()

    allowed = engine.precheck(_request("hello", "req-proof-allow"))
    allowed_result = executor.execute(
        "message.send",
        {"body": "hello"},
        receipt=allowed,
        tenant_id=DEFAULT_TENANT_ID,
        execution_boundary=DEFAULT_BOUNDARY,
        constitutional_hash=binding.constitutional_hash,
        audit=audit,
    )

    denied = engine.precheck(_request("secret token", "req-proof-deny"))
    denied_blocked = False
    denied_reason = ""
    try:
        executor.execute(
            "message.send",
            {"body": "secret token"},
            receipt=denied,
            tenant_id=DEFAULT_TENANT_ID,
            execution_boundary=DEFAULT_BOUNDARY,
            constitutional_hash=binding.constitutional_hash,
            audit=audit,
        )
    except ReceiptVerificationError as exc:
        denied_blocked = True
        denied_reason = str(exc)

    missing_blocked = False
    missing_reason = ""
    try:
        executor.execute("message.send", {"body": "hello"}, receipt=None)
    except ReceiptVerificationError as exc:
        missing_blocked = True
        missing_reason = str(exc)

    tampered = allowed.to_dict()
    tampered["tenant_id"] = "tenant-beta"
    tampered_blocked = False
    tampered_reason = ""
    try:
        executor.execute("message.send", {"body": "hello"}, receipt=tampered)
    except ReceiptVerificationError as exc:
        tampered_blocked = True
        tampered_reason = str(exc)

    chain = audit.verify_chain()
    verification = {
        "audit_chain": chain,
        "allowed_receipt_valid": verify_decision_receipt(allowed, audit=audit),
        "denied_receipt_valid": verify_decision_receipt(denied, audit=audit),
    }
    conformance = {
        "allowed_valid_receipt": {
            "passed": allowed_result == "sent:hello" and executed == ["hello"],
            "result": allowed_result,
        },
        "denied_receipt_blocked": {"passed": denied_blocked, "reason": denied_reason},
        "missing_receipt_blocked": {"passed": missing_blocked, "reason": missing_reason},
        "tampered_receipt_blocked": {"passed": tampered_blocked, "reason": tampered_reason},
        "audit_chain_valid": {"passed": chain["valid"], "checked": chain["checked"]},
    }
    return {
        "binding": binding,
        "audit": audit,
        "receipts": {"allowed": allowed, "denied": denied},
        "verification": verification,
        "conformance": conformance,
        "executed": list(executed),
    }


def _doctor(_args: argparse.Namespace) -> int:
    _emit(
        {
            "status": "ok",
            "package": "gove-zone",
            "monorepo": "govern-zone",
            "version": __version__,
            "alpha": True,
            "production_certified": False,
            "compliance_certified": False,
            "commands": ["doctor", "smoke", "gate", "proofpack", "replay"],
            "receipt_signature": "unsigned-local-dev placeholder",
            "limitations": ALPHA_LIMITATIONS,
        }
    )
    return 0


def _smoke(args: argparse.Namespace) -> int:
    if args.audit is None:
        tmp = Path(tempfile.mkdtemp(prefix="gove-zone-smoke-"))
        audit_path = tmp / "audit.jsonl"
    else:
        audit_path = Path(args.audit)
    result = _run_conformance(audit_path)
    allowed = result["receipts"]["allowed"]
    denied = result["receipts"]["denied"]
    payload = {
        "status": "ok",
        "allowed": {
            "executed": result["conformance"]["allowed_valid_receipt"]["passed"],
            "receipt_id": allowed.receipt_id,
            "receipt_hash": allowed.receipt_hash,
            "receipt": allowed.to_dict(),
        },
        "denied": {
            "executed": False,
            "blocked": result["conformance"]["denied_receipt_blocked"]["passed"],
            "receipt_id": denied.receipt_id,
            "receipt": denied.to_dict(),
        },
        "missing_receipt": {
            "blocked": result["conformance"]["missing_receipt_blocked"]["passed"],
            "reason": result["conformance"]["missing_receipt_blocked"]["reason"],
        },
        "tampered_receipt": {
            "blocked": result["conformance"]["tampered_receipt_blocked"]["passed"],
            "reason": result["conformance"]["tampered_receipt_blocked"]["reason"],
        },
        "audit": {
            "path": str(audit_path),
            "valid": result["verification"]["audit_chain"]["valid"],
            "checked": result["verification"]["audit_chain"]["checked"],
        },
        "alpha_limitations": ALPHA_LIMITATIONS,
    }
    _emit(payload)
    return 0


def _load_gate_input(args: argparse.Namespace) -> dict[str, Any]:
    raw = args.input_json if args.input_json is not None else sys.stdin.read()
    if not raw.strip():
        raise AdapterError("gate requires JSON input")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise AdapterError("gate input must be a JSON object")
    payload.setdefault("tenant_id", args.tenant_id)
    payload.setdefault("policy_bundle_id", args.policy_bundle_id)
    payload.setdefault("actor", {"id": args.actor})
    payload.setdefault("subject", {"id": "gate"})
    payload.setdefault("declared_goal", args.goal)
    payload.setdefault("execution_boundary", dict(DEFAULT_BOUNDARY))
    return payload


def _gate(args: argparse.Namespace) -> int:
    audit_path = Path(args.audit)
    engine, audit, _binding = _engine(audit_path)
    try:
        request = normalize_governance_request(_load_gate_input(args))
        receipt = engine.precheck(request)
        chain = audit.verify_chain()
        _emit(
            {
                "status": "allowed"
                if receipt.decision.name in {"ALLOW", "TRANSFORM"}
                else "blocked",
                "decision": receipt.decision.name,
                "receipt": receipt.to_dict(),
                "audit": {
                    "path": str(audit_path),
                    "valid": chain["valid"],
                    "checked": chain["checked"],
                },
            }
        )
        return 0 if receipt.decision.name in {"ALLOW", "TRANSFORM"} else 2
    except (AdapterError, json.JSONDecodeError) as exc:
        _emit(
            {
                "status": "blocked",
                "decision": "DENY",
                "reason": f"malformed gate input: {exc}",
                "audit": {"path": str(audit_path), "valid": audit.verify_chain()["valid"]},
            }
        )
        return 2


def _proofpack(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if output.exists():
        if not args.force:
            _emit(
                {
                    "status": "blocked",
                    "reason": f"proofpack output already exists: {output}; use --force",
                    "output": str(output),
                }
            )
            return 2
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    receipts_dir = output / "receipts"
    receipts_dir.mkdir(exist_ok=True)
    audit_path = output / "audit.jsonl"
    result = _run_conformance(audit_path)
    binding: PolicyBundleBinding = result["binding"]

    receipts: Mapping[str, DecisionReceipt] = result["receipts"]
    written_files: list[str] = []
    for name, receipt in receipts.items():
        target = receipts_dir / f"{name}.json"
        target.write_text(
            json.dumps(receipt.to_dict(), sort_keys=True, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        written_files.append(str(target.relative_to(output)))

    verification_path = output / "verification.json"
    verification_path.write_text(
        json.dumps(result["verification"], sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    conformance_path = output / "conformance-results.json"
    conformance_path.write_text(
        json.dumps(result["conformance"], sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    limitations_path = output / "limitations.md"
    limitations_path.write_text(
        "# govern-zone proof pack limitations\n\n"
        + "\n".join(f"- {item}" for item in ALPHA_LIMITATIONS)
        + "\n",
        encoding="utf-8",
    )
    manifest = {
        "generated_at": datetime.now(UTC).isoformat(),
        "package": "gove-zone",
        "monorepo": "govern-zone",
        "version": __version__,
        "alpha": True,
        "production_certified": False,
        "compliance_certified": False,
        "policy_bundle_id": binding.policy_bundle_id,
        "policy_version": binding.policy_version,
        "constitutional_hash": binding.constitutional_hash,
        "files": sorted(
            [
                "manifest.json",
                "audit.jsonl",
                "verification.json",
                "conformance-results.json",
                "limitations.md",
                *written_files,
            ]
        ),
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    _emit({"status": "written", "output": str(output), "manifest": str(output / "manifest.json")})
    return 0


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gove-zone",
        description="Receipt-gated governance evidence for high-risk agent execution.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="report local alpha contract and commands")
    doctor.set_defaults(func=_doctor)

    smoke = subparsers.add_parser("smoke", help="run local receipt-gated execution smoke proof")
    smoke.add_argument("--format", choices=["json"], default="json")
    smoke.add_argument("--audit", help="path to retain the smoke audit JSONL")
    smoke.set_defaults(func=_smoke)

    gate = subparsers.add_parser(
        "gate", help="precheck one JSON tool-call envelope and emit a receipt"
    )
    gate.add_argument("--audit", default=".gove-zone/audit.jsonl", help="audit JSONL path")
    gate.add_argument("--input-json", help="JSON envelope; stdin is used when omitted")
    gate.add_argument("--tenant-id", default=DEFAULT_TENANT_ID)
    gate.add_argument("--policy-bundle-id", default=DEFAULT_POLICY_BUNDLE_ID)
    gate.add_argument("--actor", default="gate")
    gate.add_argument("--goal", default="governed CLI gate request")
    gate.set_defaults(func=_gate)

    proofpack = subparsers.add_parser("proofpack", help="write local conformance evidence bundle")
    proofpack.add_argument("--output", default="dist-govern-zone-proofpack")
    proofpack.add_argument(
        "--force", action="store_true", help="replace an existing output directory"
    )
    proofpack.set_defaults(func=_proofpack)

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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
