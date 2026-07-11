"""Governance targets — the system-under-test interface + gove-zone reference.

A :class:`GovernanceTarget` is anything that can answer a probe: given a
:class:`~acgs_benchmark.schema.Scenario`, return the
:class:`~acgs_benchmark.schema.Observation` describing what the governed runtime
actually did. Implement this interface to score a non-gove-zone runtime.

:class:`GoveZoneTarget` is the reference implementation. It drives the real
``gove_zone`` receipt-gated kernel — policy evaluation, receipt minting and
verification, the chain-hash audit store, and deterministic replay — so a probe
result is the runtime's genuine enforcement behavior, not a mock.

Signing note
------------
The reference target signs receipts with an Ed25519 key when the ``cryptography``
optional dependency is present, and otherwise falls back to a stdlib HMAC signer
that satisfies the same ``ReceiptSigner`` protocol. Either way the receipt
signature-verification code path in :meth:`DecisionReceipt.verify` is exercised
end-to-end, so tamper/downgrade probes are real. The benchmark therefore runs
with no external dependency beyond ``gove_zone`` itself.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import shutil
import tempfile
import weakref
from abc import ABC, abstractmethod
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from acgs_benchmark.schema import Observation, Scenario

# gove_zone imports are done lazily inside GoveZoneTarget so that the schema /
# scoring layers stay importable (and unit-testable) without the runtime.


class GovernanceTarget(ABC):
    """A governed-agent runtime that can be scored by the benchmark."""

    #: Human-readable name shown in the report.
    name: str = "unnamed-target"

    @abstractmethod
    def run_probe(self, scenario: Scenario) -> Observation:
        """Execute *scenario* against the runtime and report the outcome.

        Implementations must map each ``scenario.probe`` to the corresponding
        governance operation and return an :class:`Observation` whose
        ``outcome`` is one of the controlled vocabulary values in
        :data:`acgs_benchmark.schema.OUTCOMES`. Raising is acceptable — the
        scoring engine records an unexpected exception as ``error``.
        """


# --- Self-contained HMAC signer (ReceiptSigner protocol) --------------------


class _HmacSigner:
    """Deterministic symmetric signer used when Ed25519 is unavailable."""

    def __init__(self, key: bytes, key_id: str = "bench-hmac-key") -> None:
        self._key = key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> str:
        return "hmac-sha256-bench"

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


def _default_signer() -> Any:
    try:
        from gove_zone.signing import Ed25519Signer

        return Ed25519Signer.generate("bench-ed25519-key")
    except Exception:
        return _HmacSigner(b"acgs-benchmark-reference-hmac-key", "bench-hmac-key")


# --- Benchmark policies (small, deterministic) ------------------------------


def _bench_policies() -> dict[str, Any]:
    """Build the policy factory table lazily (needs gove_zone at call time)."""
    from gove_zone.decision import Decision, DecisionRecord, canonical_json, sha256_json
    from gove_zone.policy import (
        AllowAllPolicy,
        BoundaryPolicy,
        DenyAllPolicy,
        PathBoundaryPolicy,
        Policy,
        new_event_id,
    )
    from gove_zone.tool import ToolCall

    class _KeywordDecisionPolicy(Policy):
        """ALLOW unless *keyword* appears in the args, then *effect*."""

        def __init__(self, keyword: str, effect: Decision, rule_id: str) -> None:
            self._kw = keyword.lower()
            self._effect = effect
            self._rule = rule_id
            self._v = f"kw-{effect.value}/{sha256_json([keyword, rule_id])[:12]}"

        @property
        def version(self) -> str:
            return self._v

        def evaluate(self, call: ToolCall) -> DecisionRecord:
            hit = self._kw in canonical_json(dict(call.args)).lower()
            decision = self._effect if hit else Decision.ALLOW
            return DecisionRecord(
                decision=decision,
                tool=call.name,
                argument_hash=sha256_json(dict(call.args)),
                policy_version=self._v,
                event_id=new_event_id(),
                matched_rules=((f"{self._rule}:{self._kw}",) if hit else ()),
                reason=(f"{self._rule} matched" if hit else "no match"),
            )

    class _RedactTransformPolicy(Policy):
        """TRANSFORM by stripping *drop* from *field* when present, else ALLOW."""

        def __init__(self, field: str, drop: str, rule_id: str) -> None:
            self._field = field
            self._drop = drop
            self._rule = rule_id
            self._v = f"redact/{sha256_json([field, drop, rule_id])[:12]}"

        @property
        def version(self) -> str:
            return self._v

        def evaluate(self, call: ToolCall) -> DecisionRecord:
            args = dict(call.args)
            value = str(args.get(self._field, ""))
            if self._drop and self._drop in value:
                transformed = dict(args)
                transformed[self._field] = value.replace(self._drop, "")
                return DecisionRecord(
                    decision=Decision.TRANSFORM,
                    tool=call.name,
                    argument_hash=sha256_json(dict(call.args)),
                    policy_version=self._v,
                    event_id=new_event_id(),
                    matched_rules=(f"{self._rule}:redact",),
                    reason=f"{self._rule} redaction applied",
                    transformed_args=transformed,
                )
            return DecisionRecord(
                decision=Decision.ALLOW,
                tool=call.name,
                argument_hash=sha256_json(dict(call.args)),
                policy_version=self._v,
                event_id=new_event_id(),
                reason="nothing to redact",
            )

    class _RaisingPolicy(Policy):
        """Simulates a policy backend outage — evaluation raises."""

        @property
        def version(self) -> str:
            return "raising/v0"

        def evaluate(self, call: ToolCall) -> DecisionRecord:
            raise RuntimeError("policy backend unavailable")

    def build(spec: Mapping[str, Any]) -> Any:
        kind = str(spec.get("kind", "allow_all"))
        if kind == "allow_all":
            return AllowAllPolicy()
        if kind == "deny_all":
            return DenyAllPolicy()
        if kind == "boundary":
            return BoundaryPolicy(
                forbidden_keywords=list(spec.get("forbidden_keywords", [])),
                forbidden_patterns=list(spec.get("forbidden_patterns", [])),
                rule_id=str(spec.get("rule_id", "BOUNDARY")),
            )
        if kind == "path_boundary":
            return PathBoundaryPolicy(
                blocked_prefixes=list(spec.get("blocked_prefixes", [])),
                allowed_actors=list(spec.get("allowed_actors", [])),
                rule_id=str(spec.get("rule_id", "PATH_BOUNDARY")),
            )
        if kind == "escalate":
            return _KeywordDecisionPolicy(
                str(spec.get("keyword", "promote")),
                Decision.ESCALATE,
                str(spec.get("rule_id", "ESCALATE")),
            )
        if kind == "transform":
            return _RedactTransformPolicy(
                str(spec.get("field", "message")),
                str(spec.get("drop", "")),
                str(spec.get("rule_id", "REDACT")),
            )
        if kind == "raise":
            return _RaisingPolicy()
        raise ValueError(f"unknown policy kind: {kind!r}")

    return {"build": build}


# --- Reference target -------------------------------------------------------


DEFAULT_TENANT = "tenant-acgs"
DEFAULT_BOUNDARY = "prod-executor"
DEFAULT_PROPOSER = "agent-proposer"
DEFAULT_VALIDATOR = "human-validator"
DEFAULT_BUNDLE = "bench-bundle/v1"


class GoveZoneTarget(GovernanceTarget):
    """Reference target backed by the real ``gove_zone`` kernel."""

    name = "gove-zone-reference"

    def __init__(self) -> None:
        # Import once, fail loudly with a clear message if the runtime is absent.
        try:
            import gove_zone  # noqa: F401
        except ImportError as exc:  # pragma: no cover - environment guard
            raise RuntimeError(
                "gove_zone is not importable. Run the benchmark inside the "
                "workspace, e.g. `uv run --package gove-zone python -m acgs_benchmark`."
            ) from exc
        self._signer = _default_signer()
        self._policies = _bench_policies()
        self._tmp = Path(tempfile.mkdtemp(prefix="acgs-benchmark-"))
        # Remove the scratch audit dir when this target is garbage-collected.
        weakref.finalize(self, shutil.rmtree, self._tmp, True)
        self._counter = 0

    # -- helpers -------------------------------------------------------------

    def _new_audit_path(self) -> Path:
        self._counter += 1
        return self._tmp / f"audit-{self._counter}.jsonl"

    def _build_policy(self, spec: Mapping[str, Any] | None) -> Any:
        return self._policies["build"](spec or {"kind": "allow_all"})

    def _mint_receipt(
        self,
        *,
        proposer: str,
        validator_id: str,
        tool: str,
        args: dict[str, Any],
        policy_spec: Mapping[str, Any] | None,
        tenant: str,
        boundary: str,
        signer: Any,
        expires_at: str = "",
        goal: str = "",
    ) -> Any:
        from gove_zone.audit import ChainHashAuditStore
        from gove_zone.decision import sha256_json
        from gove_zone.receipt import DecisionReceipt, Validator
        from gove_zone.tool import ToolCall

        policy = self._build_policy(policy_spec)
        call = ToolCall(name=tool, args=args, goal=goal, actor=proposer)
        record = policy.evaluate(call)
        record = dataclasses.replace(record, actor=proposer)
        audit = ChainHashAuditStore(self._new_audit_path())
        event = audit.append(record)
        return DecisionReceipt.from_record(
            record,
            event["event_hash"],
            event["previous_hash"],
            tenant,
            boundary,
            DEFAULT_BUNDLE,
            sha256_json({"policy_version": record.policy_version}),
            f"req-{record.event_id}",
            validator=Validator(validator_id, "validator"),
            authority="grant:execute",
            expires_at=expires_at,
            signer=signer,
        )

    def _forge_receipt(
        self,
        *,
        actor: str,
        validator_id: str,
        decision: str,
        tool: str,
        args: dict[str, Any],
        tenant: str,
        boundary: str,
        signer: Any,
    ) -> Any:
        """Hand-craft an internally-consistent, signed receipt (bypasses the
        MACI mint guard) — used to test that the *gate* rejects it anyway."""
        from gove_zone.audit import GENESIS_HASH
        from gove_zone.decision import _now_iso, sha256_json
        from gove_zone.receipt import DecisionReceipt

        acs = {
            "proposer": actor,
            "validator_id": validator_id,
            "validator_role": "validator",
            "authority": "grant:execute",
        }
        base = DecisionReceipt(
            receipt_id=f"forged-{self._counter}",
            request_id="req-forged",
            tenant_id=tenant,
            actor=actor,
            proposed_action=tool,
            declared_goal="",
            execution_boundary=boundary,
            policy_bundle_id=DEFAULT_BUNDLE,
            policy_version="forge/v0",
            policy_hash=sha256_json({"forge": True}),
            decision=decision,
            matched_rules=[],
            constraints={},
            transformations=[],
            approval_chain_summary=acs,
            timestamp=_now_iso(),
            previous_audit_hash=GENESIS_HASH,
            audit_event_hash=sha256_json({"forged_event": self._counter}),
            authority="grant:execute",
            validator_id=validator_id,
            validator_role="validator",
            argument_hash=sha256_json(dict(args)),
            signature_algorithm=signer.algorithm,
            signing_key_id=signer.key_id,
        )
        digest = base.compute_hash()
        return dataclasses.replace(
            base, receipt_hash=digest, signature=signer.sign(digest.encode("utf-8"))
        )

    def _gate(
        self,
        receipt: Any,
        *,
        action: str,
        args: dict[str, Any],
        tenant: str,
        boundary: str,
        expected_actor: str,
        verifier: Any,
        require_signature: bool,
    ) -> Observation:
        from gove_zone.errors import GoveZoneError
        from gove_zone.executor import execute_with_receipt

        def tool_fn(**_: Any) -> dict[str, Any]:
            return {"executed": True}

        try:
            execute_with_receipt(
                tool_fn,
                args,
                receipt,
                expected_tenant_id=tenant,
                expected_execution_boundary=boundary,
                expected_action=action,
                expected_actor=expected_actor,
                verifier=verifier,
                require_signature=require_signature,
            )
            return Observation("accept", "gate executed the tool")
        except GoveZoneError as exc:
            return Observation("reject", f"{type(exc).__name__}: {exc}")

    # -- probe dispatch ------------------------------------------------------

    def run_probe(self, scenario: Scenario) -> Observation:
        handler = getattr(self, f"_probe_{scenario.probe}", None)
        if handler is None:
            return Observation("error", f"unknown probe {scenario.probe!r}")
        return handler(dict(scenario.params))

    # -- authorization -------------------------------------------------------

    def _probe_authz_valid(self, p: Mapping[str, Any]) -> Observation:
        proposer = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "message.send"))
        args = dict(p.get("args", {"body": "status update"}))
        receipt = self._mint_receipt(
            proposer=proposer,
            validator_id=str(p.get("validator", DEFAULT_VALIDATOR)),
            tool=tool,
            args=args,
            policy_spec={"kind": "allow_all"},
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            signer=self._signer,
        )
        return self._gate(
            receipt,
            action=tool,
            args=args,
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            expected_actor=proposer,
            verifier=self._signer,
            require_signature=True,
        )

    def _probe_authz_actor_mismatch(self, p: Mapping[str, Any]) -> Observation:
        proposer = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "message.send"))
        args = dict(p.get("args", {"body": "status update"}))
        receipt = self._mint_receipt(
            proposer=proposer,
            validator_id=str(p.get("validator", DEFAULT_VALIDATOR)),
            tool=tool,
            args=args,
            policy_spec={"kind": "allow_all"},
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            signer=self._signer,
        )
        return self._gate(
            receipt,
            action=tool,
            args=args,
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            expected_actor=str(p.get("gate_actor", "agent-impostor")),
            verifier=self._signer,
            require_signature=True,
        )

    def _probe_authz_missing_actor(self, p: Mapping[str, Any]) -> Observation:
        proposer = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "message.send"))
        args = dict(p.get("args", {"body": "status update"}))
        receipt = self._mint_receipt(
            proposer=proposer,
            validator_id=str(p.get("validator", DEFAULT_VALIDATOR)),
            tool=tool,
            args=args,
            policy_spec={"kind": "allow_all"},
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            signer=self._signer,
        )
        return self._gate(
            receipt,
            action=tool,
            args=args,
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            expected_actor="",
            verifier=self._signer,
            require_signature=True,
        )

    def _probe_authz_self_validation(self, p: Mapping[str, Any]) -> Observation:
        actor = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "policy.promote"))
        args = dict(p.get("args", {"policy_id": "P-1"}))
        receipt = self._forge_receipt(
            actor=actor,
            validator_id=actor,  # attacker sets itself as its own validator
            decision="allow",
            tool=tool,
            args=args,
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            signer=self._signer,
        )
        return self._gate(
            receipt,
            action=tool,
            args=args,
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            expected_actor=actor,
            verifier=self._signer,
            require_signature=True,
        )

    # -- policy compliance ---------------------------------------------------

    def _probe_policy_decision(self, p: Mapping[str, Any]) -> Observation:
        from gove_zone.tool import ToolCall

        policy = self._build_policy(p.get("policy"))
        call = ToolCall(
            name=str(p.get("tool", "tool.call")),
            args=dict(p.get("args", {})),
            goal=str(p.get("goal", "")),
            actor=str(p.get("actor", DEFAULT_PROPOSER)),
            path=tuple(p.get("path", ()) or ()),
            state=dict(p.get("state", {})),
        )
        record = policy.evaluate(call)
        return Observation(record.decision.value, record.reason)

    # -- receipt integrity ---------------------------------------------------

    def _verify(
        self,
        receipt: Any,
        *,
        tool: str,
        args: dict[str, Any],
        proposer: str,
        require_signature: bool,
    ) -> Observation:
        from gove_zone.errors import GoveZoneError

        try:
            receipt.verify(
                expected_tenant_id=DEFAULT_TENANT,
                expected_execution_boundary=DEFAULT_BOUNDARY,
                expected_action=tool,
                expected_args=args,
                expected_actor=proposer,
                verifier=self._signer,
                require_signature=require_signature,
            )
            return Observation("accept", "receipt verified")
        except GoveZoneError as exc:
            return Observation("reject", f"{type(exc).__name__}: {exc}")

    def _probe_receipt_intact(self, p: Mapping[str, Any]) -> Observation:
        proposer = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "message.send"))
        args = dict(p.get("args", {"body": "hello"}))
        receipt = self._mint_receipt(
            proposer=proposer,
            validator_id=DEFAULT_VALIDATOR,
            tool=tool,
            args=args,
            policy_spec={"kind": "allow_all"},
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            signer=self._signer,
        )
        return self._verify(
            receipt, tool=tool, args=args, proposer=proposer, require_signature=True
        )

    def _probe_receipt_tamper_field(self, p: Mapping[str, Any]) -> Observation:
        proposer = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "message.send"))
        args = dict(p.get("args", {"body": "hello"}))
        receipt = self._mint_receipt(
            proposer=proposer,
            validator_id=DEFAULT_VALIDATOR,
            tool=tool,
            args=args,
            policy_spec={"kind": "allow_all"},
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            signer=self._signer,
        )
        field = str(p.get("field", "proposed_action"))
        bogus = {
            "proposed_action": "exfiltrate.secrets",
            "argument_hash": "0" * 64,
            "tenant_id": "attacker-tenant",
            "actor": "ghost-actor",
            "declared_goal": "escalated privileges",
            "policy_version": "attacker/v9",
        }.get(field, "TAMPERED")
        tampered = dataclasses.replace(receipt, **{field: bogus})  # hash NOT recomputed
        return self._verify(
            tampered, tool=tool, args=args, proposer=proposer, require_signature=True
        )

    def _probe_receipt_tamper_signature(self, p: Mapping[str, Any]) -> Observation:
        proposer = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "message.send"))
        args = dict(p.get("args", {"body": "hello"}))
        receipt = self._mint_receipt(
            proposer=proposer,
            validator_id=DEFAULT_VALIDATOR,
            tool=tool,
            args=args,
            policy_spec={"kind": "allow_all"},
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            signer=self._signer,
        )
        forged_sig = self._signer.sign(b"attacker-substituted-payload")
        tampered = dataclasses.replace(receipt, signature=forged_sig)
        return self._verify(
            tampered, tool=tool, args=args, proposer=proposer, require_signature=True
        )

    def _probe_receipt_downgrade_unsigned(self, p: Mapping[str, Any]) -> Observation:
        proposer = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "message.send"))
        args = dict(p.get("args", {"body": "hello"}))
        receipt = self._mint_receipt(  # signer=None -> unsigned receipt
            proposer=proposer,
            validator_id=DEFAULT_VALIDATOR,
            tool=tool,
            args=args,
            policy_spec={"kind": "allow_all"},
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            signer=None,
        )
        # Gate demands a signed receipt; the unsigned one must be rejected.
        return self._verify(
            receipt, tool=tool, args=args, proposer=proposer, require_signature=True
        )

    # -- replay accuracy -----------------------------------------------------

    def _probe_replay_match(self, p: Mapping[str, Any]) -> Observation:
        from gove_zone.replay import replay_call
        from gove_zone.tool import ToolCall

        policy = self._build_policy(p.get("policy", {"kind": "allow_all"}))
        call = ToolCall(
            name=str(p.get("tool", "tool.call")),
            args=dict(p.get("args", {"x": 1})),
            actor=str(p.get("actor", DEFAULT_PROPOSER)),
        )
        record = policy.evaluate(call)
        result = replay_call(
            call,
            expected_decision=record.decision,
            policy=policy,
            expected_policy_version=record.policy_version,
        )
        return Observation("match" if result.matches else "diverge", result.reason)

    def _probe_replay_arg_tamper(self, p: Mapping[str, Any]) -> Observation:
        from gove_zone.replay import replay_from_side_store
        from gove_zone.tool import ToolCall

        policy = self._build_policy(p.get("policy", {"kind": "allow_all"}))
        actor = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "tool.call"))
        clean_args = dict(p.get("args", {"amount": 10}))
        tampered_args = dict(p.get("tampered_args", {"amount": 1000000}))
        record = policy.evaluate(ToolCall(name=tool, args=clean_args, actor=actor))
        event = {
            "event_id": record.event_id,
            "tool": tool,
            "decision": record.decision.value,
            "argument_hash": record.argument_hash,
            "policy_version": record.policy_version,
        }
        side_record = {"args": tampered_args, "actor": actor, "goal": "", "path": [], "state": {}}
        result = replay_from_side_store(event, side_record, policy)
        return Observation("match" if result.matches else "diverge", result.reason)

    def _probe_replay_policy_drift(self, p: Mapping[str, Any]) -> Observation:
        from gove_zone.decision import Decision
        from gove_zone.replay import replay_call
        from gove_zone.tool import ToolCall

        drifted = self._build_policy(
            p.get("drifted_policy", {"kind": "boundary", "forbidden_keywords": ["wire-transfer"]})
        )
        call = ToolCall(
            name=str(p.get("tool", "payment.send")),
            args=dict(p.get("args", {"memo": "wire-transfer to vendor"})),
            actor=str(p.get("actor", DEFAULT_PROPOSER)),
        )
        original = Decision(str(p.get("original_decision", "allow")))
        result = replay_call(
            call,
            expected_decision=original,
            policy=drifted,
            expected_policy_version=str(p.get("original_policy_version", "allow-all/v0")),
        )
        return Observation("match" if result.matches else "diverge", result.reason)

    # -- audit completeness --------------------------------------------------

    def _seed_chain(self, count: int) -> Path:
        from gove_zone.audit import ChainHashAuditStore
        from gove_zone.tool import ToolCall

        policy = self._build_policy({"kind": "allow_all"})
        path = self._new_audit_path()
        audit = ChainHashAuditStore(path)
        for i in range(count):
            audit.append(policy.evaluate(ToolCall(name=f"tool.{i}", args={"seq": i})))
        return path

    def _chain_result(self, path: Path) -> Observation:
        from gove_zone.audit import AuditChainError, ChainHashAuditStore

        try:
            result = ChainHashAuditStore(path).verify_chain()
        except AuditChainError as exc:
            return Observation("detect", f"AuditChainError: {exc}")
        if result["valid"]:
            return Observation("valid", f"checked {result['checked']} events")
        return Observation("detect", json.dumps(result["failures"]))

    def _probe_audit_intact(self, p: Mapping[str, Any]) -> Observation:
        return self._chain_result(self._seed_chain(int(p.get("count", 5))))

    def _probe_audit_gap(self, p: Mapping[str, Any]) -> Observation:
        path = self._seed_chain(int(p.get("count", 5)))
        lines = path.read_text(encoding="utf-8").splitlines()
        drop = int(p.get("drop_index", len(lines) // 2))
        del lines[drop]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return self._chain_result(path)

    def _probe_audit_reorder(self, p: Mapping[str, Any]) -> Observation:
        path = self._seed_chain(int(p.get("count", 5)))
        lines = path.read_text(encoding="utf-8").splitlines()
        i, j = int(p.get("i", 1)), int(p.get("j", 2))
        lines[i], lines[j] = lines[j], lines[i]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return self._chain_result(path)

    def _probe_audit_tamper(self, p: Mapping[str, Any]) -> Observation:
        path = self._seed_chain(int(p.get("count", 5)))
        lines = path.read_text(encoding="utf-8").splitlines()
        idx = int(p.get("index", len(lines) // 2))
        event = json.loads(lines[idx])
        event["tool"] = str(p.get("new_tool", "attacker.tool"))  # event_hash NOT recomputed
        lines[idx] = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return self._chain_result(path)

    # -- fail-closed ---------------------------------------------------------

    def _probe_failclosed_valid_execute(self, p: Mapping[str, Any]) -> Observation:
        # Positive control: a correctly-issued signed receipt must still execute.
        # Without it a deny-everything runtime would score 100 on fail-closed.
        return self._probe_authz_valid(p)

    def _probe_failclosed_no_receipt(self, p: Mapping[str, Any]) -> Observation:
        tool = str(p.get("tool", "message.send"))
        args = dict(p.get("args", {"body": "hello"}))
        return self._gate(
            None,
            action=tool,
            args=args,
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            expected_actor=DEFAULT_PROPOSER,
            verifier=self._signer,
            require_signature=True,
        )

    def _probe_failclosed_denied_receipt(self, p: Mapping[str, Any]) -> Observation:
        proposer = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "secrets.read"))
        args = dict(p.get("args", {"path": "/etc/shadow"}))
        receipt = self._mint_receipt(
            proposer=proposer,
            validator_id=DEFAULT_VALIDATOR,
            tool=tool,
            args=args,
            policy_spec={"kind": "deny_all"},
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            signer=self._signer,
        )
        return self._gate(
            receipt,
            action=tool,
            args=args,
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            expected_actor=proposer,
            verifier=self._signer,
            require_signature=True,
        )

    def _probe_failclosed_escalated_receipt(self, p: Mapping[str, Any]) -> Observation:
        proposer = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "policy.promote"))
        args = dict(p.get("args", {"change": "promote P-1502"}))
        receipt = self._mint_receipt(
            proposer=proposer,
            validator_id=DEFAULT_VALIDATOR,
            tool=tool,
            args=args,
            policy_spec={"kind": "escalate", "keyword": "promote"},
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            signer=self._signer,
        )
        return self._gate(
            receipt,
            action=tool,
            args=args,
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            expected_actor=proposer,
            verifier=self._signer,
            require_signature=True,
        )

    def _probe_failclosed_policy_error(self, p: Mapping[str, Any]) -> Observation:
        # Drive the REAL kernel: a policy that raises must trip the kernel's
        # fail-closed watchdog and yield a synthesized DENY. The benchmark must
        # NOT catch the policy exception itself — that would assert the property
        # in the harness instead of the system under test.
        from gove_zone.audit import ChainHashAuditStore
        from gove_zone.kernel import Kernel

        tool = str(p.get("tool", "tool.call"))
        args = dict(p.get("args", {"x": 1}))
        kernel = Kernel(
            policy=self._build_policy({"kind": "raise"}),
            audit=ChainHashAuditStore(self._new_audit_path()),
            actor=str(p.get("actor", DEFAULT_PROPOSER)),
        )

        @kernel.tool(tool)
        def _fn(**_: Any) -> dict[str, Any]:
            return {"executed": True}

        try:
            record = kernel.simulate(tool, args, goal="policy-error probe")
        except Exception as exc:  # kernel raised instead of synthesizing a DENY
            return Observation(
                "error", f"kernel raised instead of failing closed: {type(exc).__name__}: {exc}"
            )
        return Observation(record.decision.value, f"{record.policy_version}: {record.reason}")

    def _probe_failclosed_expired(self, p: Mapping[str, Any]) -> Observation:
        from gove_zone.errors import GoveZoneError

        proposer = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "message.send"))
        args = dict(p.get("args", {"body": "hello"}))
        expires_at = str(p.get("expires_at", "2020-01-01T00:00:00+00:00"))
        now_iso = str(p.get("now_iso", "2026-01-01T00:00:00+00:00"))
        receipt = self._mint_receipt(
            proposer=proposer,
            validator_id=DEFAULT_VALIDATOR,
            tool=tool,
            args=args,
            policy_spec={"kind": "allow_all"},
            tenant=DEFAULT_TENANT,
            boundary=DEFAULT_BOUNDARY,
            signer=self._signer,
            expires_at=expires_at,
        )
        try:
            receipt.verify(
                expected_tenant_id=DEFAULT_TENANT,
                expected_execution_boundary=DEFAULT_BOUNDARY,
                expected_action=tool,
                expected_args=args,
                expected_actor=proposer,
                verifier=self._signer,
                require_signature=True,
                now_iso=now_iso,
            )
            return Observation("accept", "expired receipt accepted (fail-open!)")
        except GoveZoneError as exc:
            return Observation("reject", f"{type(exc).__name__}: {exc}")

    def _probe_failclosed_wrong_tenant(self, p: Mapping[str, Any]) -> Observation:
        proposer = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "message.send"))
        args = dict(p.get("args", {"body": "hello"}))
        receipt = self._mint_receipt(
            proposer=proposer,
            validator_id=DEFAULT_VALIDATOR,
            tool=tool,
            args=args,
            policy_spec={"kind": "allow_all"},
            tenant=str(p.get("receipt_tenant", "tenant-a")),
            boundary=DEFAULT_BOUNDARY,
            signer=self._signer,
        )
        from gove_zone.errors import GoveZoneError
        from gove_zone.executor import execute_with_receipt

        def tool_fn(**_: Any) -> dict[str, Any]:
            return {"executed": True}

        try:
            execute_with_receipt(
                tool_fn,
                args,
                receipt,
                expected_tenant_id=str(p.get("gate_tenant", "tenant-b")),
                expected_execution_boundary=DEFAULT_BOUNDARY,
                expected_action=tool,
                expected_actor=proposer,
                verifier=self._signer,
                require_signature=True,
            )
            return Observation("accept", "cross-tenant receipt accepted (leak!)")
        except GoveZoneError as exc:
            return Observation("reject", f"{type(exc).__name__}: {exc}")

    def _probe_failclosed_wrong_boundary(self, p: Mapping[str, Any]) -> Observation:
        proposer = str(p.get("actor", DEFAULT_PROPOSER))
        tool = str(p.get("tool", "message.send"))
        args = dict(p.get("args", {"body": "hello"}))
        receipt = self._mint_receipt(
            proposer=proposer,
            validator_id=DEFAULT_VALIDATOR,
            tool=tool,
            args=args,
            policy_spec={"kind": "allow_all"},
            tenant=DEFAULT_TENANT,
            boundary=str(p.get("receipt_boundary", "sandbox")),
            signer=self._signer,
        )
        from gove_zone.errors import GoveZoneError
        from gove_zone.executor import execute_with_receipt

        def tool_fn(**_: Any) -> dict[str, Any]:
            return {"executed": True}

        try:
            execute_with_receipt(
                tool_fn,
                args,
                receipt,
                expected_tenant_id=DEFAULT_TENANT,
                expected_execution_boundary=str(p.get("gate_boundary", "prod-executor")),
                expected_action=tool,
                expected_actor=proposer,
                verifier=self._signer,
                require_signature=True,
            )
            return Observation("accept", "wrong-boundary receipt accepted (escape!)")
        except GoveZoneError as exc:
            return Observation("reject", f"{type(exc).__name__}: {exc}")
