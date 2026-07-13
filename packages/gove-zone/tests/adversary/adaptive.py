"""Deterministic adaptive evaluation over the gove-zone adversary suite.

The static manifest calls a class DEFENDED when dedicated covering tests exist.
This module adds a bounded, fixed variant family for each of the eight current
manifest classes and executes each variant against the real
``execute_with_receipt``, ``Kernel.dispatch``, or ``verify_chain`` surface.

A "bypass" means a side effect ran, a receipt was accepted, or
``verify_chain()`` returned valid when the family expected rejection. The
result is deliberately narrow: it is deterministic config/input-space coverage,
not model-in-the-loop evaluation, and "STABLE" means only that no member of the
explicit bounded family bypassed the tested surface.
"""

from __future__ import annotations

import dataclasses
import json
import tempfile
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    DeniedError,
    Ed25519Signer,
    Kernel,
    ProductionProfileError,
    ReceiptValidationError,
    RuleSetPolicy,
    Validator,
    execute_with_receipt,
)
from gove_zone.audit import GENESIS_HASH
from gove_zone.decision import sha256_json
from gove_zone.errors import AuditError

# Must match tests/adversary/conftest.py (the canonical governed-run idiom).
TENANT = "tenant-A"
BOUNDARY = "local-sandbox"
ACTION = "runtime.file.write"
ARGS: dict[str, Any] = {"path": "safe.txt"}

# The gate's deny signals. Any OTHER exception is a broken harness and must PROPAGATE
# (a silently-swallowed error would fake a DENY and inflate stability).
_DENY_EXCEPTIONS = (ReceiptValidationError, ProductionProfileError)

# Comfortably exceeds the largest current variant family (evidence-omission, 28) so a
# future added variant cannot silently truncate at the budget before evaluation. A
# STABLE verdict enumerates the WHOLE family, so the family MUST stay strictly under
# this ceiling — enforced by test_adaptive_stability.test_stable_class_families_fit_within_budget.
DEFAULT_BUDGET = 40


@dataclasses.dataclass(frozen=True)
class AdaptiveResult:
    """Verdict for one adversary class under the bounded variant family."""

    class_name: str
    variants_tried: int
    first_bypass: str | None  # human-readable variant id, or None if none admitted
    stable: bool

    def __post_init__(self) -> None:
        if self.stable != (self.first_bypass is None):
            raise ValueError(
                "AdaptiveResult invariant violated: stable must equal (first_bypass is None)"
            )


@dataclasses.dataclass(frozen=True)
class Variant:
    """One defense-aware variant: an id plus a thunk that runs the REAL surface and
    returns True iff it WRONGLY ADMITTED (i.e. the variant is a bypass)."""

    variant_id: str
    admits: Callable[[], bool]


class _SideEffect:
    """A guarded side effect that records whether it ran (mirrors conftest)."""

    def __init__(self) -> None:
        self.ran = False

    def run(self, **_kwargs: Any) -> str:
        self.ran = True
        return "SIDE EFFECT EXECUTED"


def _mint(
    *,
    actor: str = "agent-1",
    validator_id: str = "constitutional-council",
    policy_version: str = "v2-current",
    policy_hash: str = "policy/v2-current",
    policy_bundle_id: str = "policy-bundle",
    tenant_id: str = TENANT,
    boundary: str = BOUNDARY,
    authority: str = "tenant-A/write-grant",
    args: dict[str, Any] | None = None,
    signer: Any | None = None,
) -> DecisionReceipt:
    """Mint an ALLOW receipt via the real receipt schema (mirrors conftest._issue)."""
    effective_args = ARGS if args is None else args
    record = DecisionRecord(
        decision=Decision.ALLOW,
        tool=ACTION,
        argument_hash=sha256_json(effective_args),
        policy_version=policy_version,
        event_id="ev_adversary",
        actor=actor,
    )
    return DecisionReceipt.from_record(
        record=record,
        audit_hash="audit_hash",
        previous_audit_hash="prev_audit_hash",
        tenant_id=tenant_id,
        execution_boundary=boundary,
        policy_bundle_id=policy_bundle_id,
        policy_hash=policy_hash,
        request_id="req-123",
        validator=Validator(validator_id),
        authority=authority,
        signer=signer,
    )


def _gate_admits(
    receipt: DecisionReceipt | None,
    *,
    args: dict[str, Any] | None = None,
    require_signature: bool = False,
    verifier: Any = None,
    expected_tenant_id: str = TENANT,
    expected_execution_boundary: str = BOUNDARY,
    expected_action: str = ACTION,
    expected_actor: str = "agent-1",
    expected_policy_hash: str | None = None,
    expected_policy_bundle_id: str | None = None,
    expected_authority: str | None = None,
    expected_validator_role: str | None = None,
) -> bool:
    """Run a receipt through the REAL gate; True iff the side effect ran (admitted)."""
    side_effect = _SideEffect()
    kwargs: dict[str, Any] = dict(
        tool_fn=side_effect.run,
        args=ARGS if args is None else args,
        receipt=receipt,
        expected_tenant_id=expected_tenant_id,
        expected_execution_boundary=expected_execution_boundary,
        expected_action=expected_action,
        expected_actor=expected_actor,
        expected_policy_hash=expected_policy_hash,
        expected_authority=expected_authority,
        expected_validator_role=expected_validator_role,
        verifier=verifier,
        require_signature=require_signature,
    )
    if expected_policy_bundle_id is not None:
        kwargs["expected_policy_bundle_id"] = expected_policy_bundle_id
    try:
        execute_with_receipt(**kwargs)
    except _DENY_EXCEPTIONS:
        # A late validation failure after a side effect is still an admission.
        # Never turn side-effect-before-error into a false stable result.
        return side_effect.ran
    return side_effect.ran


# --- variant axes (deterministic; no randomness) ------------------------------------

_ACTORS = ("agent-1", "attacker", "agent-2", "root")
_ARGS_VARIANTS: tuple[tuple[str, dict[str, Any]], ...] = (
    ("baseline", {"path": "safe.txt"}),
    ("path-traversal", {"path": "/etc/shadow"}),
    ("extra-field", {"path": "safe.txt", "extra": 1}),
    ("empty-args", {}),
    ("whitespace", {"path": "safe.txt "}),
    ("case-fold", {"path": "SAFE.TXT"}),
)
_WRONG_TENANTS = (
    "tenant-B",
    "tenant-C",
    "",
    "tenant-a",
    "TENANT-A",
    "tenant-A\u200b",  # zero-width space, represented explicitly
)
_WRONG_BOUNDARIES = ("prod-cluster", "", "local-sandbox ", "LOCAL-SANDBOX")


# --- STABLE-by-construction families (predict: all variants DENIED) -----------------


def _gen_signature_stripping(budget: int) -> Iterator[Variant]:
    """require_signature=True is a total check: every variant lacks a valid TRUSTED
    signature, so a correct gate denies all. Reference-monitor totality."""
    trusted = Ed25519Signer.generate()
    attacker = Ed25519Signer.generate()
    for actor in _ACTORS:
        r_unsigned = _mint(actor=actor, signer=None)
        yield Variant(
            f"sig:unsigned+trusted-verifier:actor={actor}",
            lambda r=r_unsigned, v=trusted, a=actor: _gate_admits(
                r, require_signature=True, verifier=v, expected_actor=a
            ),
        )
        r_unsigned2 = _mint(actor=actor, signer=None)
        yield Variant(
            f"sig:unsigned+no-verifier:actor={actor}",
            lambda r=r_unsigned2, a=actor: _gate_admits(
                r, require_signature=True, verifier=None, expected_actor=a
            ),
        )
        r_attacker = _mint(actor=actor, signer=attacker)
        yield Variant(
            f"sig:attacker-signed+trusted-verifier:actor={actor}",
            lambda r=r_attacker, v=trusted, a=actor: _gate_admits(
                r, require_signature=True, verifier=v, expected_actor=a
            ),
        )
        legit = _mint(actor="agent-1", signer=trusted)
        target = f"attacker-{actor}"  # always differs from the signed 'agent-1'
        tampered = dataclasses.replace(legit, actor=target)
        tampered = dataclasses.replace(tampered, receipt_hash=tampered.compute_hash())
        yield Variant(
            f"sig:tampered-recomputed:actor={target}",
            lambda r=tampered, v=trusted, a=target: _gate_admits(
                r, require_signature=True, verifier=v, expected_actor=a
            ),
        )
        r_cross = _mint(actor=actor, signer=trusted)
        yield Variant(
            f"sig:legit-signed+wrong-verifier:actor={actor}",
            lambda r=r_cross, v=attacker, a=actor: _gate_admits(
                r, require_signature=True, verifier=v, expected_actor=a
            ),
        )


def _gen_tenant_crossover(budget: int) -> Iterator[Variant]:
    """tenant/boundary/actor/args are hash-bound and checked; every variant carries at
    least one mismatch against the tenant-A/local-sandbox receipt. Least-privilege
    binding — a correct gate denies all."""
    specs: list[tuple[str, dict[str, Any]]] = []
    for t in _WRONG_TENANTS:
        specs.append((f"tenant:wrong-tenant={t!r}", dict(expected_tenant_id=t)))
    for b in _WRONG_BOUNDARIES:
        specs.append((f"tenant:wrong-boundary={b!r}", dict(expected_execution_boundary=b)))
    for a in ("attacker", "agent-2", "root", ""):
        specs.append((f"tenant:wrong-actor={a!r}", dict(expected_actor=a)))
    for aid, av in _ARGS_VARIANTS[1:]:
        specs.append((f"tenant:arg-mut={aid}", dict(args=av)))
    for t in _WRONG_TENANTS[:5]:
        specs.append(
            (
                f"tenant:combo-tenant+boundary={t!r}",
                dict(expected_tenant_id=t, expected_execution_boundary="prod-cluster"),
            )
        )
    for vid, kw in specs:
        receipt = _mint()
        yield Variant(vid, lambda r=receipt, kw=kw: _gate_admits(r, **kw))


class _BrokenAuditStore(ChainHashAuditStore):
    """An audit sink whose append always fails — models a stripped/unavailable audit
    log. A correct kernel anchors BEFORE it executes, so an append failure must abort
    the dispatch (AuditError) rather than let the side effect run unrecorded."""

    def append(self, record: DecisionRecord) -> dict[str, Any]:  # type: ignore[override]
        raise OSError("audit sink unavailable")


# A deny/escalate-only overlay that does not match the probed tools, so dispatch reaches
# ALLOW (default-allow) — enough to drive execution for the anchor-before-execute probe.
_ANCHOR_PROBE_POLICY = {
    "id": "deny-delete/v1",
    "rules": [{"id": "BLOCK_DELETE", "effect": "deny", "tools": ["fs.delete"]}],
}


def _dispatch_kernel_deny(exc: type[BaseException]) -> bool:
    """Only expected policy denial or the explicit audit-failure probe are
    classified as a denied execution. Other errors must remain visible."""
    return issubclass(exc, (DeniedError, AuditError))


def _dispatch_anchor_before_execute_admits(tool_name: str) -> bool:
    """Return true only if the tool runs before its audit anchor exists."""
    with tempfile.TemporaryDirectory() as directory:
        audit_path = Path(directory) / "audit.jsonl"
        store = ChainHashAuditStore(audit_path)
        policy = RuleSetPolicy.from_dict(_ANCHOR_PROBE_POLICY)
        kernel = Kernel(policy=policy, audit=store, actor="agent")
        observed = {"ran": False, "anchored_first": False}

        @kernel.tool(tool_name)
        def _tool(path: str = "x") -> str:
            observed["ran"] = True
            observed["anchored_first"] = len(list(store.iter_events())) >= 1
            return "wrote"

        try:
            kernel.dispatch(tool_name, {"path": "/x"})
        except Exception as exc:  # noqa: BLE001 — narrowed immediately below
            if _dispatch_kernel_deny(type(exc)):
                return False
            raise
        return observed["ran"] and not observed["anchored_first"]


def _dispatch_stripped_audit_admits(tool_name: str) -> bool:
    """Return true only if a failed audit append still allows execution."""
    with tempfile.TemporaryDirectory() as directory:
        audit_path = Path(directory) / "audit.jsonl"
        store = _BrokenAuditStore(audit_path)
        policy = RuleSetPolicy.from_dict(_ANCHOR_PROBE_POLICY)
        kernel = Kernel(policy=policy, audit=store, actor="agent")
        ran = {"v": False}

        @kernel.tool(tool_name)
        def _tool(path: str = "x") -> str:
            ran["v"] = True
            return "wrote"

        try:
            kernel.dispatch(tool_name, {"path": "/x"})
        except Exception as exc:  # noqa: BLE001 — narrowed immediately below
            if _dispatch_kernel_deny(type(exc)):
                return ran["v"]
            raise
        return ran["v"]


def _gen_evidence_omission(budget: int) -> Iterator[Variant]:
    """No evidence -> no side effect, regardless of every other parameter. The
    anchor-before-execute / total-mediation invariant (Biba integrity): the gate never
    executes without evidence to bind. A correct gate denies all.

    Two evidence axes (analysis §4: "dispatch with no receipt / stripped audit /
    reordered anchor"):
      1. execute_with_receipt with receipt=None across actor x args, and
      2. Kernel.dispatch's audit anchor — stripped (append fails -> AuditError,
         fail-closed) and reordered (evidence must be anchored before the tool runs)."""
    for actor in _ACTORS:
        for aid, av in _ARGS_VARIANTS:
            yield Variant(
                f"evidence:no-receipt:actor={actor}:args={aid}",
                lambda a=actor, av=av: _gate_admits(None, args=av, expected_actor=a),
            )
    for tool_name in ("fs.write", "proc.spawn"):
        yield Variant(
            f"evidence:dispatch-anchor-before-execute:tool={tool_name}",
            lambda t=tool_name: _dispatch_anchor_before_execute_admits(t),
        )
    for tool_name in ("fs.write", "net.send"):
        yield Variant(
            f"evidence:dispatch-stripped-audit:tool={tool_name}",
            lambda t=tool_name: _dispatch_stripped_audit_admits(t),
        )


# --- BYPASSABLE families (predict: first variant ADMITS = minimal bypass) -----------


def _gen_forged_authorization(budget: int) -> Iterator[Variant]:
    """Unsigned (dev) posture has no cryptographic root of trust: a self-minted ALLOW
    verifies. The first, minimal forgery admits."""
    yield Variant(
        "forge:unsigned-recompute:actor=attacker",
        lambda: _gate_admits(
            _mint(actor="attacker", validator_id="attacker-cabal"),
            require_signature=False,
            expected_actor="attacker",
        ),
    )
    for actor in ("mallory", "root", "agent-2"):
        yield Variant(
            f"forge:unsigned-recompute:actor={actor}",
            lambda a=actor: _gate_admits(
                _mint(actor=a, validator_id="attacker-cabal"),
                require_signature=False,
                expected_actor=a,
            ),
        )


def _gen_replayed_authorization(budget: int) -> Iterator[Variant]:
    """A call without an explicit ReceiptConsumptionLedger is stateless: the same
    receipt can authorize re-execution. The replay (second admission) records that
    unconfigured precondition; ledger-backed calls are covered separately by the
    static manifest."""

    def _replay(args: dict[str, Any]) -> bool:
        receipt = _mint(args=args)
        first = _gate_admits(receipt, args=args)
        second = _gate_admits(receipt, args=args)  # replay: identical receipt, new call
        return first and second

    yield Variant("replay:same-receipt-twice", lambda: _replay(ARGS))
    for aid, av in _ARGS_VARIANTS[1:3]:
        yield Variant(f"replay:same-receipt-twice:args={aid}", lambda av=av: _replay(av))


def _gen_ledger_tampering(budget: int) -> Iterator[Variant]:
    """The keyless chain has no external head anchor: a self-consistent rewrite /
    truncation passes verify_chain(). The bypass is verify_chain reporting valid on a
    chain from which an event was silently removed."""

    def _rewrite_admits(drop_index: int, seed_n: int) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "audit.jsonl"
            store = ChainHashAuditStore(audit_path)
            for i in range(seed_n):
                store.append(
                    DecisionRecord(
                        decision=Decision.ALLOW,
                        tool=f"tool-{i}",
                        argument_hash="h",
                        policy_version="v1",
                        event_id=f"ev{i}",
                    )
                )
            events = list(store.iter_events())
            kept = [event for i, event in enumerate(events) if i != drop_index]
            previous = GENESIS_HASH
            rewritten: list[dict[str, Any]] = []
            for event in kept:
                payload = dict(event)
                payload["previous_hash"] = previous
                payload.pop("event_hash", None)
                payload["event_hash"] = sha256_json(payload)
                rewritten.append(payload)
                previous = payload["event_hash"]
            audit_path.write_text(
                "\n".join(json.dumps(payload, sort_keys=True) for payload in rewritten) + "\n",
                encoding="utf-8",
            )
            result = ChainHashAuditStore(audit_path).verify_chain()
            return result["valid"] is True and result["checked"] == len(kept)

    yield Variant("ledger:drop-middle+rewrite", lambda: _rewrite_admits(1, 3))
    yield Variant("ledger:drop-tail+rewrite", lambda: _rewrite_admits(2, 3))
    yield Variant("ledger:drop-head+rewrite", lambda: _rewrite_admits(0, 4))


def _gen_policy_downgrade(budget: int) -> Iterator[Variant]:
    """expected_policy_hash / expected_policy_bundle_id default to None: an unpinned
    gate accepts a receipt minted under a stale/permissive policy. The first unpinned
    variant admits."""
    yield Variant(
        "downgrade:unpinned-policy-hash",
        lambda: _gate_admits(
            _mint(policy_hash="policy/v1-permissive", policy_version="v1-permissive"),
            expected_policy_hash=None,
        ),
    )
    yield Variant(
        "downgrade:unpinned-bundle-id",
        lambda: _gate_admits(
            _mint(policy_bundle_id="stale-bundle"),
            expected_policy_bundle_id=None,
        ),
    )


def _gen_validator_bypass(budget: int) -> Iterator[Variant]:
    """An authority binding only protects the call when the caller supplies it.

    The first variant is the pinned negative control: the existing executor
    rejects a receipt whose authority differs from the required authority. The
    remaining variants deliberately omit that expectation and demonstrate the
    configuration precondition without claiming the gate lacks the capability.
    """
    yield Variant(
        "authority:pinned-escalated-scope-rejected",
        lambda: _gate_admits(
            _mint(authority="tenant-A/ADMIN-grant"),
            expected_authority="tenant-A/write-grant",
        ),
    )
    yield Variant(
        "authority:unpinned-escalated-scope",
        lambda: _gate_admits(_mint(authority="tenant-A/ADMIN-grant")),
    )
    for scope in ("tenant-A/root-grant", "*/superuser", "tenant-A/"):
        yield Variant(
            f"authority:unpinned-scope={scope}",
            lambda value=scope: _gate_admits(_mint(authority=value)),
        )


VARIANT_GENERATORS: dict[str, Callable[..., Iterable[Variant]]] = {
    "signature-stripping": _gen_signature_stripping,
    "tenant-crossover": _gen_tenant_crossover,
    "evidence-omission": _gen_evidence_omission,
    "forged-authorization": _gen_forged_authorization,
    "replayed-authorization": _gen_replayed_authorization,
    "ledger-tampering": _gen_ledger_tampering,
    "policy-downgrade": _gen_policy_downgrade,
    "validator-bypass": _gen_validator_bypass,
}


def adaptive_attack(class_name: str, *, budget: int = DEFAULT_BUDGET) -> AdaptiveResult:
    """Enumerate <= ``budget`` deterministic, defense-aware variants of ``class_name``'s
    canonical attack, run each against the REAL surface, and stop at the first the
    surface WRONGLY ADMITS (the bypass). Pure function of (class_name, budget)."""
    if class_name not in VARIANT_GENERATORS:
        raise KeyError(f"no variant generator for adversary class {class_name!r}")
    generator = VARIANT_GENERATORS[class_name]
    tried = 0
    first_bypass: str | None = None
    for variant in generator(budget):
        if tried >= budget:
            break
        tried += 1
        if variant.admits():
            first_bypass = variant.variant_id
            break
    return AdaptiveResult(
        class_name=class_name,
        variants_tried=tried,
        first_bypass=first_bypass,
        stable=first_bypass is None,
    )
