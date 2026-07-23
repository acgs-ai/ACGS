"""Deterministic adaptive-attack layer over the gove-zone adversary suite.

Motivation (see ``docs/research/adaptive-eval-adversary-analysis.md``): the static
manifest calls a class DEFENDED because ONE hand-written template fails against the
gate. arXiv:2606.26479 warns that exact methodology made in-band defenses look strong
until *defense-aware, adaptive* attacks broke them. This module ports that idea to a
DETERMINISTIC reference monitor: for each manifest class it enumerates a bounded,
fixed, defense-aware *variant family* around the class's canonical exploit and runs
every variant against the REAL surface (``execute_with_receipt`` / ``Kernel.dispatch`` /
``verify_chain`` / the PQL compiler / a framework adapter — never a mock).

A "bypass" means the surface WRONGLY ADMITS: the side effect ran, the receipt was
accepted, or ``verify_chain()`` returned valid when it should not. For a deterministic
gate the verdict is binary per class:

* **stable** — no variant in the bounded family bypassed the surface (a stronger,
  machine-checked statement than "survives one template"), or
* **bypassable** — the first admitted variant is a concrete, minimal exploit.

``adaptive_attack(class_name, budget)`` is a pure function of its arguments (ephemeral
Ed25519 key material for signed-variant families is incidental — the ADMIT/DENY verdict
and the variant ids are invariant, so the returned :class:`AdaptiveResult` is
reproducible and CI-checkable).

HONEST SCOPE (verbatim in README): this is a deterministic config/input-space variant
search over gove-zone's own gate — NOT a model-in-the-loop adaptive evaluation. No
model, no AgentDojo, no GCG. "Adaptively stable" != "secure"; it means only "no bounded
variant in family F bypassed surface S." It touches no ``src/gove_zone/**`` code — this
is a test-suite layer over the existing gate.
"""

from __future__ import annotations

import dataclasses
import json
import tempfile
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

from gove_zone import (
    AllowAllPolicy,
    ChainHashAuditStore,
    Decision,
    DecisionReceipt,
    DecisionRecord,
    DeniedError,
    Ed25519Signer,
    Kernel,
    ManagedAgent,
    ProductionProfileError,
    ReceiptValidationError,
    RuleSetPolicy,
    Validator,
    execute_with_receipt,
)
from gove_zone.adapters.autogen import govern_autogen_tool
from gove_zone.audit import GENESIS_HASH
from gove_zone.decision import sha256_json
from gove_zone.errors import AuditError, EscalateError, UnknownToolError
from gove_zone.executor import adapter_artifact_digest
from gove_zone.pql_compiler import compile_pql_to_ruleset
from gove_zone.tool import ToolCall
from tests.adversary.conftest import _SIGNER, StrictGateDependencies, strict_gate_dependencies

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
_DEFAULT_SIGNER = object()


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
    signer: Any = _DEFAULT_SIGNER,
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
        signer=_SIGNER if signer is _DEFAULT_SIGNER else signer,
    )


def _gate_admits(
    receipt: DecisionReceipt | None,
    *,
    args: dict[str, Any] | None = None,
    require_signature: bool = True,
    verifier: Any = _SIGNER,
    expected_tenant_id: str = TENANT,
    expected_execution_boundary: str = BOUNDARY,
    expected_action: str = ACTION,
    expected_actor: str = "agent-1",
    expected_policy_hash: str | None = "policy/v2-current",
    expected_policy_bundle_id: str | None = "policy-bundle",
    expected_authority: str | None = "tenant-A/write-grant",
    expected_validator_id: str | None = "constitutional-council",
    dependencies: StrictGateDependencies | None = None,
) -> bool:
    """Run a receipt through the REAL gate; True iff the side effect ran (admitted)."""
    side_effect = _SideEffect()
    active_dependencies = dependencies or strict_gate_dependencies(Path(tempfile.mkdtemp()))
    kwargs: dict[str, Any] = dict(
        tool_fn=side_effect.run,
        args=ARGS if args is None else args,
        receipt=receipt,
        expected_tenant_id=expected_tenant_id,
        expected_execution_boundary=expected_execution_boundary,
        expected_action=expected_action,
        expected_actor=expected_actor,
        expected_policy_hash=expected_policy_hash,
        expected_policy_bundle_id=expected_policy_bundle_id,
        expected_authority=expected_authority,
        expected_validator_id=expected_validator_id,
        verifier=verifier,
        require_signature=require_signature,
        consumption_store=active_dependencies.consumption_store,
        rejection_audit=active_dependencies.rejection_audit,
    )
    try:
        execute_with_receipt(
            expected_adapter_artifact_digest=adapter_artifact_digest((kwargs)["tool_fn"]), **kwargs
        )
    except _DENY_EXCEPTIONS:
        return False
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
_WRONG_TENANTS = ("tenant-B", "tenant-C", "", "tenant-a", "TENANT-A", "tenant-A​")
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
    """True iff *exc* is one of the kernel's deny signals (a DENY, not an admit). Any
    OTHER exception is a broken harness and must propagate — never faked into a DENY."""
    return issubclass(exc, (DeniedError, EscalateError, AuditError, UnknownToolError))


def _dispatch_anchor_before_execute_admits(tool_name: str) -> bool:
    """Kernel.dispatch anchors every decision in the audit chain BEFORE the tool runs
    (kernel._evaluate_and_record appends, then dispatch executes). Bypass iff the side
    effect ran while its evidence was NOT yet present in the chain (a reordered anchor)."""
    tmp = Path(tempfile.mkdtemp()) / "audit.jsonl"
    store = ChainHashAuditStore(tmp)
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
    # admit == side effect ran WITHOUT its evidence anchored first.
    return observed["ran"] and not observed["anchored_first"]


def _dispatch_stripped_audit_admits(tool_name: str) -> bool:
    """With the audit sink failing, the anchor-before-execute invariant must fail closed:
    the append raises, the kernel raises AuditError, and the tool never runs. Bypass iff
    the side effect ran despite the evidence never being recorded."""
    tmp = Path(tempfile.mkdtemp()) / "audit.jsonl"
    store = _BrokenAuditStore(tmp)
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
            return False
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
    """The strict standalone path requires a signature from its configured trust root;
    unsigned self-minted ALLOW receipts must all be denied."""
    yield Variant(
        "forge:unsigned-recompute:actor=attacker",
        lambda: _gate_admits(
            _mint(actor="attacker", validator_id="attacker-cabal", signer=None),
            expected_actor="attacker",
        ),
    )
    for actor in ("mallory", "root", "agent-2"):
        yield Variant(
            f"forge:unsigned-recompute:actor={actor}",
            lambda a=actor: _gate_admits(
                _mint(actor=a, validator_id="attacker-cabal", signer=None),
                expected_actor=a,
            ),
        )


def _gen_replayed_authorization(budget: int) -> Iterator[Variant]:
    """The strict standalone gate durably consumes the receipt before execution; the
    first use admits and the second use must be denied by the same dependency set."""

    def _replay(args: dict[str, Any]) -> bool:
        receipt = _mint(args=args)
        dependencies = strict_gate_dependencies(Path(tempfile.mkdtemp()))
        first = _gate_admits(receipt, args=args, dependencies=dependencies)
        second = _gate_admits(receipt, args=args, dependencies=dependencies)
        return first and second

    yield Variant("replay:same-receipt-twice", lambda: _replay(ARGS))
    for aid, av in _ARGS_VARIANTS[1:3]:
        yield Variant(f"replay:same-receipt-twice:args={aid}", lambda av=av: _replay(av))


def _gen_ledger_tampering(budget: int) -> Iterator[Variant]:
    """The keyless chain has no external head anchor: a self-consistent rewrite /
    truncation passes verify_chain(). The bypass is verify_chain reporting valid on a
    chain from which an event was silently removed."""

    def _rewrite_admits(drop_index: int, seed_n: int) -> bool:
        tmp = Path(tempfile.mkdtemp()) / "audit.jsonl"
        store = ChainHashAuditStore(tmp)
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
        kept = [ev for i, ev in enumerate(events) if i != drop_index]
        previous = GENESIS_HASH
        rewritten: list[dict[str, Any]] = []
        for ev in kept:
            payload = dict(ev)
            payload["previous_hash"] = previous
            payload.pop("event_hash", None)
            payload["event_hash"] = sha256_json(payload)
            rewritten.append(payload)
            previous = payload["event_hash"]
        tmp.write_text(
            "\n".join(json.dumps(p, sort_keys=True) for p in rewritten) + "\n",
            encoding="utf-8",
        )
        result = ChainHashAuditStore(tmp).verify_chain()
        # Bypass: the deleted event left no trace yet the chain verifies as valid.
        return result["valid"] is True and result["checked"] == len(kept)

    yield Variant("ledger:drop-middle+rewrite", lambda: _rewrite_admits(1, 3))
    yield Variant("ledger:drop-tail+rewrite", lambda: _rewrite_admits(2, 3))
    yield Variant("ledger:drop-head+rewrite", lambda: _rewrite_admits(0, 4))


def _gen_policy_downgrade(budget: int) -> Iterator[Variant]:
    """The strict standalone caller pins the in-force hash and bundle identity; stale
    or substituted policy artifacts must be denied."""
    yield Variant(
        "downgrade:unpinned-policy-hash",
        lambda: _gate_admits(
            _mint(policy_hash="policy/v1-permissive", policy_version="v1-permissive"),
            expected_policy_hash="policy/v2-current",
        ),
    )
    yield Variant(
        "downgrade:unpinned-bundle-id",
        lambda: _gate_admits(
            _mint(policy_bundle_id="stale-bundle"),
            expected_policy_bundle_id="policy-bundle",
        ),
    )


def _gen_validator_bypass(budget: int) -> Iterator[Variant]:
    """The strict standalone caller pins trusted authority and validator identity;
    receipts carrying substituted authority scopes must be denied."""
    yield Variant(
        "authority:gate-ignores-escalated-scope",
        lambda: _gate_admits(_mint(authority="tenant-A/ADMIN-grant")),
    )
    for scope in ("tenant-A/root-grant", "*/superuser", "tenant-A/"):
        yield Variant(
            f"authority:gate-ignores-scope={scope}",
            lambda s=scope: _gate_admits(_mint(authority=s)),
        )


def _gen_policy_default_allow(budget: int) -> Iterator[Variant]:
    """RuleSetPolicy is a deny/escalate-only overlay: an unmatched action falls through
    to ALLOW. Also: an empty PQL feed compiles to a functional allow-all. Both admit an
    un-modeled action."""

    def _dispatch_admits(tool_name: str, args: dict[str, Any]) -> bool:
        tmp = Path(tempfile.mkdtemp()) / "audit.jsonl"
        policy = RuleSetPolicy.from_dict(
            {
                "id": "deny-delete/v1",
                "rules": [{"id": "BLOCK_DELETE", "effect": "deny", "tools": ["fs.delete"]}],
            }
        )
        kernel = Kernel(policy=policy, audit=ChainHashAuditStore(tmp), actor="agent")
        ran: list[str] = []

        @kernel.tool(tool_name)
        def _tool(path: str = "x") -> str:
            ran.append(path)
            return "wrote"

        try:
            kernel.dispatch(tool_name, args)
        except DeniedError:
            return False
        return bool(ran)

    def _pql_empty_feed_admits() -> bool:
        policy = compile_pql_to_ruleset("prod-governance", [])
        record = policy.evaluate(
            ToolCall(name="sap.payment.send", args={"amount": 1_000_000}, actor="agent")
        )
        return record.decision is Decision.ALLOW

    yield Variant(
        "default-allow:unmatched-action=fs.write",
        lambda: _dispatch_admits("fs.write", {"path": "/etc/shadow"}),
    )
    yield Variant(
        "default-allow:pql-empty-feed=allow-all",
        _pql_empty_feed_admits,
    )
    for tool_name in ("net.exfil", "proc.spawn"):
        yield Variant(
            f"default-allow:unmatched-action={tool_name}",
            lambda t=tool_name: _dispatch_admits(t, {"path": "/x"}),
        )


def _gen_adapter_bypass(budget: int) -> Iterator[Variant]:
    """Probe that framework adapters cannot bypass a missing receipt dispatcher.

    This bounded family covers explicit ``AllowAllPolicy`` configurations. Raw
    ``Kernel.dispatch`` and public registry access remain outside this adapter surface.
    """

    def _adapter_admits(tool_label: str, path: str) -> bool:
        tmp = Path(tempfile.mkdtemp()) / "audit.jsonl"
        agent = ManagedAgent("vulnclaw", policy=AllowAllPolicy(), audit_path=tmp)
        ran: dict[str, int] = {"count": 0}

        def danger(path: str = "/etc/shadow") -> str:
            ran["count"] += 1
            return "SIDE EFFECT EXECUTED"

        wrapped = govern_autogen_tool(agent, tool_label, danger)
        try:
            wrapped(path=path)
        except DeniedError:
            return False
        return ran["count"] >= 1

    yield Variant(
        "adapter:explicit-allowall:tool=shell",
        lambda: _adapter_admits("shell", "/etc/shadow"),
    )
    for tool_label in ("exec", "http"):
        yield Variant(
            f"adapter:explicit-allowall:tool={tool_label}",
            lambda t=tool_label: _adapter_admits(t, "/etc/shadow"),
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
    "policy-default-allow": _gen_policy_default_allow,
    "adapter-bypass": _gen_adapter_bypass,
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
