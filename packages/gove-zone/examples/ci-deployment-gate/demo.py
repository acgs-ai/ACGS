"""CI / deployment-action gate — fail the pipeline when a deploy is denied.

What this shows
---------------
gove-zone used as a CI/CD gate that **fails closed with a non-zero exit code**
when a deployment action is denied (or escalated). A CI step that runs this gate
turns a governance decision into a pipeline result: ALLOW → exit 0, the deploy
proceeds; DENY/ESCALATE → non-zero, the pipeline stops and the signed Decision
Receipt is left in the CI log as verifiable evidence of *why*.

The governed action is a "deploy" payload, e.g.::

    {"action": "deploy", "environment": "prod", "image": "svc@sha256:...",
     "proposer": "ci-bot", "approver": "release-manager"}

Two INDEPENDENT guards run on every deploy:

  * **Environment gate (the WHAT)** — a policy on the deploy itself. The
    ``RuleSetPolicy`` denies ``deploy`` to ``prod`` and escalates ``deploy`` to
    ``restricted`` (matched by the path ``env/<environment>``), so promoting to a
    protected environment cannot slip through the same low-friction path as a
    staging deploy. (Staging is allowed.) This guard does NOT inspect who the
    proposer or approver is — it is purely about the action.
  * **Approver separation / MACI (the WHO)** — independent of the environment
    gate. The receipt is issued with the *approver* as the distinct validating
    principal and the *proposer* as the actor. If a deploy tries to self-approve
    (approver == proposer) the receipt **cannot be issued at all**: issuance
    fails closed before any receipt exists. This is the cryptographic identity
    guard (proposer != validator), separate from the policy decision.

This is the integration PATTERN, not a vendored CI SDK. The "deploy" tool is a
local stub that records whether it ran; no real registry/cluster is touched and
nothing is pushed anywhere. The whole thing writes only to a tempdir.

Honest scope
------------
Status: foundational / Alpha (gove-zone ``0.1.0.dev0``). This is *local* proof
of the receipt-gate invariant ("No valid Decision Receipt, no side effect")
applied to a deploy decision. It is **not** a production-, compliance-, or
regulator-ready CI security control, and the ephemeral signing key generated
here is for self-contained demonstration only — a real deployment would inject a
trusted signer/verifier from KMS/secret storage, not mint one at runtime.

Run it
------
    .venv-ci/bin/python examples/ci-deployment-gate/demo.py            # self-test
    .venv-ci/bin/python examples/ci-deployment-gate/demo.py --payload '{...}'  # gate one payload

``main()`` (no args / ``--selftest``) runs an ALLOW case and a DENY case in
sequence and asserts the exit-code contract: allow → 0, deny → non-zero. It
returns 0 only if the gate behaved as expected for both, so ``python demo.py``
exits 0 in CI-of-the-demo.

The single-payload mode (``--payload '<json>'`` / ``$DEPLOY_PAYLOAD``) is the one
a real GitHub Actions step calls: it gates exactly one payload and exits with
the gate's own code, so a denied deploy fails the pipeline. An explicitly
requested but empty / malformed payload fails closed (non-zero) rather than
no-op'ing into an ungated deploy. See README.md for a copy-pasteable GitHub
Actions snippet.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    Ed25519Signer,
    GovernanceProfile,
    ProductionProfileError,
    ReceiptValidationError,
    RuleSetPolicy,
)
from gove_zone.receipt import DecisionReceipt, Validator
from gove_zone.tenant import TenantPolicyStore, evaluate_tenant_action

# --- Trust-boundary constants -------------------------------------------------
# The CI organization / tenant whose deploy policy bundle governs this pipeline.
TENANT = "org-acme"
# Where the deploy would actually run. In real CI this is the runner / cluster
# identity, established by the runtime — not taken from the payload.
EXECUTION_BOUNDARY = "ci-runner"
# The AUTHENTICATED identity of the principal invoking the gate. In real CI this
# is the runner's workload identity (OIDC token subject / service account), NOT
# a field read from the deploy payload — an attacker who controls the payload
# could otherwise set it to match a forged receipt. Modelling it as a separate
# constant makes the trust boundary explicit (mirrors CALLER_IDENTITY in the
# receipt-gated-execution demo).
CALLER_IDENTITY = "ci-bot"
AUTHORITY = "org-acme/deploy-grant"
# Reserved exit code for an internal invariant violation (a side effect ran
# despite a refused receipt, or an ALLOW receipt never reached the deploy). It is
# non-zero so a CI gate still fails closed, but the self-test treats it as a hard
# failure rather than a healthy block — a leaked side effect must never "pass".
INVARIANT_VIOLATION_RC = 99


# --- Output helpers -----------------------------------------------------------
def _green(msg: str) -> str:
    return f"\033[32m{msg}\033[0m"


def _red(msg: str) -> str:
    return f"\033[31m{msg}\033[0m"


def _ok(msg: str) -> None:
    print(f"  {_green('✓')} {msg}")


def _bad(msg: str) -> None:
    print(f"  {_red('✗')} {msg}")


# --- The deploy "tool": a local side-effect stub ------------------------------
class DeployTool:
    """Stand-in for a real deployment action. Records whether it actually ran.

    The whole point of the gate is that this NEVER runs for a denied payload.
    """

    def __init__(self) -> None:
        self.ran = False
        self.deployed: dict[str, Any] | None = None

    def run(self, **kwargs: Any) -> str:
        self.ran = True
        self.deployed = kwargs
        return f"DEPLOYED {kwargs.get('image', '?')} -> {kwargs.get('environment', '?')}"


# --- Policy: the deploy gate bundle -------------------------------------------
def _deploy_policy() -> RuleSetPolicy:
    """Deny ``prod`` deploys, escalate ``restricted`` deploys; allow elsewhere.

    The environment is carried in the tool-call PATH (``env/<environment>``), so
    a ``path_prefix`` of ``env/<environment>`` is the protected-path match.
    (State-based rules cannot be used here: the tenant issuance path evaluates
    with an empty state, so the rule must key on tool name + path — both of which
    survive.) Both a ``deny`` and an ``escalate`` decision yield a signed receipt
    that the side-effect gate refuses, so both fail the pipeline closed.
    """
    return RuleSetPolicy.from_dict(
        {
            "id": "deploy-policy",
            "rules": [
                {
                    "id": "PROD_DEPLOY_GATE",
                    "effect": "deny",
                    "tools": ["deploy"],
                    "path_prefix": ["env", "prod"],
                    "reason": (
                        "production deploys are gated: promote to prod only via "
                        "the change-managed path, not the standard CI deploy step"
                    ),
                },
                {
                    "id": "RESTRICTED_ESCALATE",
                    "effect": "escalate",
                    "tools": ["deploy"],
                    "path_prefix": ["env", "restricted"],
                    "reason": (
                        "restricted environment deploys require an out-of-band "
                        "human approval before the side effect may run"
                    ),
                },
            ],
        }
    )


def _rule_reason(store: TenantPolicyStore, matched_rule_ids: list[str]) -> str:
    """Resolve the human reason text for the rule(s) the receipt matched.

    The receipt carries only the matched rule *ids*; the rich reason lives in the
    policy bundle. We look it back up so the CI log shows *why*, not just an id.
    """
    if not matched_rule_ids:
        return ""
    policy = store.load_bundle(TENANT, TENANT)
    reasons = {rule.rule_id: rule.reason for rule in getattr(policy, "rules", ())}
    return "; ".join(reasons[rid] for rid in matched_rule_ids if reasons.get(rid))


def _issuance_args(payload: dict[str, Any]) -> dict[str, Any]:
    """Build the tool-call args for issuance from a deploy payload.

    ``path`` drives the protected-path policy match; the rest is the recorded
    deploy descriptor that the receipt is bound to and the tool would receive.
    """
    environment = str(payload.get("environment", ""))
    return {
        "path": ["env", environment],
        "environment": environment,
        "image": str(payload.get("image", "")),
        "target": str(payload.get("target", environment)),
    }


# --- The gate seam: one payload -> one exit code ------------------------------
def gate(
    payload: dict[str, Any],
    *,
    profile: GovernanceProfile,
    signer: Ed25519Signer,
    store: TenantPolicyStore,
    audit: ChainHashAuditStore,
) -> int:
    """Govern one deploy *payload*. Return 0 to allow the pipeline, non-zero to fail it.

    Pipeline (fail-closed at every step):

      1. Issue a signed Decision Receipt for the deploy (MACI: approver is the
         validator, proposer is the actor — issuance refuses self-approval).
      2. Verify + execute through the production-profile gate. A DENY/ESCALATE
         receipt, a tampered/forged receipt, or a missing verifier all raise.
      3. ALLOW → run the (stub) deploy, print receipt + audit evidence, exit 0.
         DENY/ESCALATE/refusal → print the reason + receipt, exit non-zero.
    """
    proposer = str(payload.get("proposer", CALLER_IDENTITY))
    approver = str(payload.get("approver", ""))
    environment = str(payload.get("environment", "?"))
    image = str(payload.get("image", "?"))

    print(
        f"  payload: deploy {image} -> {environment} (proposer={proposer!r}, approver={approver!r})"
    )

    if not approver:
        # No distinct approver supplied at all → cannot form a MACI authority.
        print(f"  {_red('DENY')}: no approver — a distinct approver is required (MACI)")
        return 3

    args = _issuance_args(payload)

    # Step 1 — issue the receipt. Self-approval (approver == proposer) fails
    # closed HERE, before any receipt exists: there is nothing to execute and
    # nothing to print but the reason. That is the cryptographic WHO guard.
    try:
        receipt: DecisionReceipt = evaluate_tenant_action(
            store=store,
            tenant_id=TENANT,
            requester_tenant_id=TENANT,
            action="deploy",
            args=args,
            execution_boundary=EXECUTION_BOUNDARY,
            request_id=str(payload.get("request_id", "deploy-req")),
            actor=proposer,
            validator=Validator(approver),
            authority=AUTHORITY,
            audit_store=audit,
            signer=signer,  # production profile: signed at issuance
        )
    except ReceiptValidationError as exc:
        # e.g. self-validation: approver == proposer
        print(f"  {_red('DENY')} (no receipt issued): {exc}")
        return 2

    print(f"  decision={receipt.decision}  matched_rules={list(receipt.matched_rules)}")
    print(
        f"  receipt_id={receipt.receipt_id[:16]}…  "
        f"signature={receipt.signature_algorithm}  "
        f"receipt_hash={receipt.receipt_hash[:16]}…"
    )
    print(f"  approval_chain={receipt.approval_chain_summary}")

    deploy = DeployTool()

    # Step 2 — verify + execute through the production-profile gate. The profile
    # resolves {require_signature: True, verifier: <public key>}; a DENY receipt
    # is refused before the side effect can run.
    from gove_zone import execute_with_receipt

    try:
        result = execute_with_receipt(
            tool_fn=deploy.run,
            args=args,
            receipt=receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=EXECUTION_BOUNDARY,
            expected_action="deploy",
            expected_actor=CALLER_IDENTITY,
            **profile.as_gate_kwargs(),  # require_signature=True, verifier=<pubkey>
        )
    except ReceiptValidationError as exc:
        # DENY / ESCALATE / tampered / forged — all land here, fail-closed.
        if deploy.ran:
            _bad("INVARIANT VIOLATED: deploy ran despite a refused receipt")
            return INVARIANT_VIOLATION_RC
        verdict = str(receipt.decision).upper()
        # The receipt records WHICH rule fired; surface that rule's human reason.
        rule_reason = _rule_reason(store, list(receipt.matched_rules))
        print(f"  {_red(verdict)}: deploy gate refused execution: {exc}")
        if rule_reason:
            print(f"  policy reason: {rule_reason}")
        print(
            f"  {_red('CI RESULT: pipeline fails (non-zero).')} "
            "Signed receipt above is the audit evidence."
        )
        return 1

    # Step 3 — ALLOW: the side effect ran.
    if not deploy.ran:
        _bad("INVARIANT VIOLATED: ALLOW receipt did not reach the deploy")
        return INVARIANT_VIOLATION_RC
    _ok(f"deploy executed: {result}")
    chain = audit.verify_chain()
    if not chain["valid"]:
        _bad(f"audit chain failed verification: {chain['failures']}")
        return INVARIANT_VIOLATION_RC
    _ok(
        f"audit chain verified: {chain['checked']} tamper-evident event(s); "
        f"this decision anchored at {receipt.audit_event_hash[:16]}…"
    )
    print(
        f"  {_green('CI RESULT: pipeline proceeds (exit 0).')} "
        "Signed receipt is the deploy authorization on record."
    )
    return 0


# --- Build the production-profile context (signed) ----------------------------
def _build_context(
    workdir: Path,
) -> tuple[GovernanceProfile, Ed25519Signer, TenantPolicyStore, ChainHashAuditStore]:
    """Production profile + a freshly generated Ed25519 signer/verifier pair.

    Generating the keypair in-process is fine for a self-contained example: the
    point is to exercise the signed gate end to end. A real CI gate injects a
    trusted signer at issuance and a trusted public-key verifier at the gate from
    secret storage / KMS — it would NOT mint an ephemeral key at runtime.
    """
    signer = Ed25519Signer.generate()
    verify_key = Ed25519Signer.from_public_bytes(signer.public_bytes())
    # Lead with the production profile (the secure default): signed receipts
    # required at the gate, verified against the public key.
    profile = GovernanceProfile.production(signer=signer, verifier=verify_key)
    store = TenantPolicyStore(workdir / "policies")
    store.store_bundle(TENANT, _deploy_policy())
    audit = ChainHashAuditStore(workdir / "audit.jsonl")
    return profile, signer, store, audit


# --- Entry points -------------------------------------------------------------
def run_payload(payload: dict[str, Any]) -> int:
    """Single-payload mode: gate one deploy and return its exit code.

    This is what a real GitHub Actions step calls — a denied deploy returns
    non-zero and fails the job.
    """
    workdir = Path(tempfile.mkdtemp(prefix="gove-zone-ci-gate-"))
    profile, signer, store, audit = _build_context(workdir)
    print("\ngove-zone — CI deployment gate (production profile, signed receipts)")
    print(
        f"(tenant={TENANT}  boundary={EXECUTION_BOUNDARY}  "
        f"profile={'production' if profile.is_production else profile.name})\n"
    )
    rc = gate(payload, profile=profile, signer=signer, store=store, audit=audit)
    print(f"\n(audit log: {audit.path})  exit={rc}\n")
    return rc


def main() -> int:
    """Self-test: run an ALLOW case and a DENY case; assert the exit contract.

    Returns 0 iff the gate behaved as expected: allow → 0, deny → non-zero.
    """
    workdir = Path(tempfile.mkdtemp(prefix="gove-zone-ci-gate-"))
    profile, signer, store, audit = _build_context(workdir)

    print("\ngove-zone — CI deployment gate proof")
    print(
        "Contract: ALLOW deploy → exit 0 (pipeline proceeds); "
        "DENY/ESCALATE → non-zero (pipeline fails closed)."
    )
    print(f"Profile: production (signed receipts required), boundary={EXECUTION_BOUNDARY}\n")

    failures: list[str] = []

    # --- ALLOW case: staging deploy with a distinct approver (MACI satisfied) --
    print("[1] ALLOW — staging deploy, distinct approver (proposer != approver)")
    allow_payload = {
        "action": "deploy",
        "environment": "staging",
        "image": "checkout-svc@sha256:1111aaaa",
        "proposer": CALLER_IDENTITY,
        "approver": "release-manager",
        "request_id": "deploy-staging-1",
    }
    rc_allow = gate(allow_payload, profile=profile, signer=signer, store=store, audit=audit)
    if rc_allow == 0:
        _ok("ALLOW path returned exit 0 as expected")
    else:
        failures.append(f"ALLOW case returned {rc_allow}, expected 0")
        _bad(f"ALLOW path returned {rc_allow}, expected 0")

    # --- DENY case: prod deploy → policy denies → signed deny receipt printed ---
    print("\n[2] DENY — prod deploy, distinct approver, blocked by PROD_DEPLOY_GATE")
    deny_payload = {
        "action": "deploy",
        "environment": "prod",
        "image": "checkout-svc@sha256:2222bbbb",
        "proposer": CALLER_IDENTITY,
        "approver": "release-manager",
        "request_id": "deploy-prod-1",
    }
    rc_deny = gate(deny_payload, profile=profile, signer=signer, store=store, audit=audit)
    if rc_deny != 0 and rc_deny != INVARIANT_VIOLATION_RC:
        _ok(f"DENY path returned non-zero exit ({rc_deny}) as expected — pipeline fails closed")
    else:
        failures.append(f"DENY case returned {rc_deny}, expected a clean non-zero block")
        _bad(f"DENY path returned {rc_deny}, expected a clean non-zero block")

    # --- ESCALATE case: restricted env → signed escalate receipt → gate refuses --
    print("\n[3] ESCALATE — restricted-env deploy, blocked by RESTRICTED_ESCALATE")
    escalate_payload = {
        "action": "deploy",
        "environment": "restricted",
        "image": "checkout-svc@sha256:3333cccc",
        "proposer": CALLER_IDENTITY,
        "approver": "release-manager",
        "request_id": "deploy-restricted-1",
    }
    rc_escalate = gate(escalate_payload, profile=profile, signer=signer, store=store, audit=audit)
    if rc_escalate != 0 and rc_escalate != INVARIANT_VIOLATION_RC:
        _ok(
            f"ESCALATE path returned non-zero exit ({rc_escalate}) as expected — "
            "pipeline fails closed pending human approval"
        )
    else:
        failures.append(f"ESCALATE case returned {rc_escalate}, expected a clean non-zero block")
        _bad(f"ESCALATE path returned {rc_escalate}, expected a clean non-zero block")

    # --- DENY case 2: self-approval → no receipt issued (cryptographic MACI) ----
    print("\n[4] DENY — self-approval (approver == proposer): refused at issuance, no receipt")
    self_approve_payload = {
        "action": "deploy",
        "environment": "staging",
        "image": "checkout-svc@sha256:4444dddd",
        "proposer": CALLER_IDENTITY,
        "approver": CALLER_IDENTITY,  # same principal proposes AND approves
        "request_id": "deploy-self-1",
    }
    rc_self = gate(self_approve_payload, profile=profile, signer=signer, store=store, audit=audit)
    if rc_self != 0:
        _ok(f"self-approval returned non-zero exit ({rc_self}) — MACI separation held")
    else:
        failures.append("self-approval case returned 0, expected non-zero")
        _bad("self-approval path returned 0, expected non-zero")

    # --- Production-profile safety: no verifier fails closed loud --------------
    print("\n[5] Production profile with NO verifier fails closed loud")
    from gove_zone import execute_with_receipt

    misconfigured = GovernanceProfile.production()  # no verifier supplied
    try:
        execute_with_receipt(
            tool_fn=lambda **_: "should not run",
            args={"environment": "staging"},
            receipt=None,
            expected_tenant_id=TENANT,
            expected_execution_boundary=EXECUTION_BOUNDARY,
            expected_action="deploy",
            expected_actor=CALLER_IDENTITY,
            **misconfigured.as_gate_kwargs(),
        )
        failures.append("production profile with no verifier did not fail closed")
        _bad("production profile with no verifier did not raise")
    except ProductionProfileError:
        _ok(
            "production profile with no verifier raised ProductionProfileError "
            "(no silent downgrade)"
        )

    print()
    if failures:
        print(_red("CONTRACT VIOLATED:"))
        for f in failures:
            print(_red(f"  - {f}"))
        return 1

    print(_green("Exit-code contract held: ALLOW→0, DENY/ESCALATE/self-approval→non-zero."))
    print(f"(audit log: {audit.path})\n")
    return 0


def _load_payload_from_args(argv: list[str]) -> tuple[str, Any]:
    """Resolve a single deploy payload from ``--payload`` / ``$DEPLOY_PAYLOAD``.

    Returns ``(kind, value)``:

    * ``("payload", dict)`` — a valid deploy payload was supplied.
    * ``("invalid", message)`` — a payload was EXPLICITLY requested (``--payload``
      or ``$DEPLOY_PAYLOAD``) but is empty / malformed. The caller must fail
      closed (non-zero) here — an unset/typo'd CI variable must NEVER silently
      no-op into an ungated deploy.
    * ``("none", "")`` — no payload requested at all (bare run); the caller
      self-tests.

    Note: this intentionally does NOT read stdin. The documented CI path passes
    the payload explicitly (``--payload "$DEPLOY_PAYLOAD"``) so a bare
    ``python demo.py`` is unambiguously the self-test, never a payload no-op.
    """
    import os

    raw: str | None = None
    explicit = False
    if "--payload" in argv:
        explicit = True
        idx = argv.index("--payload")
        if idx + 1 < len(argv):
            raw = argv[idx + 1]
    elif "DEPLOY_PAYLOAD" in os.environ:
        explicit = True
        raw = os.environ["DEPLOY_PAYLOAD"]

    if raw is None or not raw.strip():
        if explicit:
            return ("invalid", "deploy payload was requested but empty (fail closed)")
        return ("none", "")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return ("invalid", f"deploy payload is not valid JSON: {exc}")
    if not isinstance(parsed, dict):
        return ("invalid", "deploy payload must be a JSON object")
    return ("payload", parsed)


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--selftest" in args:
        # Explicit self-test always runs the allow+deny contract proof.
        sys.exit(main())
    # Single-payload mode if a payload is supplied via --payload / $DEPLOY_PAYLOAD.
    # A bare `python demo.py` (no payload requested) self-tests and exits 0 as the
    # demo's own CI requires.
    kind, value = _load_payload_from_args(args)
    if kind == "payload":
        sys.exit(run_payload(value))
    if kind == "invalid":
        # An explicitly-requested-but-bad payload fails closed, never self-tests.
        print(f"\ngove-zone CI gate: {value}", file=sys.stderr)
        print("CI RESULT: pipeline fails (non-zero). Fix the deploy payload.", file=sys.stderr)
        sys.exit(64)
    # kind == "none": bare interactive run -> self-test.
    sys.exit(main())
