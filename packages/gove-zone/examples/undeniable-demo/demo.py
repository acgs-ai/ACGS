"""The undeniable evidence path — gove-zone's flagship end-to-end proof.

A privileged AI tool call is DENIED by policy, the denial is captured in a
signed Decision Receipt, the receipts plus the append-only audit chain are
packaged into a portable evidence bundle, the bundle is re-verified OFFLINE,
and finally two independent tamper attempts are shown to FAIL — proving the
evidence cannot be quietly rewritten after the fact.

    No valid Decision Receipt, no side effect.

This is an EXECUTABLE proof, not a slide. Every step asserts its expected
outcome; if any invariant is violated the script exits non-zero. There is no
fake green: the final banner prints only if every assertion held.

--------------------------------------------------------------------------------
Integration PATTERN, not a vendored SDK
--------------------------------------------------------------------------------
A real deployment governs calls coming from an agent framework (an MCP tool
server, a LangGraph node, an OpenAI-Agents tool). To stay self-contained and
dependency-free, this demo models that framework's CALL SHAPE with a tiny
in-file stub (:class:`PrivilegedToolGateway`) and then governs it with
gove-zone's real API — the same policy evaluator, signed-receipt issuer,
executor gate, and audit chain you would wire into the real framework. We do
NOT import ``mcp`` / ``langgraph`` / ``openai-agents``; the gateway here only
demonstrates WHERE the gate slots in.

--------------------------------------------------------------------------------
Honest scope
--------------------------------------------------------------------------------
Status: foundational / Alpha (``0.1.0a1``). This proves the LOCAL invariant
with a keypair generated inside this process (correct and self-contained for a
pedagogical example, but obviously not real key custody). It is NOT a
production, compliance, or regulator-ready certification. See ``SECURITY.md``
for the full enforced-vs-out-of-scope boundary.

Run it (from the monorepo root)::

    uv run --package gove-zone python \\
        packages/gove-zone/examples/undeniable-demo/demo.py

or directly with a venv that has gove-zone installed::

    python packages/gove-zone/examples/undeniable-demo/demo.py
"""

from __future__ import annotations

import dataclasses
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from gove_zone import (
    ChainHashAuditStore,
    Decision,
    DecisionReceipt,
    Ed25519Signer,
    GovernanceProfile,
    ReceiptValidationError,
    RuleSetPolicy,
    TenantPolicyStore,
    Validator,
    __version__,
    evaluate_tenant_action,
    execute_with_receipt,
    normalize_path_context,
    replay_call,
)
from gove_zone.tool import ToolCall

# --- Fixed governance context for the scenario -------------------------------
TENANT = "tenant-acme"
BOUNDARY = "local-sandbox"
# A distinct MACI validating principal — NEVER the proposer ("payments-agent").
# An agent may *propose* a side effect but can never *validate* its own
# authority to run it.
VALIDATOR = Validator("constitutional-council")
AUTHORITY = "tenant-acme/payments-write-grant"
# The invoking principal's identity, supplied to the gate as expected_actor.
# In production this comes from the AUTHENTICATED session/runtime context — NOT
# from the request body or the receipt (using the request's own actor would be
# circular: an attacker controlling the request could match a forged receipt).
CALLER_IDENTITY = "payments-agent"

# The protected path prefix our policy guards. A write whose path starts here is
# denied unless the actor is explicitly allow-listed.
PROTECTED_PREFIX = "secrets/prod"


# --- ANSI evidence helpers (mirror the receipt-gated demo style) -------------
def _step(title: str) -> None:
    print(f"\n\033[1m{title}\033[0m")


def _ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m {msg}")


def _fail(msg: str) -> None:
    print(f"  \033[31m✗ INVARIANT VIOLATED: {msg}\033[0m")
    raise SystemExit(1)


# --- The modelled external framework (call SHAPE only, no real SDK) ----------
class PrivilegedToolGateway:
    """A stand-in for an agent-framework tool that performs a real side effect.

    Models the call shape an MCP tool server / LangGraph node / OpenAI-Agents
    tool would expose: ``invoke(path=..., content=...)`` writes a file. We track
    whether the side effect actually RAN so the deny path can be asserted to
    have produced NO effect on disk.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self.ran = False
        self.last_args: dict[str, Any] | None = None

    def invoke(self, *, path: str, content: str) -> str:
        """The privileged side effect: write a file under the gateway root."""
        self.ran = True
        self.last_args = {"path": path, "content": content}
        target = self._root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return f"WROTE {target}"


def _build_policy() -> RuleSetPolicy:
    """A RuleSetPolicy that denies writes into the protected prod-secrets path.

    Content-addressed: the same definition reproduces the same ``version``, which
    the bonus replay relies on.
    """
    return RuleSetPolicy.from_dict(
        {
            "id": "acme-prod-guard/v1",
            "rules": [
                {
                    "id": "BLOCK_PROD_SECRETS_WRITE",
                    "effect": "deny",
                    "tools": ["payments.file.write"],
                    "path_prefix": PROTECTED_PREFIX,
                    "reason": (
                        "writes into secrets/prod/** are forbidden for agents "
                        "(no actor is allow-listed)"
                    ),
                }
            ],
        }
    )


def _issue(
    store: TenantPolicyStore,
    audit: ChainHashAuditStore,
    *,
    action: str,
    args: dict[str, Any],
    request_id: str,
    signer: Ed25519Signer,
) -> DecisionReceipt:
    """Issue a SIGNED Decision Receipt for a proposed action (production profile)."""
    return evaluate_tenant_action(
        store=store,
        tenant_id=TENANT,
        requester_tenant_id=TENANT,
        action=action,
        args=args,
        execution_boundary=BOUNDARY,
        request_id=request_id,
        actor=CALLER_IDENTITY,
        validator=VALIDATOR,
        authority=AUTHORITY,
        audit_store=audit,
        signer=signer,
    )


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="gove-zone-undeniable-"))
    gateway_root = workdir / "gateway-fs"
    gateway_root.mkdir(parents=True, exist_ok=True)

    print("gove-zone — the undeniable evidence path")
    print("Invariant: No valid Decision Receipt, no side effect.")
    print(f"(workdir: {workdir})")

    # --- Production profile (the secure default) -----------------------------
    # Generate an Ed25519 keypair IN-PROCESS: the private key signs receipts at
    # issuance; the gate verifies with the PUBLIC key only. We LEAD with the
    # production profile (require_signature=True) to reflect the default posture.
    # (dev mode — GovernanceProfile.dev(), require_signature=False — is the
    # explicit unsigned opt-out and is intentionally NOT used here.)
    signing_key = Ed25519Signer.generate()
    verify_key = Ed25519Signer.from_public_bytes(signing_key.public_bytes())
    profile = GovernanceProfile.production(signer=signing_key, verifier=verify_key)
    if not profile.is_production or not profile.require_signature:
        _fail("expected the production profile to require signatures by default")
    gate_kwargs = profile.as_gate_kwargs()  # {"require_signature": True, "verifier": verify_key}
    print(
        f"profile: {profile.name}  require_signature={profile.require_signature}  "
        f"signing_key_id={signing_key.key_id}"
    )

    store = TenantPolicyStore(workdir / "policies")
    store.store_bundle(TENANT, _build_policy())
    audit = ChainHashAuditStore(workdir / "audit.jsonl")

    # An ALLOWED companion action gives the chain a second event and proves the
    # gate is not simply blocking everything (hard rule 3: show BOTH paths).
    _step("[0] ALLOWED companion — a permitted write executes for real")
    allow_args = {"path": "reports/summary.txt", "content": "quarterly numbers"}
    allow_receipt = _issue(
        store,
        audit,
        action="payments.file.write",
        args=allow_args,
        request_id="req-allow",
        signer=signing_key,
    )
    if allow_receipt.decision != Decision.ALLOW.value:
        _fail(f"expected ALLOW for a non-protected path, got {allow_receipt.decision!r}")
    allow_gateway = PrivilegedToolGateway(gateway_root)
    result = execute_with_receipt(
        tool_fn=allow_gateway.invoke,
        args=allow_args,
        receipt=allow_receipt,
        expected_tenant_id=TENANT,
        expected_execution_boundary=BOUNDARY,
        expected_action="payments.file.write",
        expected_actor=CALLER_IDENTITY,
        **gate_kwargs,
    )
    if not allow_gateway.ran or not (gateway_root / "reports/summary.txt").exists():
        _fail("a valid signed ALLOW receipt did not reach execution")
    _ok(f"allowed write executed: {result!r}")

    # =========================================================================
    # [1] DENIED — a privileged tool call is denied by policy; NO side effect.
    # =========================================================================
    _step("[1] DENIED — privileged write into secrets/prod/** is blocked")
    denied_args = {
        "path": f"{PROTECTED_PREFIX}/stripe_key.txt",
        "content": "sk_live_exfiltrated",
    }
    denied_receipt = _issue(
        store,
        audit,
        action="payments.file.write",
        args=denied_args,
        request_id="req-deny",
        signer=signing_key,
    )
    if denied_receipt.decision != Decision.DENY.value:
        _fail(f"expected DENY for a protected-path write, got {denied_receipt.decision!r}")
    deny_gateway = PrivilegedToolGateway(gateway_root)
    try:
        execute_with_receipt(
            tool_fn=deny_gateway.invoke,
            args=denied_args,
            receipt=denied_receipt,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action="payments.file.write",
            expected_actor=CALLER_IDENTITY,
            **gate_kwargs,
        )
        _fail("denied receipt reached execution")
    except ReceiptValidationError as exc:
        if deny_gateway.ran:
            _fail("side effect RAN despite a DENY decision")
        if (gateway_root / denied_args["path"]).exists():
            _fail("the protected file was written despite a DENY decision")
        _ok(f"blocked at the gate: {exc}")
        _ok("asserted: gateway.invoke never ran; no file written on disk")

    # =========================================================================
    # [2] RECEIPT — the signed DecisionReceipt for that denial.
    # =========================================================================
    _step("[2] RECEIPT — the signed Decision Receipt that records the denial")
    if denied_receipt.signature_algorithm != "ed25519":
        _fail(f"expected an ed25519-signed receipt, got {denied_receipt.signature_algorithm!r}")
    if denied_receipt.signature in ("", "unsigned_local"):
        _fail("denial receipt is not actually signed")
    # The receipt_hash must be the canonical hash of the receipt body.
    if denied_receipt.receipt_hash != denied_receipt.compute_hash():
        _fail("denial receipt_hash does not match its canonical body")
    print(f"  receipt_id           = {denied_receipt.receipt_id}")
    print(f"  decision             = {denied_receipt.decision}")
    print(f"  matched_rules        = {denied_receipt.matched_rules}")
    print(f"  signature_algorithm  = {denied_receipt.signature_algorithm}")
    print(f"  signing_key_id       = {denied_receipt.signing_key_id}")
    print(f"  receipt_hash         = {denied_receipt.receipt_hash}")
    print(f"  signature[:32]       = {denied_receipt.signature[:32]}…")
    _ok("signed denial receipt is well-formed (hash matches body, ed25519 signature present)")

    # =========================================================================
    # [3] EVIDENCE BUNDLE — portable bundle of receipts + audit chain.
    # =========================================================================
    _step("[3] EVIDENCE BUNDLE — portable receipts + append-only audit chain")
    # Hand-assemble the bundle in our tempdir. (The `gove-zone proofpack` CLI
    # writes to a hard-coded relative dir, runs its OWN unsigned scenario, and
    # cannot contain THIS demo's signed denial — so we serialize our own bundle,
    # using proofpack's folder layout only as a structural reference.)
    bundle = workdir / "evidence-bundle"
    receipts_dir = bundle / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    (receipts_dir / "allow_receipt.json").write_text(allow_receipt.to_json(), encoding="utf-8")
    (receipts_dir / "denied_receipt.json").write_text(denied_receipt.to_json(), encoding="utf-8")
    # Copy the append-only audit chain verbatim into the bundle.
    bundle_audit_path = bundle / "audit.jsonl"
    bundle_audit_path.write_text(audit.path.read_text(encoding="utf-8"), encoding="utf-8")
    # A verification.json snapshot of the chain at bundle time.
    chain_at_bundle = audit.verify_chain()
    (bundle / "verification.json").write_text(
        json.dumps(chain_at_bundle, indent=2, sort_keys=True), encoding="utf-8"
    )
    manifest = {
        "version": __version__,
        "tenant_id": TENANT,
        "execution_boundary": BOUNDARY,
        "profile": profile.name,
        "signing_key_id": signing_key.key_id,
        "files": [
            "manifest.json",
            "receipts/allow_receipt.json",
            "receipts/denied_receipt.json",
            "audit.jsonl",
            "verification.json",
        ],
    }
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    listing = sorted(p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if p.is_file())
    print(f"  bundle path = {bundle}")
    print("  contents:")
    for rel in listing:
        size = (bundle / rel).stat().st_size
        print(f"    {rel:<32} {size:>6} bytes")
    if "audit.jsonl" not in listing or "receipts/denied_receipt.json" not in listing:
        _fail("evidence bundle is missing required artifacts")
    _ok(f"assembled portable bundle with {len(listing)} files")

    # =========================================================================
    # [4] AUDIT REPLAY — verify the bundle OFFLINE (fresh store, no live state).
    # =========================================================================
    _step("[4] AUDIT REPLAY — verify the bundle's hash chain offline")
    # Construct a FRESH ChainHashAuditStore over the bundle's COPIED audit.jsonl
    # to prove verification needs nothing but the portable bundle itself.
    offline_store = ChainHashAuditStore(bundle_audit_path)
    chain = offline_store.verify_chain()
    print(f"  valid   = {chain['valid']}")
    print(f"  checked = {chain['checked']} events")
    print(f"  failures = {chain['failures']}")
    if not chain["valid"]:
        _fail(f"offline chain verification failed: {chain['failures']}")
    if chain["checked"] < 2:
        _fail(f"expected at least 2 chained events (allow + deny), got {chain['checked']}")
    _ok(f"offline verification: valid=True, checked={chain['checked']}, zero failures")

    # =========================================================================
    # [5] TAMPER ATTEMPTS FAIL — chain mutation AND forged-receipt both rejected.
    # =========================================================================
    _step("[5] TAMPER ATTEMPTS FAIL — chain mutation and signature forgery both rejected")

    # 5a. Mutate one event in the bundle's audit.jsonl — the DENIAL itself, the
    # strongest narrative for a demo named "undeniable": an attacker tries to
    # rewrite the recorded denial into an approval in the permanent record.
    # Re-verify → must FAIL with a hash-chain mismatch. We rewrite the line as
    # valid JSON (so the failure is a *hash* mismatch, not a JSON parse error).
    tampered_bundle_audit = bundle / "audit.tampered.jsonl"
    lines = bundle_audit_path.read_text(encoding="utf-8").splitlines()
    # Locate the recorded DENY event (the second/last event in the chain).
    deny_idx = next(
        i for i in range(len(lines) - 1, -1, -1) if json.loads(lines[i]).get("decision") == "deny"
    )
    deny_event = json.loads(lines[deny_idx])
    deny_event["decision"] = "allow"
    deny_event["reason"] = "TAMPERED: denial silently rewritten into an approval"
    lines[deny_idx] = json.dumps(
        deny_event, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    tampered_bundle_audit.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tampered_chain = ChainHashAuditStore(tampered_bundle_audit).verify_chain()
    print(f"  [5a] chain after mutation: valid={tampered_chain['valid']}")
    for f in tampered_chain["failures"]:
        print(f"       failure: type={f['type']} event_id={f.get('event_id')}")
    if tampered_chain["valid"]:
        _fail("a mutated audit chain still verified as valid")
    tamper_types = {f["type"] for f in tampered_chain["failures"]}
    if not tamper_types & {"event_hash_mismatch", "previous_hash_mismatch"}:
        _fail(f"expected a hash-chain mismatch, got failures: {tampered_chain['failures']}")
    _ok(f"mutated chain rejected: failure types = {sorted(tamper_types)}")

    # 5b. Forge a receipt WITHOUT the private key: flip the recorded DENY into an
    # ALLOW and recompute a self-consistent receipt_hash (the classic
    # recomputed-receipt attack). The signature still attests the ORIGINAL hash,
    # so the gate's signature check (receipt.py check 2a — which runs BEFORE the
    # decision check) rejects it. Forging DENY→ALLOW (not leaving it DENY) is
    # what isolates the *signature* failure as the cause.
    forged = dataclasses.replace(denied_receipt, decision=Decision.ALLOW.value)
    forged = dataclasses.replace(forged, receipt_hash=forged.compute_hash())
    # Sanity: the recomputed hash IS internally consistent (the old residual)…
    if forged.receipt_hash != forged.compute_hash():
        _fail("forged receipt_hash is not self-consistent — test setup is wrong")
    # …yet it must still be rejected because the signature cannot be reproduced.
    forge_gateway = PrivilegedToolGateway(gateway_root)
    try:
        execute_with_receipt(
            tool_fn=forge_gateway.invoke,
            args=denied_args,
            receipt=forged,
            expected_tenant_id=TENANT,
            expected_execution_boundary=BOUNDARY,
            expected_action="payments.file.write",
            expected_actor=CALLER_IDENTITY,
            **gate_kwargs,
        )
        _fail("forged DENY→ALLOW receipt reached execution")
    except ReceiptValidationError as exc:
        if forge_gateway.ran:
            _fail("side effect ran despite a forged receipt")
        if "invalid signature" not in str(exc):
            _fail(f"forged receipt rejected for the WRONG reason (expected signature): {exc}")
        print(f"  [5b] forged receipt rejected: {exc}")
        _ok("signature forgery rejected — no private key, no valid signature")

    # =========================================================================
    # BONUS — true re-decision replay against the RETAINED args.
    # =========================================================================
    _step("Bonus: true re-decision replay (retained args reproduce the verdict)")
    # A self-contained demo still holds the original args, so we can re-run the
    # SAME content-addressed policy against them and show the DENY reproduces.
    # Rebuild the ToolCall exactly as evaluate_tenant_action did internally.
    replay_policy = _build_policy()
    denied_call = ToolCall(
        name="payments.file.write",
        args=denied_args,
        goal="",
        actor=CALLER_IDENTITY,
        path=normalize_path_context(denied_args.get("path") or denied_args.get("file_path") or ()),
        state={},
    )
    replay_result = replay_call(
        denied_call,
        expected_decision=Decision.DENY,
        policy=replay_policy,
        # Cross-check the freshly-built policy against the version RECORDED on the
        # original receipt at decision time — not replay_policy.version against
        # itself, which would be tautological. This proves the rebuilt policy is
        # genuinely the same content-addressed bundle that issued the denial.
        expected_policy_version=denied_receipt.policy_version,
    )
    print(f"  replayed_decision    = {replay_result.replayed_decision.value}")
    print(f"  matches original     = {replay_result.matches}")
    print(f"  policy_version_match = {replay_result.policy_version_match}")
    print(f"  argument_hash_match  = {replay_result.argument_hash_match}")
    if not replay_result.matches or replay_result.replayed_decision is not Decision.DENY:
        _fail("re-running the policy against the retained args did not reproduce DENY")
    _ok("retained-args replay reproduced the DENY verdict under the same policy version")
    print(
        "  note: a COLD audit event alone cannot re-derive the decision — events store\n"
        "        only argument_hash, not raw args. True cold re-derivation needs the opt-in\n"
        '        raw-args side-store (see README "Replay (what it actually verifies)").'
    )

    print("\n\033[1;32m=== ALL 5 STEPS PROVEN — undeniable evidence path holds ===\033[0m")
    print("  [1] denied (no side effect)  [2] signed receipt  [3] evidence bundle")
    print("  [4] offline audit replay valid  [5] chain + signature tampering both rejected")
    print(f"\n(evidence bundle retained at: {bundle})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
