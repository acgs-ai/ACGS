# gove-zone adversary suite

Honest, non-redundant adversary coverage over the **real** gove-zone gate
(`execute_with_receipt`) and the surrounding surfaces (adapters, kernel dispatch, policy
compilation, audit chain). This suite makes the threat taxonomy explicit and
machine-checked, and adds live reproducing tests for every open gap. It does **not**
re-prove defenses that existing package tests already cover with real exploits.

Prose companion: [`docs/security/threat-model-v2.md`](../../../../docs/security/threat-model-v2.md).

Run:

```bash
uv run --package gove-zone --extra crypto --extra dev \
  python -m pytest packages/gove-zone/tests/adversary --import-mode=importlib -q
```

## Coverage at a glance (10 classes)

| Adversary class | Status | Where it's proven / reproduced |
|---|---|---|
| forged-authorization | **PARTIAL** | strict standalone execution rejects unsigned/untrusted receipts; raw `ReceiptVerifier` unsigned default remains a legacy residual → `test_unsigned_forgery.py` |
| replayed-authorization | **DEFENDED** | workflow and strict standalone reuse are rejected before a second side effect → `test_standalone_receipt_replay.py` |
| ledger-tampering | **PARTIAL** | single-field edit detected (`test_audit_chain.py`); full self-consistent rewrite → `test_audit_full_chain_rewrite.py` |
| policy-downgrade | **PARTIAL** | strict standalone caller pins hash/bundle; legacy unpinned hash and bundle-id paths remain live residuals |
| policy-default-allow | **NOT-DEFENDED** | RuleSetPolicy allow-by-default → `test_ruleset_default_allow.py`; PQL empty-feed fail-open → `test_pql_silent_fail_open.py` |
| tenant-crossover | **DEFENDED** | `test_tenant_safety.py`, `test_executor_guard.py` (+ adversary tripwire `test_tenant_boundary_isolation.py`) |
| signature-stripping | **DEFENDED** | `test_receipt_signing.py` |
| validator-bypass | **PARTIAL** | strict standalone caller pins authority/validator identity; legacy callers may omit the additive authority pin → `test_authority_scope_unenforced.py` |
| evidence-omission | **DEFENDED** | `test_kernel_dispatch.py`, `test_executor_guard.py` |
| adapter-bypass | **DEFENDED** | default `ManagedAgent` installs `DenyAllPolicy`; the adapter's `Kernel.dispatch` path fails closed and the wrapped tool never runs → `test_adapter_bypass.py`. Residual: the adapter path has no receipt gate, so an explicit `AllowAllPolicy` opt-in stays adaptively BYPASSABLE |

The map itself is enforced by `test_coverage_manifest.py`: if a "covering" test is
renamed/deleted, or a PARTIAL/NOT-DEFENDED gap loses its tripwire, the manifest test fails.
Posture is pinned at **5 DEFENDED / 4 PARTIAL / 1 NOT-DEFENDED** — changing it must be a
deliberate edit to the manifest.

## Adaptive stability layer (NEW in cycle 7)

The adversary suite now evaluates a deterministic adaptive family per class via real
gates/surfaces (`execute_with_receipt`, `Kernel.dispatch`, `ChainHashAuditStore.verify_chain`,
policy adapters).

For each class, `adaptive_attack(class_name, budget=DEFAULT_BUDGET)` enumerates up to
`DEFAULT_BUDGET` (40) defense-aware variants (argument mutation, actor/tenant substitution,
signature handling, policy hash/bundle permutation, receipt-field perturbation,
decode/normalization edges, and — for evidence-omission — the `Kernel.dispatch` audit anchor:
stripped-audit and anchor-before-execute) and returns:

- `variants_tried` (how many variants were evaluated),
- `first_bypass` (first variant ID that passed),
- `stable` (`stable is True` only when no variant was admitted).

`test_adaptive_stability.py` compares `stable` to the manifest `"adaptive"` pin:
`STABLE` (must remain denied) versus `BYPASSABLE` (one or more variant bypasses). The
adaptive posture is pinned at **8 STABLE / 2 BYPASSABLE / 0 UNTESTED** in
`test_adaptive_posture_is_pinned`, mirroring the static `test_taxonomy_posture_is_pinned`.
The 8 STABLE classes are stable **by construction** — each rests on a total,
bound-and-checked invariant: forged authorization (trusted signature), replay
(durable single-use consumption), policy downgrade (pinned artifact identity), validator
bypass (pinned authority and validator), signature-stripping (reference-monitor totality),
tenant-crossover (least-privilege binding), evidence-omission (Biba integrity /
anchor-before-execute — probed on both the `execute_with_receipt` no-receipt axis and the
`Kernel.dispatch` audit anchor: a failed/stripped audit append fails closed, and the anchor
is recorded before the tool runs). The STABLE families are held strictly under
`DEFAULT_BUDGET` (`test_stable_class_families_fit_within_budget`) so a future variant that
reaches the budget fails loudly instead of truncating a full-family enumeration.

Honest-scope limits (must be stated verbatim):

- **No model, no AgentDojo, no GCG.** This is a deterministic config/input-space variant search
  over gove-zone's own gate — NOT the paper's model-in-the-loop adaptive evaluation. It cannot and
  does not claim robustness against an optimizing LLM attacker.
- **"Adaptively stable" ≠ "secure".** It means "no variant in a bounded, hand-enumerated family
  bypassed the gate," which is a stronger statement than single-template but far weaker than a
  proof. Wording stays at "no bounded variant in family F bypassed surface S."
- **Bypassable classes are already known gaps.** The adaptive layer does not discover new
  vulnerabilities so much as *quantify the decision boundary* of known ones (minimal bypass) and
  *pin* the stability of the defended ones. That framing must not be inflated into new CVEs.
- The paper's empirical result is one weak-model data point; we cite it as motivation for the
  methodology, never as evidence about gove-zone.

## Open gaps & residuals (tracked as live tests)

Highest-severity first (see threat-model-v2.md §11 for the full remediation order):

1. **Adapter path has no receipt gate (architectural residual).** `govern_autogen_tool` /
   `govern_langgraph_tools` route execution through `ManagedAgent.dispatch` → `Kernel.dispatch`
   (self-asserted actor, no receipt verification, no signature) rather than the cryptographic
   gate `execute_with_receipt`. The **default** posture is now DEFENDED: `ManagedAgent` defaults
   to `DenyAllPolicy`, so a default "governed" agent fails closed and the wrapped side effect
   never runs — proved by the integration negative-path test
   (`test_adapter_bypass.py::test_managed_agent_default_policy_blocks_untrusted_tool`). The
   critical residual is that the adapter path still verifies no receipt or signature, so an agent
   **explicitly** configured with a permissive policy (`AllowAllPolicy`) executes every wrapped
   tool unconditionally — an opt-in, not the default, which keeps this class adaptively
   BYPASSABLE (`adaptive.py::_gen_adapter_bypass`). Closing it means routing the adapters
   through `execute_with_receipt`.
2. **PQL/GPA silent fail-open (High).** An empty/malformed vendor feed compiles to a
   functional allow-all with no error.
3. **Audit full-chain rewrite (High).** The keyless chain has no external head anchor, so a
   self-consistent rewrite / truncation passes `verify_chain()`.
4. **Legacy authority pin omission (Medium).** The strict standalone path pins authority and
   validator identity, but additive pins remain optional for legacy direct callers.
5. **Gate default-posture inconsistency (Medium).** `ReceiptVerifier` defaults
   `require_signature=False` while `execute_with_receipt` defaults `True`.
6. **Unpinned legacy policy-bundle-id & RuleSetPolicy-as-sole-policy (Medium).**

Overclaiming a defense is a BLOCKER: a class is "DEFENDED" here only because a real exploit
test proves it, and every gap is stated plainly with a live reproducing test rather than
hidden. The gap tests assert current (weaker) reality, so the day a defense lands the
relevant test flips (xfail→xpass, or a KNOWN_GAP assertion starts failing) — a built-in
"defense arrived" signal.
