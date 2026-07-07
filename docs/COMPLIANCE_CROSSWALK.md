# Governance Framework Crosswalk

> **What this is.** A mapping from gove-zone's *enforced runtime controls* to the
> governance/security frameworks buyers and auditors already use: **NIST AI RMF
> 1.0**, **NIST CSF 2.0**, **MITRE ATLAS**, and the **OWASP LLM / Agentic AI**
> risk lists.
>
> **What this is NOT.** This is a self-assessment mapping, not a certification,
> attestation, or audit result. gove-zone is **alpha / local-proof** software
> (see `docs/SECURITY_MODEL.md`). Mapping a control to a framework outcome means
> "the receipt membrane produces *evidence toward* that outcome at the executor
> boundary" — it does **not** mean adopting gove-zone makes a system compliant.
> Compliance is a property of an organization and its full control set; gove-zone
> is one layer (the execution-legitimacy membrane), not the whole stack.

The pattern is borrowed from the wider agent-skills ecosystem (e.g. the
Anthropic-Cybersecurity-Skills `mappings/` convention of crosswalking controls to
MITRE ATT&CK / NIST CSF / OWASP). Here it is applied to gove-zone's own enforced
controls.

## Core invariant being mapped

**No valid Decision Receipt, no side effect.** A registered tool executes only
when a receipt passes the full executor gate: it exists; was issued for *this*
caller (actor anchor); is hash-intact (and signature-valid when it claims a
signature); is ALLOW/TRANSFORM (not DENY/ESCALATE/expired); and its tenant,
boundary, action, *exact arguments*, policy hash + bundle, and audit-event hash
all match what the executor is about to do — minted by a validator distinct from
the proposer. Any failure raises `ReceiptValidationError` **before** the tool
runs. Independently, the kernel guarantees policy-runs-before-effect and
fail-closes (synthesized DENY / `AuditError`) on policy or audit failure.

Evidence: `packages/gove-zone/src/gove_zone/{receipt,executor,kernel,audit,policy,signing,consumption}.py`.

## Control inventory (anchor for the mappings below)

| Control | What it enforces at runtime | Evidence | Default |
|---|---|---|---|
| RECEIPT-REQUIRED | No receipt → no execution | `executor.py` | on |
| ACTOR-ANCHOR | Gate caller identity must equal `receipt.actor`; validator ≠ caller (no self-authorization) | `receipt.py` | on |
| HASH-INTEGRITY | Recompute `receipt_hash`; any field edit (incl. sig/algo/key) rejected — anti-downgrade | `receipt.py` | on |
| SIG-VERIFY | If a receipt claims a signature, it MUST verify (Ed25519); unknown key / bad sig / algo-mismatch rejected | `receipt.py`, `signing.py` | on when claimed |
| DECISION-GATE | DENY / ESCALATE / unknown decision cannot authorize execution | `receipt.py` | on |
| ARG-BIND | Executed args must hash to `argument_hash` (ALLOW) or equal approved transformed set (TRANSFORM) | `receipt.py` | on |
| POLICY/TENANT/BOUNDARY/ACTION/AUDIT-BIND | Each must match expected — blocks bundle / tenant / action / audit-event substitution | `receipt.py`, `tenant.py` | on |
| MACI-VALIDATOR-SEP | Proposer ≠ validator at issuance and at the gate (approval-chain consistency) | `receipt.py`, `tenant.py` | on |
| POLICY-BEFORE-EXEC | Policy evaluated and appended to audit before any tool runs | `kernel.py` | on |
| FAILCLOSED-POLICY/AUDIT | Policy exception/timeout → synthesized DENY; audit append failure → `AuditError` (never silent allow) | `kernel.py` | on |
| AUDIT-HASHCHAIN | Append-only JSONL, `previous_hash`→`event_hash`, `flock`+fsync, `verify_chain()` re-walk | `audit.py` | on |
| EXPIRY | `expires_at` enforced when set; unparseable/mixed-awareness → reject | `receipt.py` | opt-in field |
| SIG-REQUIRED | `require_signature=True` rejects *unsigned* receipts (closes the recomputable-hash gap) | `executor.py`, `signing.py` | on (secure-profile default; fails closed without a configured trusted verifier — unsigned dev mode is an explicit opt-out) |
| ANTI-REPLAY | Single-use receipts via persistent consumption ledger keyed on `audit_event_hash` | `consumption.py` | opt-in |
| REPLAY-VERIFY | Re-derive decision by re-running policy; side-store args cross-checked against chain `argument_hash` | `replay.py`, `replay_store.py` | opt-in (side-store) |

## NIST AI RMF 1.0

| AI RMF function / subcategory (intent) | gove-zone contribution | Controls |
|---|---|---|
| **GOVERN 1** — policies & procedures to manage AI risk | Policy bundles are bound by id+hash into every decision; substitution is rejected | POLICY/TENANT/BOUNDARY/ACTION/AUDIT-BIND, POLICY-BEFORE-EXEC |
| **GOVERN 1.5 / 4.1** — accountability, transparency, documentation | Every governed side effect emits a tamper-evident Decision Receipt bound to actor/action/args/policy/authority/audit | RECEIPT-REQUIRED, AUDIT-HASHCHAIN |
| **GOVERN 2** — accountability roles & separation of duties | Proposer/validator separation enforced at issuance and at the gate | MACI-VALIDATOR-SEP, ACTOR-ANCHOR |
| **MAP 1 / 5** — context & risk framing per action | Decisions categorized ALLOW / DENY / ESCALATE / TRANSFORM with bound arguments | DECISION-GATE, ARG-BIND |
| **MEASURE 2** — evaluate trustworthy characteristics; **MEASURE 4** — track over time | Deterministic replay re-derives the decision from recorded policy + args; hash chain verifies integrity | REPLAY-VERIFY, AUDIT-HASHCHAIN |
| **MANAGE 2** — risk treatment & fail-safe; **MANAGE 4** — monitor & respond | Fail-closed on policy/audit failure; DENY/ESCALATE are not executable; expired/replayed receipts blocked | FAILCLOSED-*, DECISION-GATE, EXPIRY, ANTI-REPLAY |

## NIST CSF 2.0

| CSF function | gove-zone contribution | Controls |
|---|---|---|
| **GOVERN (GV)** | Policy-bound decisions; separation of duties | POLICY/TENANT/BOUNDARY/ACTION/AUDIT-BIND, MACI-VALIDATOR-SEP |
| **IDENTIFY (ID)** | Every action carries a bound actor, tenant, and execution boundary | ACTOR-ANCHOR, POLICY/TENANT/BOUNDARY/ACTION/AUDIT-BIND |
| **PROTECT (PR.AC / PR.DS)** | Access mediated by receipt; argument & policy integrity protected by hash; tenant isolation; optional Ed25519 signing | RECEIPT-REQUIRED, ARG-BIND, SIG-VERIFY, SIG-REQUIRED |
| **DETECT (DE.CM / DE.AE)** | Append-only hash chain makes tampering detectable; replay surfaces decision drift | AUDIT-HASHCHAIN, REPLAY-VERIFY |
| **RESPOND (RS)** | Fail-closed synthesis of DENY; ESCALATE routes to human authority | FAILCLOSED-POLICY, DECISION-GATE |
| **RECOVER (RC)** | Decisions are reconstructable from the audit chain (+ side-store for full args) | REPLAY-VERIFY |

## MITRE ATLAS (honest, partial)

ATLAS catalogs the adversarial-ML attack lifecycle. gove-zone is **not** a
model-defense or data-poisoning control — it governs the **action / side-effect**
stage. It therefore acts as a *mitigation* on the techniques where a manipulated
model tries to convert reasoning into a real-world effect, and offers **no
coverage** for the model-manipulation stages.

| ATLAS technique (action stage) | gove-zone as mitigation |
|---|---|
| LLM Prompt Injection → unauthorized action (`AML.T0051`) | Injection may corrupt the *request*, but the executor still requires a valid receipt binding actor+action+exact args+policy; substituted/dangerous args fail ARG-BIND |
| LLM Plugin / Tool compromise & abuse (`AML.T0053`, agentic tool-use) | A compromised tool call cannot execute without a matching ALLOW receipt; DENY/ESCALATE are non-executable |
| Exfiltration / impact via agent execution | Side effects are gated, bound, and audited; fail-closed on policy/audit failure |
| **Model evasion, data/model poisoning, model theft (`AML.T0043/0020/0044`, …)** | **Out of scope** — gove-zone does not inspect or defend the model itself |

## OWASP LLM & Agentic AI risks (strongest fit)

| OWASP risk | gove-zone contribution |
|---|---|
| **LLM06/LLM08 Excessive Agency** | The central mitigation: an agent's *intended* action only becomes a *real* action through a validator-issued, argument-bound receipt; authority is explicit and least-privilege per decision |
| **Insecure Plugin/Tool Design; Improper Output Handling → action** | Executor boundary re-checks the concrete tool + args against the receipt regardless of upstream framework | 
| **Agentic: tool misuse, privilege compromise, cascading actions** | Per-action gating, tenant/boundary binding, fail-closed defaults, ESCALATE-to-human, append-only audit |
| **Agentic: memory/replay abuse** | Opt-in single-use consumption ledger + expiry bound the reuse window |

## Limitations — do not overstate (read before citing this doc)

These are load-bearing. A crosswalk row means "contributes evidence," bounded by:

1. **Signing default is fail-closed, not auto-sign.** `require_signature=True`
   is the default; a gate with no configured trusted verifier fails closed
   (raises) rather than emitting an unsigned receipt. In the explicit unsigned
   dev mode (`require_signature=False`), verification checks only the
   recomputable SHA-256 `receipt_hash`, which is forgeable under host
   compromise — do not promote dev mode as production security.
   `docs/SECURITY_MODEL.md`, `docs/CLAIMS.md`.
2. **Anti-replay and full-argument replay are opt-in.** Stateless verification
   accepts a valid ALLOW receipt until `expires_at` unless the consumption ledger
   (`consumption.py`) and/or a `ReplaySideStore` are enabled.
3. **Executor-bypass is possible.** Controls bind only to calls routed through
   `GovernedExecutor` / `execute_with_receipt` / kernel `dispatch`. A raw tool
   call the integrator exposes bypasses the membrane entirely — handler wiring is
   integrator-owned.
4. **Identity is opaque strings, not IAM/PKI.** Actor authentication, key
   custody/distribution, and **revocation** are operator responsibilities; the
   verifier map is static with no cert chain.
5. **Audit is local JSONL, tamper-*evident*, not tamper-*proof*.** Off-host /
   WORM durability is an operator concern.
6. **No policy lifecycle/revocation registry** beyond id+hash binding.
7. **Not certified.** Not production-certified, not compliance-certified, not
   regulator-approved; complements (does not replace) sandboxing, content
   moderation, IAM/RBAC/PKI, and is not full formal verification.
   `docs/CLAIMS.md` rows 27–33.

## Scope boundary (one sentence)

gove-zone is the *execution-legitimacy layer* — it binds actor + action +
arguments + policy + validator + authority + audit into one verifiable decision
at the executor boundary — and is explicitly **not** the whole safety stack the
frameworks above describe.

## Sources

- Control evidence: `packages/gove-zone/src/gove_zone/*.py`; `docs/SECURITY_MODEL.md`; `docs/CLAIMS.md`; `docs/DECISION_RECEIPT_SPEC.md`; `docs/COMPARISON.md`.
- Frameworks: NIST AI RMF 1.0 (GOVERN/MAP/MEASURE/MANAGE); NIST CSF 2.0 (GV/ID/PR/DE/RS/RC); MITRE ATLAS; OWASP Top 10 for LLM Applications & OWASP Agentic AI threats.
- Crosswalk-as-`mappings/` pattern: github.com/mukul975/Anthropic-Cybersecurity-Skills.
