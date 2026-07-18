# gove-zone — one-screen battlecard

> **Core invariant: No valid Decision Receipt, no side effect.**
> Receipt-gated, not audit-centric. A layer that *complements* your stack — it does
> not replace it. Every line below traces to [`COMPARISON.md`](COMPARISON.md) and
> [`CLAIMS.md`](CLAIMS.md).

## The one distinction

Most agent tooling makes actions **possible**. gove-zone proves whether a specific
action is **legitimate** — before it runs. *(COMPARISON.md §"Core distinction".)*

## Receipt-gated vs audit-centric

| | Audit-centric tooling | gove-zone (receipt-gated) |
|---|---|---|
| When it acts | Records **after** the action | Decides **before** the side effect |
| Artifact | A log entry / chain, for forensics | A **Decision Receipt** — pre-execution, sealed, self-contained |
| Who can verify | The enforcement runtime that wrote the log | A relying party **outside** the runtime, independently |
| Default posture | Observe | **Fail closed** — no valid receipt, no side effect |

Source: CLAIMS.md ("Audit evidence is tamper-evident", "No valid Decision Receipt,
no side effect", "Decision Receipt is a vendor-neutral evidence format") and
COMPARISON.md §"Audit logs" / §"Microsoft agent governance".

## Complement, don't replace

A production-adjacent stack combines layers — gove-zone is the **execution
legitimacy** layer, not the whole safety stack. *(COMPARISON.md §"What to combine".)*

| Layer | gove-zone's relationship |
|---|---|
| IAM / RBAC | Authenticates principals; gove-zone proves a specific side-effect decision. Complement. |
| Sandboxing | Contains execution; gove-zone authorizes it before it begins. Complement. |
| Content guardrails | Moderate text/output; gove-zone enforces execution legitimacy. Complement. |
| MCP / agent frameworks | Connect and orchestrate tools; gove-zone governs whether a `tools/call` may execute. Complement. |
| Audit logs / SIEM / WORM | Observe and retain; gove-zone gates and audits before the fact. Complement. |

## vs Microsoft Agent Governance Toolkit (AGT)

AGT is the structurally nearest comparison and deserves a fair one: open-source
(MIT), framework-agnostic across 15+ runtimes, explicitly fail-closed, with a
SHA-256 Merkle-chained audit log and external inclusion proofs — strong
engineering, and broader named-framework coverage than this project today.

The evidenced difference is **receipt-centric vs audit-centric**. Per AGT's own
audit-and-compliance docs, its chain is built for forensics and compliance
reporting **after the fact**, and it has **no first-class decision receipt** — no
pre-execution, sealed, self-contained artifact, signed before the side effect
fires, that a relying party outside the enforcement runtime can independently
verify before accepting the action, and no lifecycle for that artifact such as
hash-bound expiry or static receipt-signing-key-ID revocation. gove-zone's
narrower bet is exactly that artifact: a Decision Receipt issued before execution
and verifiable on its own (hash-bound, optionally Ed25519-signed), vendor-neutral
by format — with cross-host reference validators still on the roadmap. Its
current revocation control is operator-supplied, static, off by default, and
key-scoped—not per-receipt revocation. **This is a contrast by evidence, not a
knock: AGT and a receipt gate could even compose.** *(COMPARISON.md:61–77.)*

## What we do not claim

Current source metadata is `1.0.0rc1` / Beta; candidate release reconciliation
is still required. **Not** production-certified, **not**
compliance-certified, **not** regulator-approved; not a replacement for
sandboxing, content moderation, or a complete IAM/PKI system. See
[`CLAIMS.md`](CLAIMS.md) for the full claim-to-evidence ledger and safe wording.
