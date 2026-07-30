# gove-zone FAQ

Short, citable answers about ACGS. Every answer traces to
[`CLAIMS.md`](CLAIMS.md) (claim-to-evidence ledger and safe wording) and
[`COMPARISON.md`](COMPARISON.md). Current `gove-zone` source metadata is
`1.0.0rc1` with a Beta classifier; tag, PyPI publication, production, and
certification status are separate claims.

## What is a Decision Receipt?

A Decision Receipt is a vendor-neutral evidence artifact that records one
authorization decision: it binds the actor, the action, the exact arguments, the
tenant, and the policy bundle/hash that the executor checks before a side effect
runs. It is issued **before** execution, is self-contained, is hash-bound, and can
optionally be Ed25519-signed. Because the format carries no vendor-specific shape,
a relying party can verify a receipt on its own. *(Source: CLAIMS.md —
"Decision Receipt is a vendor-neutral evidence format", "Actor/action/argument
binding exists", "Tenant and policy binding exist".)*

## What is gove-zone's core invariant?

**No valid Decision Receipt, no side effect.** The governed executor fails closed
without a valid receipt — denied, missing, or tampered receipts are blocked before
anything runs, and denied actions are still audited. This holds for paths wired
through the governed executor. *(Source: CLAIMS.md — "No valid Decision Receipt, no
side effect", "Missing receipt is blocked", "Tampered receipt is blocked",
"Denied action leaves evidence and does not run".)*

## How is gove-zone different from an audit log?

An audit log records what happened, **after** it happened. gove-zone requires
policy and receipt evidence **before** execution, fails closed without it, and
records denials too — it gates and audits, rather than only observing. Its own
audit evidence is a tamper-evident hash chain on top of that gate. *(Source:
COMPARISON.md §"Audit logs"; CLAIMS.md — "Audit evidence is tamper-evident".)*

## How is gove-zone different from Microsoft Agent Governance Toolkit (AGT)?

AGT is the structurally nearest comparison and a fair one: open-source (MIT),
framework-agnostic across 15+ runtimes, explicitly fail-closed, with a SHA-256
Merkle-chained audit log and external inclusion proofs — strong engineering and
broader named-framework coverage than this project today. The evidenced difference
is **receipt-centric vs audit-centric**: per AGT's own audit-and-compliance docs,
its chain is built for forensics and compliance reporting after the fact, and it
has no first-class **decision receipt** — no pre-execution, sealed, self-contained
artifact, signed before the side effect fires, that a relying party outside the
enforcement runtime can independently verify, and no lifecycle for that artifact
such as hash-bound expiry or static receipt-signing-key-ID revocation. gove-zone's
current revocation control is operator-supplied, static, off by default, and
key-scoped—not per-receipt revocation. This is a contrast by evidence, not a knock
— AGT and a receipt gate could even compose.
*(Source: COMPARISON.md:61–77.)*

## Does gove-zone replace my agent framework, sandbox, or IAM?

No. gove-zone is the **execution legitimacy** layer, not the whole safety stack. It
complements — it does not replace — agent frameworks, MCP, content guardrails,
sandboxing, and IAM/RBAC. A production-adjacent stack combines them: IAM
authenticates the caller, gove-zone authorizes the exact side effect via a receipt,
a sandbox contains execution, guardrails moderate content, and SIEM/WORM retains
audit. *(Source: COMPARISON.md §"What to combine"; CLAIMS.md — "ACGS replaces
sandboxing/content moderation" rows: "not claimed".)*

## Is gove-zone production-ready?

No. The checked-in `1.0.0rc1` / Beta metadata is not production evidence, and
the candidate history still requires release reconciliation. gove-zone is
explicitly **not** production-certified, **not** compliance-certified, and
**not** regulator-approved. The local proofs (proof pack, tamper-evident audit
chain, test suite) are real engineering evidence, but they are not production
deployment proof. For the authoritative non-claims and safe public wording, see
[`CLAIMS.md`](CLAIMS.md). *(Source: CLAIMS.md — "ACGS is production-certified /
compliance-certified / regulator-approved" rows: all "not claimed".)*

## Is signing on by default?

Signing is not automatic: receipt issuance is unsigned unless the caller
supplies a signer. Separately, trusted signature verification is required by
default at the governed executor boundary; it does not auto-generate or trust a
key, and missing configuration fails closed. Unsigned development mode requires
an explicit opt-out through `require_signature=False` or
`GovernanceProfile.dev`. Ed25519 signing/verification and an operator-supplied
static signing-key `RevocationList` are implemented, but the project does not
provide PKI, key custody, automatic distribution/rotation, or global
receipt/nonce revocation. *(Source: package `SECURITY.md`; receipt signing,
revocation, and profile tests.)*

## How do I reproduce the proof?

From the repository root, using Bash on Linux/macOS (or WSL/Git Bash on
Windows):

```bash
tmp=$(mktemp -d) && uv run --package gove-zone gove-zone smoke --audit "$tmp/acgs-gove-zone-smoke-audit.jsonl"
uv run --extra crypto --package gove-zone gove-zone proofpack    # → {"status":"pass", ...}
uv run --package gove-zone python examples/tamper_demo/demo.py
```

The proof pack writes receipts, the audit chain, a verification result, and a
limitations note — local conformance evidence you can attach as release evidence.
*(Source: CLAIMS.md — "Proof pack generation exists".)*

## Where do I read more?

- [`CLAIMS.md`](CLAIMS.md) — claim-to-evidence ledger and safe wording.
- [`COMPARISON.md`](COMPARISON.md) — honest comparison with MCP, frameworks, guardrails, sandboxing, IAM, audit logs, policy engines, and Microsoft AGT.
- [`COMPARISON-ONEPAGER.md`](COMPARISON-ONEPAGER.md) — one-screen battlecard.
- [`SECURITY_MODEL.md`](SECURITY_MODEL.md) — threat model and current protections.
- [`DECISION_RECEIPT_SPEC.md`](DECISION_RECEIPT_SPEC.md) — public receipt contract.
