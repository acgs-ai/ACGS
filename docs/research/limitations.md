# Known Limitations — ACGS / gove-zone

> **Core invariant: No valid Decision Receipt, no side effect.**

Status: **alpha.** ACGS is not production-certified, not compliance-certified, and
not regulator-approved. This document is the standing, public list of what the
system does *not* do yet, where its capability boundaries actually sit, and which
claims remain externally unvalidated.

It exists because the product's value rests on verifiability. A governance layer
that publishes only its strengths is asking to be trusted rather than checked,
which is the posture this project is built to replace. Capability claims are
tracked in [`docs/CLAIMS.md`](../CLAIMS.md); this file is its negative space.

Scope note: this is a technical-limitations document. Commercial position,
pricing, and go-to-market are deliberately out of scope and are not published.

## 1. Capability boundaries

**The kernel is Python-only.** Executor-boundary enforcement runs in-process, so
governing a Node, Go, or Rust agent stack requires either a language port or an
out-of-process hop. Neither exists today. The accurate form of the "sits below any
framework" claim is currently *below any Python framework*, plus adapter shapes and
the MCP gateway path for everything else. Treat cross-language coverage as a
protocol-level story (MCP), not a kernel-level one.

**The MCP gateway is alpha and assumes a trusted local transport.** It does not
implement an authenticated remote identity hop. Do not deploy it across a trust
boundary you would not already grant the caller. Current gaps are enumerated in
[`../strategy/mcp-gateway-gap-analysis.md`](../strategy/mcp-gateway-gap-analysis.md).

**Adapter coverage is tiered, not uniform.** Named-runtime adapters differ in depth;
a shipped adapter shape is not the same as a dispatcher-level wiring guarantee. A
passing unit test on a handler does not prove the handler is wired into the path
that receives real traffic — verify wiring per integration.

**Anti-replay is local.** Receipt consumption is tracked in a local store. That
gives single-instance replay protection; it does not give cross-instance or
distributed replay protection. A multi-process or multi-host deployment needs a
shared consumption store, which is not shipped.

**Fail-closed converts integrity risk into availability risk.** This is a deliberate
trade, not an oversight: if the gate cannot evaluate, the side effect does not
happen. Any deployment needs an error budget and a documented degraded-mode policy.
See [`../SECURITY_MODEL.md`](../SECURITY_MODEL.md).

**No managed service exists.** What ships is a self-hosted library, a CLI, and the
alpha MCP gateway. Hosted evidence retention, managed signing, and a tenant-admin
console are roadmap items, not offerings. Self-hosted deployment — on-premise,
private cloud, air-gapped — is the mature path and the only one available today.

## 2. Validation status

**No external auditor has yet reviewed a proof pack.** The offline verifier is
designed so that an auditor needs no trust in the operator, and the auditor-facing
packet exists ([`../strategy/auditor-validation/BRIEF.md`](../strategy/auditor-validation/BRIEF.md),
[`REVIEW-CHECKLIST.md`](../strategy/auditor-validation/REVIEW-CHECKLIST.md)) — but no
independent GRC or audit professional has walked it and published a finding. Until
that happens, "Decision Receipts are acceptable control evidence" is a design
argument, not an established one. This is the single most important open question
about the product, and it is open.

**No third party is known to be running the gate fail-closed in production.**
Every deployment-shaped claim in this repository derives from local tests, demos,
and the maintainer's own runs.

**Overhead is measured, but on one machine.** Per-governed-call latency numbers
are published in [`../strategy/overhead-benchmarks.md`](../strategy/overhead-benchmarks.md)
with the exact commands that produced them. They characterize order of magnitude
on a single local dev box. They are not a controlled-environment result, not an
SLA, and not a claim about your hardware.

**Multi-tenant isolation evidence is thin.** Tenant safety is covered by targeted
tests, not by an isolation audit. Do not treat the current test suite as sufficient
evidence for hostile multi-tenancy.

**Compliance crosswalks are self-assessment support, not certification.** Mapping a
control to a framework row is an argument that the control is relevant. It is not a
statement that any certifying body has agreed.

## 3. Structural costs

**The repository is a monorepo with nested repos.** `acgs-lite`, `Acgs-Swarm`, and
`clinicalguard` are independent repositories, and several evaluation and research
packages live alongside the kernel. This raises contributor onboarding cost relative
to a single crisp kernel repo, and it means a green parent-repo gate is not proof
that a nested package is green. Run the package-local gate.

**Published-vs-workspace Python floors differ deliberately.** `acgs-lite` publishes
with `requires-python = ">=3.10"`; the workspace floor is 3.11. That divergence is
intentional and load-bearing for PyPI consumers — not drift to be "fixed."

## 4. How this list is maintained

Items leave this document when the gap is closed *and* the closure is verifiable
from code, tests, or a published artifact — not when it is planned. Planned work
lives in [`../ROADMAP.md`](../ROADMAP.md).

If you find a limitation not listed here, that is a documentation bug worth filing;
an unlisted gap is more damaging to this project than a listed one.
