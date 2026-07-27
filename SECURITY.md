# Security Policy

ACGS is receipt-gated runtime governance for AI-agent side effects.
Because the project's purpose is enforcement and auditability, we take
vulnerability reports seriously — especially any issue that could weaken
fail-closed behavior, bypass receipt validation, or forge/replay audit evidence.

> Scope note: this repository provides local engineering evidence. It is **not**
> production-certified, compliance-certified, or regulator-approved. See
> [`docs/CLAIMS.md`](docs/CLAIMS.md) and
> [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) for the evidence boundary
> and the documented threat model.

## Supported versions

The flagship enforcement kernel `gove-zone` is at `1.0.0rc1` (Beta). Security
fixes land on the latest `master` and the current release line only; there is no
long-term-support branch yet.

| Component | Version | Security fixes |
|---|---|---|
| `gove-zone` kernel | `1.0.0rc1` (Beta) | Latest `master` / current line |
| Other monorepo packages | independent lines | Latest `master` |
| Nested submodules (`acgs-lite`, `Acgs-Swarm`, `clinicalguard`, `ACGS-agency-agents`) | see each repo | Report to the respective repository |
| `external/*` references | third-party upstreams | Report upstream (see `external/README.md`) |

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Preferred: use GitHub's private vulnerability reporting —
**Security → Advisories → Report a vulnerability** on
`https://github.com/dislovelhl/ACGS`. This keeps the report private until a fix
is available.

Fallback: email **hello@acgs.ai** with subject `SECURITY: <short summary>`. Do
not include exploit code in the clear if the impact is severe; ask for a secure
channel first.

Please include, where possible:

- affected component/file and version or commit SHA;
- a minimal reproduction (the fail-closed invariant that is bypassed);
- impact (e.g. side effect executed without a valid receipt, audit chain
  forged, actor/tenant binding bypassed);
- any suggested remediation.

## What to expect

- We aim to acknowledge a report within a few business days. This is a
  best-effort target, not a contractual SLA.
- We will confirm the issue, determine affected versions, and prepare a fix.
- We practice coordinated disclosure: we ask that you give us reasonable time to
  ship a fix before public disclosure, and we will credit reporters who wish to
  be credited.

## Out of scope

- Findings that depend on a fully compromised issuer or execution host (the
  documented trust boundary — see `docs/SECURITY_MODEL.md`).
- Overclaiming in third-party `external/*` upstreams (report upstream).
- Missing production/compliance certification — the project does not claim it.
