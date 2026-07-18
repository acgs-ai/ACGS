# Open-core and local-safety boundary

**Status:** Phase-0 target beta contract (G007).

**Not an implementation claim:** This contract neither changes a license nor
creates a paid module, price, entitlement, customer commitment, or legal term.

## Current-state boundary

The G006 survey supports local receipt/executor, audit, and proof primitives
with documented configuration limits. It does not establish a managed evidence
service, independent witness, billing ledger, live entitlements, or a
production deployment. Existing licensing and repository notices remain
unchanged.

## Target beta contract

### Permanently open safety surface

The Community local runtime must retain, without a hosted entitlement or
network dependency:

- local policy evaluation and receipt-gated executor enforcement;
- signing and trusted local verification;
- anti-replay/single-use support, local audit/replay, and proof-pack export;
- CLI and conformance tests; and
- configuration and examples needed to prove `DENY`/invalid artifacts execute
  zero side effects within the documented trust boundary.

No plan, entitlement, billing failure, account suspension, hosted outage, or
retention limit may disable the local gate, remove signature verification,
weaken replay protection, or authorize a side effect that the local policy and
executor would otherwise reject.

### Managed value boundary

Future paid value may cover hosted evidence retention, fleet/policy/approval
operations, collaboration, alerts, integration support, private deployment
guidance, customer-controlled storage/key options, and support obligations.
It must not turn the hosted plane into a mandatory remote authorization call in
the side-effect hot path. Hosted availability may limit hosted functionality;
it cannot create allow-by-default behavior locally.

### Commercial and licensing authority

Any separable commercial module, open-core boundary, provider contract, price,
or license decision requires the proposed G008 commercial-boundary ADR plus
explicit owner and counsel review. Apache-2.0 core assets are not retroactively
reclassified as paid-only by this document. No live charge or legal promise is
authorized here.

## Evidence and next gate

G008 records the owner-gated ADR. G203/G206/G301/G501-G503 must prove degraded
mode, entitlement behavior, managed evidence, usage, and billing semantics. The
sole roadmap of record is [ROADMAP.md](../ROADMAP.md); the current gap inventory
is [CURRENT_STATE_SURVEY.md](CURRENT_STATE_SURVEY.md).
