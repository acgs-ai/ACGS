# ADR 0008: `ManagedIdempotencyResult` Is the Single Idempotency Authority

## Status

Accepted (2026-07-28).

## Context

Three idempotency authorities exist across the repository and the open `beta/*`
draft stack. They were built by two lineages that raced to implement agent-create
idempotency; both landed, and the stack proposed a third.

| | A `TenantBootstrapIdempotency` | B `ManagedIdempotencyResult` | C `AgentRegistrationIdempotency` |
|---|---|---|---|
| status | live on master | live on master | never merged; stack only |
| migration | `0005_tenant_bootstrap` | `0011_managed_idempotency_results` | stack `0007` (collides) |
| scope key | `idempotency_key`, unique `org_id` | `(org, env, principal, canonical_action, key_digest)` | scoped agent-registration key |
| runtime owner | `tenant_bootstrap.py` | `idempotency.py` + `app.py` | `agent_registration.py` (stack) |
| action model | one route | generic `canonical_action` | one route |
| decision typing | none; stores the success response | `terminal_decision ∈ {allow,deny,escalate}` + CHECK | terminal response |
| receipt binding | none | FKs to `native_decision_receipts`, `governance_events`, `agents` | FK to `managed_decision_receipts` |
| signing | none | `result_artifact` + hash + algorithm + key id + signature | none |

A and B are disjoint tables owned by disjoint modules. No compatibility shim
exists in either direction — `tenant_bootstrap.py` has zero references to
`ManagedIdempotencyResult`, and the managed route has zero references to
`TenantBootstrapIdempotency`. The two authorities never meet.

### Evidence durability

B writes its refusal evidence *inside* the governing transaction:
`ManagedMutationUnitOfWork.record_non_executable_evidence`
(`managed_mutations.py:339-367`) opens one `with session.begin():` wrapping the
refusal mirror, the receipt projection, the governance event, and the outbox
enqueue. `_record_refusal_evidence` states the intent directly: *"a refusal that
never became final must leave no trace on the org's evidence surface."*

A writes its refusal evidence after the fact. `record_refusal`
(`tenant_bootstrap.py:926`) is reachable only via `_record_tenant_bootstrap_refusal`
(`app.py:290`), which is invoked only from Starlette exception handlers
(`app.py:495`, `542`, `580`) — after the route transaction has already unwound.
It dedupes on `request_id`, so it is idempotent *if* it runs, but nothing
guarantees it runs and nothing reconciles a miss. A crash or a failure inside the
refusal session leaves a request that was refused with no evidence row and no
signal that one is missing.

This is a completeness gap, not an atomicity violation: the ordering is strictly
post-rollback, never concurrent with it. An earlier draft of this analysis
asserted an atomicity violation; tracing the call sites disproved it.

## Decision

**`ManagedIdempotencyResult` (B) is the single idempotency authority.** New
idempotent mutation routes bind to it through `idempotency.py` and a
`canonical_action`; they do not introduce a per-route table.

Grounds:

1. It is the only action-generic authority, so it absorbs new routes without a
   new table per route.
2. It is the only one binding a receipt, a governance event, and a signed result
   artifact — it produces evidence, not just a cached response.
3. It is the only one that types the terminal decision and constrains it in the
   schema.
4. Its evidence writes are transactional with the governance decision; A's are
   best-effort and can be silently lost.
5. It is already master's authority for `AGENT_CREATE_ACTION` and is the newest
   migration, so adopting it converges the two lineages instead of forking again.

**`AgentRegistrationIdempotency` (C) is never restored.** Work still carrying it
must be re-pointed at B and `AGENT_CREATE_ACTION` rather than rebased. Its
migration number collides with `0007_governance_events`, and three further stack
migrations (`0008`/`0009`/`0010`) collide with `native_receipt_ledger`,
`native_receipt_artifacts`, and `scope_attachment`; all must renumber to `0012+`.

**`TenantBootstrapIdempotency` (A) stays as-is for now.** A is live, tested, and
carries a semantic B does not currently express — the `UniqueConstraint("org_id")`
one-bootstrap-per-org singleton. Converging A onto B is a separate project with
its own migration and its own risk, and is explicitly **not** a prerequisite for
this decision. It is recorded here so it is not lost, not so it is done now.

## Consequences

- Test assertions that count rows in `agent_registration_idempotency` re-point to
  `ManagedIdempotencyResult` filtered by `AGENT_CREATE_ACTION`. Two draft PRs
  couple to C through exactly one integration test file each; their production
  code is already free of it.
- The evidence harness names a gate selector for
  `tests/integration/test_agent_registration_idempotency_postgres.py`, which does
  not exist on master. That dangling selector predates this ADR and is tracked
  separately; it must not be resolved by restoring C.
- Anything still building on C accrues rework. The decision is recorded here so
  it is not re-litigated per PR.
