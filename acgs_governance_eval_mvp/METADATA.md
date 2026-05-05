# `request.metadata` reference

Every `ActionRequest` carries a free-form `metadata: dict[str, Any]`. A
small set of well-known keys are read by the bundled gates and by the
HTTP service layer; everything else is round-tripped into the audit
record but otherwise ignored.

This file is the source of truth for which keys carry semantics today.
If you add a new gate that reads a metadata key, document it here.

## Read by the bundled gates today

| Key | Type | Semantics | Read by |
|---|---|---|---|
| `cross_tenant_delegation` | `bool` (truthy) | When `request.tenant != actor.tenant`, this flag bypasses the tenant-mismatch deny. Set this only when there is an out-of-band delegation contract; the value is preserved verbatim in the audit record. | `AuthorityGate` (also surfaced by `governance/service/api.py` for the privilege banner) |
| `maci_required_role` | `str` | When set, the actor's role must list this string in its `maci_roles` (proposer / executor / observer / verifier / etc). Used to enforce separation of duties on a per-call basis. | `AuthorityGate` |
| `policy_citations` | `list[str]` | Policy ids (or obligation ids) the agent claims as authority for this action. The gate compares each applicable policy's id + obligation ids against this list. Missing required citations → `POLICY_CITATION_MISSING`. | `PolicyRecallGate` |
| `requires_policy` | `bool` | Forces `PolicyRecallGate` to treat the action as critical even if `action_type` is not in the bundled `critical_actions` set — useful for actions that are normally optional but become regulated under specific conditions. | `PolicyRecallGate` |
| `content_flags` | `list[str]` | Free-form content classifiers (`bonus_offer`, `inducement`, `risk_free`, ...). Policies can match on these via `conditions.metadata_flags_any`. | `PolicyRecallGate` (via policy `conditions`) |

`PolicyRecallGate` also evaluates `conditions.metadata_equals` per policy:
any metadata key listed there must match exactly. The set of keys is
therefore policy-defined (not gate-defined) — see each policy's
`conditions.metadata_equals` for the keys it pins.

## Forward-compatible keys (recognized but not yet enforced)

These keys appear in roadmap docs and review templates but are NOT read
by any bundled gate today. They are reserved so adapters can begin
populating them without churning the audit schema later. If you set them
now, they ride along in the audit record but do not affect the
decision.

| Key | Type | Semantics | Status |
|---|---|---|---|
| `user_confirmed` | `bool` | Whether a human-in-the-loop confirmed this specific action. Slated for the future `require_human` gate. | reserved |
| `risk_domain` | `str` | Coarse risk category (`financial`, `pii`, `marketing`, `infra`, ...). Slated for a future risk-routing gate. | reserved |
| `procedure_id` | `str` | Stable identifier for the procedure or runbook this action is part of. Slated for cross-event correlation in audit / replay. | reserved |
| `risk_tags` | `list[str]` | Fine-grained risk tags supplementing `risk_domain`. Slated for the same future risk-routing gate. | reserved |

## Notes

- The metadata dict is preserved verbatim in the audit record
  (`DecisionRecord.request.metadata`) and is part of the canonical hash
  payload. Do not put secrets or PII in metadata.
- New keys consumed by gates should be added to **the table above** in
  the same PR that adds the consuming gate, so integrators always have a
  one-stop reference.
- Reason codes referenced in this file are documented in
  [INTEGRATING.md](INTEGRATING.md#3-reason-code-reference).
