# Handoff Prompt — ACGS Governance Evaluation MVP

You are implementing the ACGS runtime governance evaluation layer for AI agents.

## Goal

Create a minimal, tested, fail-closed governance layer that intercepts every external tool/API/DB/write action before execution and emits a replayable, chain-hashed audit event.

## Required components

Implement the following files or equivalents:

```text
governance/
  models.py
  policy_loader.py
  roles.json
  policies/2026-05/*.yaml
  gates/
    authority_gate.py
    policy_recall_gate.py
    governance_recall_gate.py
  audit/
    jsonl_chain.py
  adapters/
    tools.py
  service/
    api.py
  metrics/
    otel.py
  cli/
    sample_audit_query.py
    replay_event.py
  schema/
    audit_event.schema.json
    decision_explain.schema.json
tests/
  test_authority_gate.py
  test_policy_recall_gate.py
  test_audit_chain.py
  test_replay.py
```

## Behavioral contract

For every external action:

```text
allow = AuthorityGate.allow AND PolicyRecallGate.allow AND GovernanceRecallGate.allow
```

Deny on:

- Unknown role.
- Action not listed in role.
- Resource outside scope.
- Amount over limit.
- Missing policy for critical action.
- Missing policy citation for applicable policy.
- Deny policy match.
- Missing governance explanation.

## Audit contract

Every decision must persist a JSONL event with:

- `event_id`
- `who`: actor ID, role, tenant
- `intent`
- `action_type`
- `resource`
- `inputs_hash`
- `checks[]`
- `allow`
- `reasons[]`
- `reason_codes[]`
- `rule_ids[]`
- `policy_version`
- `role_version`
- `timestamp`
- `previous_hash`
- `event_hash`

`event_hash = sha256(canonical_json(event_without_event_hash))`

## Tests required before merge

- LegalOps can redline a contract when citing `CONTRACT-AUTHORITY-001`.
- MarketingOps cannot approve a contract.
- Ontario marketing with `bonus_offer` flag is denied by `MKT-ONTARIO-NO-INDUCEMENT-001`.
- Missing policy citation denies critical contract action.
- Two appended audit events form a valid hash chain.
- Tampering with one JSONL line causes `verify_chain().valid == false`.
- Replay of an audit event under same versions returns same `allow` and `reason_codes`.

## Do not do

- Do not allow execution when a gate errors.
- Do not make audit optional in production paths.
- Do not use free-text explanations as the source of truth; explanations must reference structured rule IDs.
- Do not put event IDs in OTel labels.
- Do not use nondeterministic policy matching in the core gate path.
