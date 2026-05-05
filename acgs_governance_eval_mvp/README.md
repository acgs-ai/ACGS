# ACGS Governance Evaluation MVP

Runtime governance layer for AI agents and tool calls.

This scaffold implements three pre-execution gates:

1. **Authority Check** — role/scope/action/limit validation.
2. **Policy Recall** — deterministic policy citation and denial checks.
3. **Governance Recall** — explainable final decision record.

It also includes:

- JSONL chain-hashed audit trail.
- Replay support.
- Optional FastAPI surface.
- Optional OTel metric hooks.
- Policy/role examples.
- Pytest acceptance tests.

## Install

```bash
python -m pip install -e ".[test]"
pytest
```

Optional API runtime:

```bash
python -m pip install -e ".[api,otel]"
ACGS_ROLES_PATH=governance/roles.json \
ACGS_POLICY_DIR=governance/policies/2026-05 \
ACGS_AUDIT_PATH=.acgs/audit.jsonl \
uvicorn governance.service.api:app --reload --port 8080
```

## API example

```bash
curl -X POST http://localhost:8080/govern/validate \
  -H 'content-type: application/json' \
  -d '{
    "tenant": "default",
    "intent": "Redline supplier contract",
    "action_type": "contract.redline",
    "resource": "contracts/supplier-123",
    "inputs_hash": "sha256:demo",
    "actor": {"id":"agent-legal-1","role":"LegalOps","tenant":"default"},
    "metadata": {"policy_citations":["CONTRACT-AUTHORITY-001"]}
  }'
```

## Core invariant

Every external action must satisfy:

```text
AuthorityGate.allow AND PolicyRecallGate.allow AND GovernanceRecallGate.allow
```

If a gate cannot evaluate, it must fail closed and emit an audit event.
