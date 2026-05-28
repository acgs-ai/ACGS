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
- `gove-zone` evaluation report ingestion for claim-safe evidence.
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


## Evaluation report ingestion

`gove-zone eval` emits local policy-fixture metrics (`scenario_count`,
`passed`, `failed`, attack success rate, utility retention, p95 latency, and
per-scenario decisions). The eval MVP can ingest that JSON as hash-addressed
claim evidence and append a chain-hashed audit record:

```bash
python -m governance.cli.ingest_evaluation_report \
  --report gove-zone-report.json \
  --audit-path .acgs/audit.jsonl \
  --tenant acme
```

The same surface is available over the optional API:

```bash
curl -X POST http://localhost:8080/evidence/evaluation-report \
  -H 'authorization: Bearer acme:secret' \
  -H 'content-type: application/json' \
  -d '{"tenant":"acme","report":{...}}'
```

Tenant-scoped report evidence can be queried back from the hash chain without
reading raw audit events:

```bash
curl 'http://localhost:8080/evidence/evaluation-reports?status=passed' \
  -H 'authorization: Bearer acme:secret'
```

Reports with failed scenarios are still audited, but they are marked `failed`
and `allow: false`, so downstream claim mappers cannot treat them as passed
benchmark evidence.

### Benchmark result adapters

Local AgentDojo/InjecAgent/ToolEmu-style result fixtures can be converted into
the same gove-zone-compatible report schema before ingestion:

```python
from governance.benchmarks.agentdojo_adapter import agentdojo_report_from_fixture
from governance.benchmarks.injecagent_adapter import injecagent_report_from_fixture
from governance.benchmarks.toolemu_adapter import toolemu_report_from_fixture

agentdojo_report = agentdojo_report_from_fixture("agentdojo-results.json")
injecagent_report = injecagent_report_from_fixture("injecagent-results.json")
toolemu_report = toolemu_report_from_fixture("toolemu-results.json")
```

The adapters preserve `source` (`agentdojo` / `injecagent` / `toolemu`),
compute attack-success and utility-retention metrics, and add source-specific
audit risk tags during ingestion. They only cover local reviewable
fixture/result shapes; running the full upstream benchmark suites remains a
separate evidence task.
