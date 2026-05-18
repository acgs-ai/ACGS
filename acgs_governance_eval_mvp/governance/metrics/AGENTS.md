# AGENTS.md — acgs_governance_eval_mvp/governance/metrics

## Purpose

Optional OpenTelemetry adapter for emitting governance counters from the
evaluator. Lives in its own subpackage so importing `governance.metrics` never
forces an `opentelemetry` dependency on minimal installs — the module degrades
silently to a no-op when the OTel runtime is not installed. Counters are kept
low-cardinality on purpose so the metrics pipeline does not explode on
per-event labels.

## Key Files

- `__init__.py` — Re-exports `GovernanceMetrics` for the parent package
- `otel.py` — `GovernanceMetrics` class with `record_gate(GateResult)` and
  `record_decision(event: dict)`. Provides a `GovernanceMetrics.disabled()`
  classmethod for tests and a try/except guard around `from opentelemetry
  import metrics` that flips `self.enabled = False` on import failure

## Workflow / Commands

```bash
# Install the optional OTel extra and run the evaluator with metrics on
pip install opentelemetry-api opentelemetry-sdk
python -m governance.evaluate --metrics on  # if wired in your runner

# Run governance tests with metrics disabled (default)
pytest acgs_governance_eval_mvp/tests -q

# Smoke-check that disabled mode still produces a usable object
python -c "from governance.metrics import GovernanceMetrics as M; \
  m=M.disabled(); m.record_decision({'allow': True, 'tenant': 't1'})"
```

## Gotchas / Conventions

- **Never put `event_id` (or any high-cardinality field) on a metric label.**
  The module's docstring is explicit about this — OTel backends will silently
  drop or bill astronomical numbers of series. Allowed labels today: `gate`,
  `allow`, `reason_code`, `tenant`.
- `reason_code` defaults to `UNKNOWN` when `result.reason_codes` is empty. Do
  not "fix" this by emitting an empty string — downstream dashboards filter
  on `reason_code != UNKNOWN` to spot unattributed denies.
- The constructor tolerates a missing OTel install: `enabled` flips to `False`
  and every `record_*` becomes a no-op. Callers should not branch on
  availability; just always call.
- Counter names (`acgs_governance_gate_decisions_total`,
  `acgs_governance_decisions_total`) are part of the metrics contract.
  Renaming them breaks Grafana dashboards and alert rules; coordinate via a
  governance amendment before changing.

## Tests

There are no metrics-specific tests in this dir; coverage comes via the
evaluator suite under `acgs_governance_eval_mvp/tests/`, which runs with the
disabled adapter by default.
