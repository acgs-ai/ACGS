# Contributing to acgs-governance-eval-mvp

## Before you change gate or adapter code

Read **[docs/failure-modes-taxonomy.md](docs/failure-modes-taxonomy.md)** first. It catalogs
every reason code, decision state, integration mistake, and replay invariant in one place.
If you are adding a new deny path, adding a reason code there keeps the taxonomy complete.

## Key reference docs

| Document | What it covers |
|---|---|
| [docs/failure-modes-taxonomy.md](docs/failure-modes-taxonomy.md) | All failure modes, reason codes, integration mistakes, replay failures |
| [INTEGRATING.md](INTEGRATING.md) | Five-minute quickstart, `validate`/`guard` lifecycle, full reason-code table |
| [METADATA.md](METADATA.md) | Every `request.metadata` key the gates read |
| [docs/acgs-governance-eval-mvp.md](docs/acgs-governance-eval-mvp.md) | MVP gates, API surface, replay acceptance criteria, non-negotiable invariants |

## Running tests

```bash
cd acgs_governance_eval_mvp
pytest tests/ -v
```

## Adding a new reason code

1. Emit the code from the relevant gate in `governance/gates/`.
2. Add a `GateResult.remediation` string explaining the fix.
3. Add the code + description + fix to `docs/failure-modes-taxonomy.md` in the correct section.
4. Add a test in `tests/` that triggers the new code and asserts it in `decision.reason_codes`.

## Adding a new policy

Drop a YAML file into `governance/policies/<bundle-date>/`. Policies are loaded by
`governance/policy_loader.load_policy_bundle()` — any file matching `*.yaml` or `*.yml` in
the directory is included.

## Replay safety

Any change that alters gate evaluation order, reason code strings, or the `DecisionRecord`
schema must bump `DECISION_SCHEMA_VERSION` in `governance/models.py` and update the replay
acceptance criteria in `docs/acgs-governance-eval-mvp.md`.
