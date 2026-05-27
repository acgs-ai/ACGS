# iii-governance-lab

Experimental iii worker lab for local governance orchestration trials.

## Boundaries

- Do not edit acgi-ai/ from this experiment.
- Do not edit .github/workflows/ from this experiment.
- Do not store secrets, tokens, service-account JSON, or production URLs here.
- Do not treat a local iii run as production deployment proof.
- Keep function IDs stable unless tests and README examples change in the same commit.

## Local Gates

Run the root experiment contract test after edits:

```bash
uv run --package acgs_governance_eval_mvp python -m pytest tests/test_iii_governance_lab.py -q
```

If `uv` or `pytest` is unavailable on the current machine, record that and run
the direct Python fallback documented in the root test handoff.
