# ACGS Governed Trajectory Pipeline

A governed measurement framework that captures Claude Code acting as a senior AI
researcher/engineer on the ACGS codebase, and turns each session into an
**immutable, verified execution trajectory** — human request → investigation →
reasoning → tool use → code changes → tests → verification → outcome.

The asset is the complete, provenance-stamped, evidence-graded trajectory, not the
generated text. The pipeline is **fail-closed**: every derived judgment defaults to
"unproven," and success is never marked without evidence.

## Architecture (by phase)

| Phase | What | Module(s) | Artifact |
|---|---|---|---|
| **1 — Ingestion** | Claude Code JSONL → causal trajectory; content-addressed WORM raw + hash-chained manifest; validation gates V1–V6; secret boundary | `adapter`, `materialize`, `raw_store`, `secrets_scan`, `validate`, `ingest`, `replay`, `git_evidence` | `governance_trajectory/v2` |
| **2 — Evaluation** | Deterministic, evidence-cited evaluator (6 checks, 4 scores, labels, provisional tier ≤ B) | `evaluate`, `scoring`, `annotation_store` | `governance_annotation/v1` |
| **3 — Outcome grounding** | Link to commit/diff/tests/CI/review/deploy; confirm A/S only with evidence | `outcome` | `governance_outcome/v1` |
| **4 — Dataset factory** | SQLite index, tiered release packaging, 3 dataset products | `index`, `packaging`, `datasets` | reference-only manifests |

Design records: `docs/adr/0001`–`0004`. Schemas: `docs/schema/`. Examples:
`docs/examples/`. Phase-1.1 evidence freeze: `docs/evidence/` (tags
`phase-1-baseline`, `phase-1.1-freeze`).

## Invariants (ACGS)

- **Immutable provenance** — raw is authoritative, write-once, content-addressed;
  every registry (manifest / annotation / outcome / release) is hash-chained.
- **Separation of raw & derived** — normalized/annotation/outcome data reference raw
  by digest; nothing derived is ever copied into raw, and packages reference members
  by id+digest (no raw content copied). All derived layers are rebuildable.
- **Deterministic verification** — no LLM / network / wall-clock / randomness in any
  scoring or gating path; same inputs → byte-identical output.
- **Fail-closed** — missing/ambiguous evidence lowers status/score, never raises it;
  secrets quarantine (never redact raw); unknown versions/types quarantine; confirmed
  Tier S/A requires real outcome evidence.

## Quality tiers

`C` raw archive · `B` complete/attempted trajectory · `A` verified outcome
(tests+commit) · `S` merged-quality (A + approved review + green CI). Phase 2 caps
at B; Phases 3 confirms A/S from outcome evidence only.

## Usage

```bash
uv venv .venv && uv pip install --python .venv/bin/python -e '.[dev]'
.venv/bin/python -m pytest -q                      # full suite
.venv/bin/python -m acgs_trajectory.cli <session.jsonl> --store <dir> --repo .
```

`acgs_trajectory.ingest.ingest_text` → v2 record; `acgs_trajectory.evaluate.evaluate`
→ annotation; `acgs_trajectory.outcome.build_outcome` → grounded tier;
`acgs_trajectory.index.Index` + `datasets.build_all` → dataset manifests.

## Status

Phases 1–4 implemented and tested (see `pytest`). Not a security boundary against a
same-trust-domain adversary; the unforgeable enforcement is CI branch protection.
