# Classification Corpus

`classification_corpus.jsonl` — 200 hand-authored synthetic events for evaluating
the event-status classifier (SC-002: ≥ 95 % accuracy on labeled corpus).

## Label Distribution

| Status              | Count |
|---------------------|-------|
| `completed`         | 100   |
| `policy-violation`  | 20    |
| `dispatch-failure`  | 20    |
| `unwired-handler`   | 20    |
| `orphan-response`   | 20    |
| `incomplete-pair`   | 20    |
| **Total**           | **200** |

Note: `ingest-gap` is excluded from the corpus — it describes a missing-capture
interval, not a classifiable event payload, and cannot be produced by the
classifier from row-level signal alone.

## Row Signal Convention

Each row contains sufficient field-level signal for a classifier to reproduce
the labeled status without external context:

| Status             | Distinguishing signal                                                     |
|--------------------|---------------------------------------------------------------------------|
| `completed`        | `kind` ∈ {dispatch, response} OR `kind=decision` + `decision` ∈ {allow, transform}; no flagged_rule |
| `policy-violation` | `kind=decision` + `decision=deny` OR (`decision=escalate` + `flagged_rule` set) |
| `dispatch-failure` | `kind=dispatch` + `target_handler_resolved=null`                          |
| `unwired-handler`  | `kind=dispatch` + `target_handler_declared` names an unregistered handler + `target_handler_resolved=null` |
| `orphan-response`  | `kind=response` + `causal_index=0` (no prior dispatch in trace)           |
| `incomplete-pair`  | `kind=dispatch` + event is the sole event in its trace (no matching response) |

## Hash Convention

All rows use:
- `constitutional_hash`: `"a1b2c3d4e5f60718"` (16-char hex, stable test constant)
- `event_hash`: SHA-256 over `canonical_json(event_without_event_hash)`, computed
  deterministically at generation time

## Re-labeling Policy

Re-labeling any row requires **two-labeler agreement** with Cohen's kappa ≥ 0.8
before the new label is accepted into this file. Rationale: the corpus gates
SC-002 accuracy assertions in CI; single-annotator drift can silently inflate
apparent accuracy.

## Regeneration

The corpus is generated deterministically (seed=42) by the inline script in
`tests/test_classification_accuracy.py`'s module docstring or by running the
generator embedded in the original task plan. If you need to extend the corpus,
add rows at the end — do not shuffle existing rows, as causal_index values
within a trace must remain monotonic.
