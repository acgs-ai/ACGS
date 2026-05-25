"""T073 — SC-002 classification accuracy harness.

Loads ``tests/fixtures/classification_corpus.jsonl`` (200 labeled events) and
asserts that the classifier achieves ≥ 95 % accuracy on the rows it can handle.

US1 scope (``classify``): ``completed`` and ``policy-violation``.
US2 scope (``classify_with_context``): ``dispatch-failure``, ``unwired-handler``,
``orphan-response``, ``incomplete-pair``.

If ``classify_with_context`` is not yet present the US2 rows are
``pytest.mark.xfail``-ed so CI stays green while US2 is in flight.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_bus_analyzer.classifier import classify

# US2 statuses need classify_with_context — import if present, else None.
try:
    from agent_bus_analyzer.classifier import classify_with_context  # type: ignore[attr-defined]

    _HAS_US2 = True
except ImportError:
    _HAS_US2 = False
    classify_with_context = None  # type: ignore[assignment]

_CORPUS_PATH = Path(__file__).parent / "fixtures" / "classification_corpus.jsonl"

_US1_STATUSES = frozenset({"completed", "policy-violation"})
_US2_STATUSES = frozenset(
    {"dispatch-failure", "unwired-handler", "orphan-response", "incomplete-pair"}
)

_SC002_ACCURACY_THRESHOLD = 0.95


def _load_corpus() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with _CORPUS_PATH.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            clean = line.strip()
            if not clean:
                continue
            try:
                rows.append(json.loads(clean))
            except json.JSONDecodeError as exc:
                pytest.fail(f"corpus parse error at line {lineno}: {exc}")
    return rows


def _us1_params() -> list[pytest.param]:
    rows = _load_corpus()
    params = []
    for i, row in enumerate(rows):
        if row.get("status") in _US1_STATUSES:
            params.append(pytest.param(row, id=f"row{i}-{row['event_id']}"))
    return params


def _us2_params() -> list[pytest.param]:
    rows = _load_corpus()
    params = []
    for i, row in enumerate(rows):
        if row.get("status") in _US2_STATUSES:
            marks = (
                []
                if _HAS_US2
                else [pytest.mark.xfail(reason="awaits US2 classify_with_context", strict=False)]
            )
            params.append(pytest.param(row, marks=marks, id=f"row{i}-{row['event_id']}"))
    return params


@pytest.mark.parametrize("row", _us1_params())
def test_us1_classification(row: dict[str, Any]) -> None:
    """US1: classify() must return the corpus label for completed/policy-violation rows."""
    expected = row["status"]
    got = classify(row)
    assert got == expected, f"event_id={row['event_id']!r}: expected {expected!r}, got {got!r}"


@pytest.mark.parametrize("row", _us2_params())
def test_us2_classification(row: dict[str, Any]) -> None:
    """US2: classify_with_context() must return the corpus label for remaining statuses.

    Rows are xfail until classify_with_context is implemented (US2/T040).
    """
    assert _HAS_US2, "classify_with_context not yet available"
    expected = row["status"]
    got = classify_with_context(row)  # type: ignore[misc]
    assert got == expected, f"event_id={row['event_id']!r}: expected {expected!r}, got {got!r}"


def test_sc002_us1_accuracy_threshold() -> None:
    """SC-002: aggregate US1 accuracy must be ≥ 95 %."""
    rows = _load_corpus()
    us1_rows = [r for r in rows if r.get("status") in _US1_STATUSES]
    assert us1_rows, "no US1 rows found in corpus"

    correct = sum(1 for r in us1_rows if classify(r) == r["status"])
    accuracy = correct / len(us1_rows)
    assert accuracy >= _SC002_ACCURACY_THRESHOLD, (
        f"SC-002 US1 accuracy {accuracy:.1%} < {_SC002_ACCURACY_THRESHOLD:.0%} "
        f"({correct}/{len(us1_rows)} correct)"
    )


@pytest.mark.skipif(not _HAS_US2, reason="classify_with_context not yet available")
def test_sc002_full_accuracy_threshold() -> None:
    """SC-002: full corpus accuracy (US1 + US2) must be ≥ 95 % once US2 lands."""
    rows = _load_corpus()
    us1_correct = sum(
        1 for r in rows if r.get("status") in _US1_STATUSES and classify(r) == r["status"]
    )
    us2_correct = sum(
        1
        for r in rows
        if r.get("status") in _US2_STATUSES and classify_with_context(r) == r["status"]  # type: ignore[misc]
    )
    total = len(rows)
    accuracy = (us1_correct + us2_correct) / total
    assert accuracy >= _SC002_ACCURACY_THRESHOLD, (
        f"SC-002 full accuracy {accuracy:.1%} < {_SC002_ACCURACY_THRESHOLD:.0%}"
    )
