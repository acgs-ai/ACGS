"""Guards for ``scripts/check_governance_stack_index.py``.

The script is a claim-safety gate over two routing documents: it fails when a
required package row or evidence concept disappears, and — the load-bearing
half — when an overclaim ("production-ready", "regulator-grade") appears. A
gate that silently stops failing is worse than no gate, so every failure branch
is exercised here, plus the real repo documents as an integration check.
"""

from __future__ import annotations

import check_governance_stack_index as gate
import pytest

VALID_INDEX_HEAD = "# Governance stack index\n\n"
VALID_MAP_HEAD = "# Integration readiness task map\n\n"


def _index_body() -> str:
    """Minimal document text that satisfies every index assertion."""
    rows = "\n".join(
        f"| layer | `{path}` | contract | gate | status |" for path in gate.REQUIRED_PATHS
    )
    concepts = "\n".join(gate.REQUIRED_CONCEPTS)
    return f"{VALID_INDEX_HEAD}{gate.MAIN_TABLE_HEADER}\n{rows}\n\n{concepts}\n"


def _map_body() -> str:
    return VALID_MAP_HEAD + "\n".join(gate.INTEGRATION_MAP_REQUIRED_CONCEPTS) + "\n"


@pytest.fixture
def docs(tmp_path, monkeypatch):
    """Point the gate at writable copies of the two documents it validates."""
    index = tmp_path / "docs" / "governance-stack-index.md"
    readiness = tmp_path / "docs" / "integration-readiness-task-map.md"
    index.parent.mkdir(parents=True)
    index.write_text(_index_body(), encoding="utf-8")
    readiness.write_text(_map_body(), encoding="utf-8")
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    monkeypatch.setattr(gate, "INDEX", index)
    monkeypatch.setattr(gate, "INTEGRATION_MAP", readiness)
    return index, readiness


def test_valid_documents_pass(docs, capsys):
    assert gate.main() == 0
    assert "check passed" in capsys.readouterr().out


def test_missing_index_is_an_error(docs, capsys):
    index, _ = docs
    index.unlink()

    assert gate.main() == 1
    assert "missing docs/governance-stack-index.md" in capsys.readouterr().out


def test_missing_integration_map_is_an_error(docs, capsys):
    _, readiness = docs
    readiness.unlink()

    assert gate.main() == 1
    assert "missing docs/integration-readiness-task-map.md" in capsys.readouterr().out


def test_index_must_start_with_the_expected_h1(docs, capsys):
    index, _ = docs
    index.write_text(
        _index_body().replace(VALID_INDEX_HEAD, "# Something else\n\n", 1), encoding="utf-8"
    )

    assert gate.main() == 1
    assert "index must start with the expected H1" in capsys.readouterr().out


def test_integration_map_must_start_with_the_expected_h1(docs, capsys):
    _, readiness = docs
    readiness.write_text("# Drifted title\n\n" + _map_body(), encoding="utf-8")

    assert gate.main() == 1
    assert "integration readiness map must start with the expected H1" in capsys.readouterr().out


@pytest.mark.parametrize("concept", gate.REQUIRED_CONCEPTS)
def test_each_required_index_concept_is_enforced(docs, capsys, concept):
    index, _ = docs
    index.write_text(_index_body().replace(concept, "REMOVED"), encoding="utf-8")

    assert gate.main() == 1
    assert f"missing required concept: {concept}" in capsys.readouterr().out


@pytest.mark.parametrize("concept", gate.INTEGRATION_MAP_REQUIRED_CONCEPTS)
def test_each_required_map_concept_is_enforced(docs, capsys, concept):
    _, readiness = docs
    readiness.write_text(_map_body().replace(concept, "REMOVED"), encoding="utf-8")

    assert gate.main() == 1
    assert (
        f"integration readiness map missing required concept: {concept}" in capsys.readouterr().out
    )


@pytest.mark.parametrize("path", gate.REQUIRED_PATHS)
def test_each_required_package_row_is_enforced(docs, capsys, path):
    index, _ = docs
    index.write_text(_index_body().replace(f"`{path}`", path), encoding="utf-8")

    assert gate.main() == 1
    assert f"missing package/path row: {path}" in capsys.readouterr().out


@pytest.mark.parametrize("claim", gate.FORBIDDEN_CLAIMS)
def test_each_forbidden_overclaim_is_rejected(docs, capsys, claim):
    index, _ = docs
    index.write_text(_index_body() + f"\nThis stack is {claim} today.\n", encoding="utf-8")

    assert gate.main() == 1
    assert f"forbidden overclaim present: {claim}" in capsys.readouterr().out


def test_forbidden_overclaim_detection_is_case_insensitive(docs, capsys):
    index, _ = docs
    index.write_text(_index_body() + "\nPRODUCTION-READY stack.\n", encoding="utf-8")

    assert gate.main() == 1
    assert "forbidden overclaim present: production-ready" in capsys.readouterr().out


@pytest.mark.parametrize("stale", gate.INTEGRATION_MAP_FORBIDDEN_STALE_SCOPE)
def test_stale_scope_wording_is_rejected(docs, capsys, stale):
    _, readiness = docs
    readiness.write_text(_map_body() + f"\n{stale}\n", encoding="utf-8")

    assert gate.main() == 1
    assert f"integration readiness map has stale scope wording: {stale}" in capsys.readouterr().out


def test_drifted_main_table_header_is_reported(docs, capsys):
    index, _ = docs
    index.write_text(
        _index_body().replace(gate.MAIN_TABLE_HEADER, "| Layer | Path |"), encoding="utf-8"
    )

    assert gate.main() == 1
    assert "main routing table header is missing or drifted" in capsys.readouterr().out


def test_all_failures_are_reported_together_not_just_the_first(docs, capsys):
    """The gate is a report, not a fail-fast: an operator fixing drift needs
    every violation in one pass."""
    index, _ = docs
    text = _index_body().replace("fail-closed", "REMOVED").replace(gate.MAIN_TABLE_HEADER, "")
    index.write_text(text + "\nregulator-grade\n", encoding="utf-8")

    assert gate.main() == 1
    out = capsys.readouterr().out
    assert "missing required concept: fail-closed" in out
    assert "main routing table header is missing or drifted" in out
    assert "forbidden overclaim present: regulator-grade" in out


def test_repository_documents_currently_pass(capsys):
    """Integration check against the real tracked documents — this is what the
    gate actually runs on."""
    if not gate.INDEX.exists() or not gate.INTEGRATION_MAP.exists():
        pytest.skip("governance routing documents are not present in this checkout")

    assert gate.main() == 0, capsys.readouterr().out
