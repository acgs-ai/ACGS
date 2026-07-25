"""Lock the canonical adversary model in ``docs/SECURITY_MODEL.md``.

`ROADMAP-ENFORCEMENT-SUBSTRATE.md` (Part III / Part V Track E) makes the adversary
model the *spine* of the security story and requires it to be canonicalized into
``docs/SECURITY_MODEL.md`` before later tracks layer onto it. Two failure modes
that doc spine must never silently develop:

1. **Dropping an adversary** — especially ``ADV9`` (out-of-gate executor bypass),
   the *complete-mediation keystone* of the reference monitor. An earlier roadmap
   draft miscounted the table and dropped it; this test makes that recurrence loud.
2. **Citing evidence that does not exist** — an ``[on-master]`` row that names a
   ``test_*.py`` which is not in the tree is an overclaim. This is the Track E
   enforcement seed: *a named on-master control must have a real artifact.*

The test is pure text + filesystem (no ``gove_zone`` import), so it runs in the
``tests/docs`` job without the package installed.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SECURITY_MODEL = ROOT / "docs" / "SECURITY_MODEL.md"

# The canonical adversary set is ADV1..ADV14 (14 adversaries). The roadmap is
# explicit: "this 14-adversary view"; ADV9..ADV14 were added after an adversarial
# review found the original eight missing the complete-mediation keystone.
EXPECTED_ADVERSARIES = {f"ADV{i}" for i in range(1, 15)}

# The per-mechanism threat table enumerates exactly these 22 named threats. The
# reconciliation must map every one of them to >=1 adversary. "Exactly" is
# enforced in both directions: a dropped row and an *added* row both fail. The
# one-directional (subset) form let four composition rows land in the threat
# table with no reconciliation entry, which is precisely the table-vs-adversary
# drift this section exists to prevent.
EXPECTED_THREATS = {
    "Missing receipt",
    "Malformed receipt",
    "Expired receipt",
    "Tampered receipt",
    "Mismatched actor",
    "Mismatched action",
    "Argument substitution",
    "Self-validation",
    "Replay attempt",
    "Audit-chain tampering",
    "Consumption-ledger tampering",
    "Unsigned dev mode misuse",
    "Policy-bundle substitution",
    "MCP/tool-gateway misuse",
    "Executor bypass",
    "Policy evaluation failure",
    "Policy timeout/hang",
    "Audit append failure",
    "Step reorder",
    "Predecessor substitution",
    "Cross-workflow / cross-plan step lifting",
    "Cross-level collusion (plan/step)",
}

# Directories an [on-master] adversary row may cite test evidence from.
TEST_DIRS = (
    ROOT / "packages" / "gove-zone" / "tests",
    ROOT / "tests",
)

_ADV_ROW = re.compile(r"^\|\s*(ADV\d+)\s*\|")
_TEST_FILE = re.compile(r"test_[A-Za-z0-9_]+\.py")
_STATUS = re.compile(r"\[on-master(?:, partial)?\]|\[proposed\]")


def _read() -> str:
    return SECURITY_MODEL.read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    """Return the body from ``heading`` up to the next same-or-higher heading."""
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip() == heading)
    level = len(heading) - len(heading.lstrip("#"))
    end = len(lines)
    for i in range(start + 1, len(lines)):
        stripped = lines[i].lstrip("#")
        this_level = len(lines[i]) - len(stripped)
        if lines[i].startswith("#") and 0 < this_level <= level:
            end = i
            break
    return "\n".join(lines[start:end])


def _cells(row: str) -> list[str]:
    """Split a markdown table row into trimmed cell values."""
    return [c.strip() for c in row.strip().strip("|").split("|")]


def _adversary_rows(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        if _ADV_ROW.match(line):
            rows.append(_cells(line))
    return rows


def test_security_model_exists() -> None:
    assert SECURITY_MODEL.is_file(), f"missing {SECURITY_MODEL}"


def test_all_fourteen_adversaries_present_no_gaps() -> None:
    """ADV1..ADV14 each appear exactly once; no gaps, no duplicates, no extras."""
    rows = _adversary_rows(_read())
    ids = [r[0] for r in rows]
    found = set(ids)

    assert found == EXPECTED_ADVERSARIES, (
        "adversary table drifted from the canonical ADV1..ADV14 set:\n"
        f"  missing : {sorted(EXPECTED_ADVERSARIES - found, key=_num)}\n"
        f"  unexpected: {sorted(found - EXPECTED_ADVERSARIES, key=_num)}"
    )
    assert len(ids) == len(found), f"duplicate adversary rows: {ids}"


def test_adv9_executor_bypass_keystone_not_dropped() -> None:
    """ADV9 is the complete-mediation keystone; it must name the bypass attack."""
    rows = {r[0]: r for r in _adversary_rows(_read())}
    assert "ADV9" in rows, "ADV9 (out-of-gate executor bypass) is missing entirely"
    adv9 = " ".join(rows["ADV9"]).lower()
    assert "bypass" in adv9, "ADV9 row no longer describes the executor-bypass keystone"
    # The keystone must be tied to the reference-monitor property it protects.
    assert "complete mediation" in _read().lower(), (
        "the complete-mediation property must be named (ADV9 protects it)"
    )


def test_every_adversary_row_carries_a_claim_status_tag() -> None:
    """Claim discipline: each row's Status column is on-master/partial/proposed."""
    rows = _adversary_rows(_read())
    # Row layout: [id, adversary, attempt, mechanism, gate, status, evidence]
    for row in rows:
        assert len(row) == 7, f"{row[0]}: expected 7 columns, got {len(row)}: {row}"
        status = row[5]
        assert _STATUS.fullmatch(status), (
            f"{row[0]}: Status column {status!r} is not one of "
            "[on-master] / [on-master, partial] / [proposed]"
        )


def test_on_master_evidence_files_exist() -> None:
    """No dangling citations: every test_*.py named in a non-proposed row exists.

    This is the Track E enforcement seed — a named on-master control must map to a
    real artifact in the tree.
    """
    known = {p.name for d in TEST_DIRS for p in d.rglob("test_*.py")}
    missing: list[str] = []
    for row in _adversary_rows(_read()):
        adv_id, status, evidence = row[0], row[5], row[6]
        if status == "[proposed]":
            continue  # proposed rows are allowed to cite no concrete test
        for name in _TEST_FILE.findall(evidence):
            if name not in known:
                missing.append(f"{adv_id} -> {name}")
    assert not missing, "adversary rows cite test files not present in the tree:\n  " + "\n  ".join(
        missing
    )


def _threat_table_names() -> set[str]:
    """Every row label in the per-mechanism threat table, as written."""
    names: set[str] = set()
    for line in _section(_read(), "## Threat table").splitlines():
        if not line.startswith("|"):
            continue
        cells = _cells(line)
        if not cells or cells[0] in {"Threat", ""} or set(cells[0]) <= {"-"}:
            continue  # header / separator
        names.add(cells[0])
    return names


def test_threat_table_matches_the_canonical_threat_set() -> None:
    """The threat table enumerates the canonical threats -- no more, no less."""
    found = _threat_table_names()
    assert found == EXPECTED_THREATS, (
        "threat table drifted from the canonical threat set; "
        f"missing: {sorted(EXPECTED_THREATS - found)}; "
        f"unexpected: {sorted(found - EXPECTED_THREATS)}"
    )


def test_reconciliation_maps_every_threat_to_valid_adversaries() -> None:
    """Every canonical threat is mapped to >=1 adversary in ADV1..ADV14."""
    recon = _section(_read(), "### Reconciliation — each named threat maps to ≥1 adversary")

    mapped: dict[str, set[str]] = {}
    for line in recon.splitlines():
        if not line.startswith("|"):
            continue
        cells = _cells(line)
        if len(cells) < 2 or cells[0] in {"Named threat", ""} or set(cells[0]) <= {"-"}:
            continue  # header / separator
        threat = cells[0]
        advs = set(re.findall(r"ADV\d+", " ".join(cells[1:])))
        mapped[threat] = advs

    # Both directions: a threat with no reconciliation row, and a reconciliation
    # row naming a threat the table does not carry, are each drift.
    unmapped = sorted(EXPECTED_THREATS - set(mapped))
    assert not unmapped, f"threats missing from the reconciliation table: {unmapped}"
    unknown = sorted(set(mapped) - EXPECTED_THREATS)
    assert not unknown, f"reconciliation maps threats absent from the threat table: {unknown}"

    for threat, advs in mapped.items():
        assert advs, f"threat {threat!r} maps to no adversary"
        bad = advs - EXPECTED_ADVERSARIES
        assert not bad, f"threat {threat!r} maps to unknown adversaries {sorted(bad)}"


def test_executor_bypass_reconciles_to_adv9() -> None:
    """The keystone reconciliation edge: Executor bypass is owned by ADV9."""
    recon = _section(_read(), "### Reconciliation — each named threat maps to ≥1 adversary")
    row = next(
        (ln for ln in recon.splitlines() if ln.startswith("| Executor bypass |")),
        None,
    )
    assert row is not None, "Executor bypass row missing from reconciliation"
    assert "ADV9" in row, "Executor bypass must reconcile to ADV9 (complete-mediation keystone)"


def _num(adv: str) -> int:
    return int(adv.removeprefix("ADV"))
