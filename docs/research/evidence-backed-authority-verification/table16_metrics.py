#!/usr/bin/env python3
"""Recompute and verify every value published in paper Table 16."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import privilege_context

HERE = Path(__file__).resolve().parent
PAPER = HERE / "paper.md"
RUNTIME_FILES = (
    "container_launch.py",
    "deployment.py",
    "v3_authority.py",
    "v3_client.py",
)


def _load(name: str) -> dict:
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def _line_count(paths: list[Path]) -> int:
    return sum(len(path.read_text(encoding="utf-8").splitlines()) for path in paths)


def metrics() -> dict[str, object]:
    topology = _load("PRIVILEGE_TOPOLOGY_FINAL.json")
    verification = _load("verification_result.json")
    operator = _load("OPERATOR_EVIDENCE_CHECKLIST.json")
    decision = _load("CUTOVER_DECISION.json")
    paths = topology["paths"]
    classifications = [entry["classification"] for entry in paths.values()]
    setuid = {path_id: entry for path_id, entry in paths.items() if path_id.startswith("setuid:")}

    def setuid_count(*, match: bool, bounded: bool) -> int:
        total = 0
        for entry in setuid.values():
            integrity_match = entry.get("evidence", {}).get("integrity") == "MATCH"
            is_bounded = entry["classification"] == "NON_ROOT_EQUIVALENT"
            total += integrity_match is match and is_bounded is bounded
        return total

    history = [
        json.loads(line)
        for line in (HERE / "run_history.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    python_files = sorted(HERE.rglob("*.py"))
    test_files = [path for path in python_files if "tests" in path.parts]
    runtime_files = [HERE / name for name in RUNTIME_FILES]
    non_runtime = [path for path in python_files if path not in runtime_files]
    digests = {row["evidence_digest"] for row in history}
    final_four = (
        len(history) >= 4
        and len({(row["verdict"], row["evidence_digest"]) for row in history[-4:]}) == 1
    )
    return {
        "Authority paths measured": len(paths),
        "ROOT_EQUIVALENT": classifications.count("ROOT_EQUIVALENT"),
        "NON_ROOT_EQUIVALENT": classifications.count("NON_ROOT_EQUIVALENT"),
        "REQUIRES_OPERATOR_EVIDENCE": classifications.count("REQUIRES_OPERATOR_EVIDENCE"),
        "NOT_PRESENT": classifications.count("NOT_PRESENT"),
        "Blocking paths": len(topology["blocking_paths"]),
        "Surfaces enumerated": len({path_id.split(":", 1)[0] for path_id in paths}),
        "File-capability paths": sum(path_id.startswith("filecaps:") for path_id in paths),
        "setuid paths": len(setuid),
        "setuid digest MATCH, bounded": setuid_count(match=True, bounded=True),
        "setuid digest MATCH, unresolved": setuid_count(match=True, bounded=False),
        "setuid no match, bounded": setuid_count(match=False, bounded=True),
        "setuid no match, unresolved": setuid_count(match=False, bounded=False),
        "Measured as host identity": privilege_context.is_host_representative(
            topology["measurement_context"]
        ),
        "Conditions verified": len(verification["conditions"]),
        "Conditions met": sum(
            entry.get("met") is True for entry in verification["conditions"].values()
        ),
        "Operator-evidence items": operator["counts"]["total"],
        "…requiring privileged access": operator["counts"]["requires_privileged_access"],
        "…requiring analysis only": operator["counts"]["analysis_only_no_privilege_needed"],
        "authority_exclusivity_proven": decision["authority_exclusivity_proven"],
        "Closure gates evaluated": len(decision["closure_gates"]),
        "Runs recorded": len(history),
        "Distinct digests over those runs": len(digests),
        "Final four runs identical": final_four,
        "Evidence digest": verification["evidence_digest"],
        "Shipped non-runtime Python lines": _line_count(non_runtime),
        "...of which tests": _line_count(test_files),
        "Runtime subject Python lines": _line_count(runtime_files),
    }


ROW = re.compile(
    r"^(?P<prefix>\| (?P<claim>[^|]+?) \| )"
    r"`(?P<value>[^`]*)`(?P<suffix> \| .*)$"
)


def update_paper(text: str) -> str:
    values = metrics()
    found: set[str] = set()
    output = []
    for line in text.splitlines():
        match = ROW.match(line)
        claim = match.group("claim").strip() if match else None
        if claim in values:
            found.add(claim)
            line = f"{match.group('prefix')}`{values[claim]}`{match.group('suffix')}"
        output.append(line)
    missing = set(values) - found
    if missing:
        raise ValueError(f"Table 16 is missing metric rows: {sorted(missing)}")
    return "\n".join(output) + "\n"


def verify_paper() -> tuple[bool, list[str]]:
    original = PAPER.read_text(encoding="utf-8")
    updated = update_paper(original)
    if original == updated:
        return True, []
    errors = []
    original_lines = original.splitlines()
    updated_lines = updated.splitlines()
    for before, after in zip(original_lines, updated_lines, strict=True):
        if before != after:
            errors.append(f"stale Table 16 row: {before} -> {after}")
    return False, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.write:
        PAPER.write_text(
            update_paper(PAPER.read_text(encoding="utf-8")),
            encoding="utf-8",
        )
    ok, errors = verify_paper()
    if not ok:
        print("\n".join(errors))
        return 2
    print(f"Table 16 verified: {len(metrics())} recomputed values")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
