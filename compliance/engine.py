#!/usr/bin/env python3
"""Compliance mapping engine for ACGS.

Reads compliance/control-mapping.json, validates its structure, checks that
every evidence source exists in the working tree, optionally executes each
mapping's verification command, and generates the Compliance Readiness Report.

This engine produces a self-assessment artifact. It does not and cannot make
ACGS "compliant"; see the disclaimer embedded in the mapping file.

Usage:
    python3 compliance/engine.py validate            # schema + evidence checks
    python3 compliance/engine.py report              # write readiness report
    python3 compliance/engine.py report --run        # also run verification commands (slow)

Stdlib only, by design (matches gove-zone's zero-runtime-deps posture).
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MAPPING_PATH = REPO_ROOT / "compliance" / "control-mapping.json"
REPORT_PATH = REPO_ROOT / "compliance" / "COMPLIANCE_READINESS_REPORT.md"

REQUIRED_ENTRY_FIELDS = ("id", "requirement", "evidence_source", "verification_method", "status")
ALLOWED_STATUSES = ("implemented", "opt-in", "partial", "operator-owned", "gap", "not-applicable")
# Statuses that count toward the "runtime evidence available" readiness ratio.
EVIDENCE_BEARING = ("implemented", "opt-in", "partial")
NON_PATH_EVIDENCE = ("none",)
NON_COMMAND_METHODS = ("none",)


def load_mapping(path: Path = MAPPING_PATH) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def validate_schema(mapping: dict) -> list[str]:
    """Return a list of schema problems (empty = valid)."""
    problems: list[str] = []
    for key in ("version", "disclaimer", "controls", "frameworks"):
        if key not in mapping:
            problems.append(f"missing top-level key: {key}")
    controls = set(mapping.get("controls", {}))
    seen_ids: set[str] = set()
    for fw_key, fw in mapping.get("frameworks", {}).items():
        if "requirements" not in fw:
            problems.append(f"{fw_key}: missing 'requirements'")
            continue
        for entry in fw["requirements"]:
            eid = entry.get("id", "<no id>")
            for field in REQUIRED_ENTRY_FIELDS:
                if not entry.get(field):
                    problems.append(f"{fw_key}/{eid}: missing field '{field}'")
            if eid in seen_ids:
                problems.append(f"duplicate requirement id: {eid}")
            seen_ids.add(eid)
            if entry.get("status") not in ALLOWED_STATUSES:
                problems.append(
                    f"{fw_key}/{eid}: status '{entry.get('status')}' not in {ALLOWED_STATUSES}"
                )
            for ctrl in entry.get("acgs_controls", []):
                if ctrl not in controls:
                    problems.append(f"{fw_key}/{eid}: unknown control '{ctrl}'")
    return problems


def _missing_paths(src: str) -> list[str]:
    if src in NON_PATH_EVIDENCE:
        return []
    return [p.strip() for p in src.split(",") if p.strip() and not (REPO_ROOT / p.strip()).exists()]


def check_evidence_paths(mapping: dict) -> dict[str, list[str]]:
    """Map requirement/control id -> evidence paths missing from the working tree."""
    missing: dict[str, list[str]] = {}
    for ctrl_id, ctrl in mapping["controls"].items():
        gone = _missing_paths(ctrl["evidence"])
        if gone:
            missing[f"control:{ctrl_id}"] = gone
    for fw in mapping["frameworks"].values():
        for entry in fw["requirements"]:
            gone = _missing_paths(entry["evidence_source"])
            if gone:
                missing[entry["id"]] = gone
    return missing


def run_verifications(mapping: dict) -> dict[str, dict]:
    """Execute each unique runnable verification command once; map id -> result.

    Trust boundary: verification_method strings are repo-controlled content from
    control-mapping.json — same trust class as a Makefile or CI config. shell=False
    with shlex tokenization prevents shell-metacharacter injection, but --run will
    execute whatever a future edit to the mapping puts here; review mapping diffs
    accordingly.
    """
    results: dict[str, dict] = {}
    command_cache: dict[str, dict] = {}
    for fw in mapping["frameworks"].values():
        for entry in fw["requirements"]:
            method = entry["verification_method"]
            if method in NON_COMMAND_METHODS or method.startswith("documentation review"):
                results[entry["id"]] = {"ran": False, "reason": method}
                continue
            if method not in command_cache:
                proc = subprocess.run(
                    shlex.split(method),
                    cwd=REPO_ROOT,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                command_cache[method] = {
                    "ran": True,
                    "exit_code": proc.returncode,
                    "tail": (proc.stdout + proc.stderr).strip().splitlines()[-1:],
                }
            results[entry["id"]] = command_cache[method]
    return results


def summarize(mapping: dict) -> dict[str, dict]:
    """Per-framework status counts and evidence ratio."""
    summary: dict[str, dict] = {}
    for fw_key, fw in mapping["frameworks"].items():
        counts = {status: 0 for status in ALLOWED_STATUSES}
        for entry in fw["requirements"]:
            counts[entry["status"]] += 1
        applicable = sum(counts[s] for s in ALLOWED_STATUSES if s != "not-applicable")
        evidence = sum(counts[s] for s in EVIDENCE_BEARING)
        summary[fw_key] = {
            "name": fw["name"],
            "counts": counts,
            "applicable": applicable,
            "evidence_bearing": evidence,
            "ratio": (evidence / applicable) if applicable else 0.0,
        }
    return summary


def _git_context() -> str:
    try:
        branch = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        sha = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        return f"`{branch}` @ `{sha}`"
    except Exception:  # report generation must not die on git absence
        return "unknown checkout"


def generate_report(
    mapping: dict,
    missing: dict[str, list[str]],
    verifications: dict[str, dict] | None,
) -> str:
    summary = summarize(mapping)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []
    lines.append("# Compliance Readiness Report — ACGS")
    lines.append("")
    lines.append(f"> Generated by `compliance/engine.py` on {now} from {_git_context()}.")
    lines.append("> Regenerate with `python3 compliance/engine.py report` — do not hand-edit.")
    lines.append("")
    lines.append("## Scope and honesty disclaimer")
    lines.append("")
    lines.append(mapping["disclaimer"])
    lines.append("")
    lines.append("**Not compliance-certified. Not regulator-approved. Not an audit result.**")
    lines.append("A status below means runtime evidence exists in this repository toward the")
    lines.append("requirement — nothing more.")
    lines.append("")

    lines.append("## Readiness summary")
    lines.append("")
    lines.append(
        "| Framework | Requirements | Implemented | Opt-in | Partial "
        "| Operator-owned | Gap | N/A | Evidence-bearing |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for fw in summary.values():
        c = fw["counts"]
        lines.append(
            f"| {fw['name'].split(' — ')[0].split(' (')[0]} | {sum(c.values())} "
            f"| {c['implemented']} | {c['opt-in']} | {c['partial']} | {c['operator-owned']} "
            f"| {c['gap']} | {c['not-applicable']} "
            f"| {fw['evidence_bearing']}/{fw['applicable']} ({fw['ratio']:.0%}) |"
        )
    lines.append("")
    lines.append("Status vocabulary:")
    for status, meaning in mapping["status_vocabulary"].items():
        lines.append(f"- **{status}** — {meaning}")
    lines.append("")

    for fw in mapping["frameworks"].values():
        lines.append(f"## {fw['name']}")
        lines.append("")
        if fw.get("scope_note"):
            lines.append(f"> {fw['scope_note']}")
            lines.append("")
        lines.append("| ID | Requirement | ACGS controls | Status | Limitation |")
        lines.append("|---|---|---|---|---|")
        for entry in fw["requirements"]:
            ctrls = ", ".join(entry.get("acgs_controls", [])) or "—"
            lines.append(
                f"| {entry['id']} | {entry['requirement']} | {ctrls} "
                f"| {entry['status']} | {entry.get('limitation', '')} |"
            )
        lines.append("")

    lines.append("## Evidence integrity check")
    lines.append("")
    if missing:
        lines.append("Evidence sources referenced by the mapping but **missing on this checkout**:")
        lines.append("")
        for rid, paths in sorted(missing.items()):
            lines.append(f"- `{rid}`: {', '.join(f'`{p}`' for p in paths)}")
        lines.append("")
        lines.append("Missing evidence usually means this checkout is behind the branch where the")
        lines.append("control landed. Treat the affected rows as unverified here, not as absent.")
    else:
        lines.append("All evidence source paths referenced by the mapping exist on this checkout.")
    lines.append("")

    lines.append("## Verification commands")
    lines.append("")
    if verifications is None:
        lines.append("Verification commands were **not executed** for this report")
        lines.append("(`--run` not passed). Each mapping row carries a runnable")
        lines.append("`verification_method`; run `python3 compliance/engine.py report --run`")
        lines.append("to execute them and embed pass/fail results.")
    else:
        lines.append("| Requirement | Ran | Result |")
        lines.append("|---|---|---|")
        for rid, res in sorted(verifications.items()):
            if res.get("ran"):
                verdict = "pass" if res["exit_code"] == 0 else f"FAIL (exit {res['exit_code']})"
                tail = res["tail"][0] if res["tail"] else ""
                lines.append(f"| {rid} | yes | {verdict} — `{tail}` |")
            else:
                lines.append(f"| {rid} | no | {res['reason']} |")
    lines.append("")

    lines.append("## Standing limitations (load-bearing — read before citing)")
    lines.append("")
    lines.append("Inherited from `docs/COMPLIANCE_CROSSWALK.md`:")
    lines.append("")
    lines.append(
        "1. **Unsigned by default** — default verification checks only the recomputable "
        "SHA-256 receipt hash; signing closes this only when engaged."
    )
    lines.append("2. **Anti-replay and full-argument replay are opt-in.**")
    lines.append(
        "3. **Executor-bypass is possible** — controls bind only to calls routed through "
        "the governed executor; handler wiring is integrator-owned."
    )
    lines.append(
        "4. **Identity is opaque strings, not IAM/PKI** — authentication, key custody, "
        "and revocation are operator responsibilities."
    )
    lines.append(
        "5. **Audit is local JSONL, tamper-evident not tamper-proof** — off-host/WORM "
        "durability and retention (EU AI Act Art. 19 / Art. 26(6)) are operator concerns."
    )
    lines.append("6. **No policy lifecycle/revocation registry** beyond id+hash binding.")
    lines.append(
        "7. **Not certified** — not production-certified, not compliance-certified, "
        "not regulator-approved (`docs/CLAIMS.md` rows 27-33)."
    )
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="validate mapping schema and evidence paths")
    report_p = sub.add_parser("report", help="generate the Compliance Readiness Report")
    report_p.add_argument("--run", action="store_true", help="execute verification commands (slow)")
    args = parser.parse_args(argv)

    mapping = load_mapping()
    problems = validate_schema(mapping)
    if problems:
        for p in problems:
            print(f"SCHEMA: {p}", file=sys.stderr)
        return 1
    missing = check_evidence_paths(mapping)

    if args.command == "validate":
        total = sum(len(fw["requirements"]) for fw in mapping["frameworks"].values())
        print(f"schema: OK ({total} requirements, {len(mapping['controls'])} controls)")
        if missing:
            for rid, paths in sorted(missing.items()):
                print(f"evidence MISSING [{rid}]: {', '.join(paths)}")
            print(f"evidence: {len(missing)} requirement(s) with missing paths on this checkout")
        else:
            print("evidence: all paths present")
        return 0

    verifications = run_verifications(mapping) if args.run else None
    if (
        verifications is None
        and REPORT_PATH.exists()
        and "| yes |" in REPORT_PATH.read_text(encoding="utf-8")
    ):
        print(
            "warning: overwriting a report that contained executed verification "
            "results; use --run to regenerate them",
            file=sys.stderr,
        )
    REPORT_PATH.write_text(generate_report(mapping, missing, verifications), encoding="utf-8")
    print(f"wrote {REPORT_PATH.relative_to(REPO_ROOT)}")
    if missing:
        print(f"note: {len(missing)} requirement(s) have missing evidence paths (see report)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
