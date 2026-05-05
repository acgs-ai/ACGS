#!/usr/bin/env bash
# scripts/bench-coverage.sh - severity-weighted regression coverage benchmark.
# - No network. No secrets. No deploys.
# - Emits exactly one JSON object on stdout; pytest output goes to stderr.
# - Fails closed for seed drift, empty test collection, and invalid markers.
set -euo pipefail
cd "$(dirname "$0")/.."

SEED_PATH="tests/regression_seed.json"
PHASE_A_NODEIDS_PATH=".omc/self-improve/topics/eval-regression-coverage-hardening/state/phase_a_nodeids.json"

if git ls-files --error-unmatch .acgs/audit.jsonl >/dev/null 2>&1; then
  printf '{"errors":0,"failed":0,"harness_error":"tracked_audit_log_would_be_deleted","pass_rate":0,"passed":0,"pytest_exit_code":2,"regression_coverage_points":0,"regression_coverage_score":0,"seed_baseline_points_recomputed":0,"skipped":0,"total":0,"xfailed":0,"xpassed":0}\n'
  exit 2
fi

rm -f .acgs/audit.jsonl .acgs/audit.jsonl.lock

TMP_DIR="$(mktemp -d)"
TMP_OUT="$TMP_DIR/pytest.out"
PLUGIN_REPORT="$TMP_DIR/plugin-report.json"
PLUGIN="$TMP_DIR/bench_coverage_plugin.py"
trap 'rm -rf "$TMP_DIR"' EXIT

python - "$SEED_PATH" <<'PY'
import json
import sys
from pathlib import Path

seed_path = Path(sys.argv[1])

def emit_error(error: str, **extra: object) -> None:
    payload = {
        "pass_rate": 0,
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "total": 0,
        "pytest_exit_code": 2,
        "regression_coverage_points": 0,
        "regression_coverage_score": 0,
        "seed_baseline_points_recomputed": 0,
        "harness_error": error,
    }
    payload.update(extra)
    print(json.dumps(payload, sort_keys=True))

try:
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
except Exception as exc:
    emit_error("seed_unreadable", detail=str(exc))
    sys.exit(2)

try:
    weights = seed["severity_weights"]
    recomputed = sum(
        weights[issue["severity"]] * len(issue.get("seed_tests", []))
        for issue in seed.get("issues", [])
        if issue.get("contributes") is True
    )
    declared = seed["seed_baseline_points"]
except Exception as exc:
    emit_error("seed_schema_invalid", detail=str(exc))
    sys.exit(2)

if recomputed != declared:
    emit_error("seed_baseline_drift", declared=declared, recomputed=recomputed)
    sys.exit(2)
PY

cat >"$PLUGIN" <<'PY'
import json
import os
from pathlib import Path

REPORT_PATH = Path(os.environ["BENCH_COVERAGE_PLUGIN_REPORT"])
_ITEMS = {}

def _marker_payload(marker):
    if marker is None:
        return None
    keys = ("pr", "severity", "issue", "coverage_angle")
    payload = {}
    for index, key in enumerate(keys):
        if index < len(marker.args):
            payload[key] = marker.args[index]
    payload.update(marker.kwargs)
    return payload

def pytest_collection_modifyitems(config, items):
    items.sort(key=lambda item: item.nodeid)
    for item in items:
        marker = item.get_closest_marker("regression")
        _ITEMS[item.nodeid] = {
            "nodeid": item.nodeid,
            "marker": _marker_payload(marker),
            "outcome": None,
        }

def pytest_runtest_logreport(report):
    item = _ITEMS.setdefault(
        report.nodeid,
        {"nodeid": report.nodeid, "marker": None, "outcome": None},
    )
    was_xfail = hasattr(report, "wasxfail")
    if was_xfail and report.outcome == "skipped":
        item["outcome"] = "xfailed"
    elif was_xfail and report.outcome in {"passed", "failed"}:
        item["outcome"] = "xpassed"
    elif report.when == "call":
        item["outcome"] = report.outcome
    elif report.outcome in {"failed", "skipped"} and item.get("outcome") is None:
        item["outcome"] = "error" if report.outcome == "failed" else "skipped"

def pytest_sessionfinish(session, exitstatus):
    REPORT_PATH.write_text(
        json.dumps(
            {
                "exitstatus": exitstatus,
                "items": sorted(_ITEMS.values(), key=lambda item: item["nodeid"]),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
PY

set +e
PYTHONPATH="$TMP_DIR${PYTHONPATH:+:$PYTHONPATH}" \
BENCH_COVERAGE_PLUGIN_REPORT="$PLUGIN_REPORT" \
  python -m pytest --tb=no -q --no-header -p bench_coverage_plugin >"$TMP_OUT" 2>&1
PYTEST_STATUS=$?
set -e

cat "$TMP_OUT" >&2

python - "$TMP_OUT" "$PYTEST_STATUS" "$SEED_PATH" "$PLUGIN_REPORT" "$PHASE_A_NODEIDS_PATH" <<'PY'
import json
import re
import sys
from pathlib import Path

pytest_output = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
pytest_status = int(sys.argv[2])
seed_path = Path(sys.argv[3])
plugin_report_path = Path(sys.argv[4])
phase_a_nodeids_path = Path(sys.argv[5])

seed = json.loads(seed_path.read_text(encoding="utf-8"))
weights = seed["severity_weights"]
seed_baseline_points = seed["seed_baseline_points"]
seed_baseline_points_recomputed = sum(
    weights[issue["severity"]] * len(issue.get("seed_tests", []))
    for issue in seed.get("issues", [])
    if issue.get("contributes") is True
)

base_payload = {
    "pass_rate": 0,
    "passed": 0,
    "failed": 0,
    "errors": 0,
    "skipped": 0,
    "xfailed": 0,
    "xpassed": 0,
    "total": 0,
    "pytest_exit_code": pytest_status,
    "regression_coverage_points": 0,
    "regression_coverage_score": 0,
    "seed_baseline_points_recomputed": seed_baseline_points_recomputed,
}

def emit(payload):
    print(json.dumps(payload, sort_keys=True))

def fail(error: str, **extra: object) -> None:
    payload = dict(base_payload)
    payload["harness_error"] = error
    payload.update(extra)
    emit(payload)

def count(label: str) -> int:
    matches = re.findall(rf"(\d+)\s+{label}s?\b", pytest_output)
    return int(matches[-1]) if matches else 0

passed = count("passed")
failed = count("failed")
errors = count("error")
skipped = count("skipped")
xfailed = count("xfailed")
xpassed = count("xpassed")
total = passed + failed + errors + skipped + xfailed + xpassed

base_payload.update(
    {
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
        "xfailed": xfailed,
        "xpassed": xpassed,
        "total": total,
        "pass_rate": round(passed / total, 6) if total else 0,
    }
)

if total == 0:
    fail("no_tests_or_unparseable_pytest_output")
    sys.exit(2)

if seed_baseline_points_recomputed != seed_baseline_points:
    fail(
        "seed_baseline_drift",
        declared=seed_baseline_points,
        recomputed=seed_baseline_points_recomputed,
    )
    sys.exit(2)

try:
    plugin_report = json.loads(plugin_report_path.read_text(encoding="utf-8"))
except Exception as exc:
    fail("plugin_report_unreadable", detail=str(exc))
    sys.exit(2)

issue_by_key = {}
seed_nodeids = set()
for issue in seed.get("issues", []):
    key = (str(issue["pr"]), str(issue["issue"]))
    issue_by_key[key] = issue
    for test in issue.get("seed_tests", []):
        seed_nodeids.add(test["nodeid"])

phase_a_nodeids = set()
if phase_a_nodeids_path.exists():
    try:
        phase_a_nodeids = set(
            json.loads(phase_a_nodeids_path.read_text(encoding="utf-8")).get("nodeids", [])
        )
    except Exception as exc:
        fail("phase_a_nodeids_unreadable", detail=str(exc))
        sys.exit(2)

coverage_angles = {}
points = 0
marker_errors = []
marked_count = 0
phase_b_new_points = 0

for item in plugin_report.get("items", []):
    marker = item.get("marker")
    if not marker:
        continue

    marked_count += 1
    nodeid = item["nodeid"]
    missing = [field for field in ("pr", "severity", "issue", "coverage_angle") if not marker.get(field)]
    if missing:
        marker_errors.append({"nodeid": nodeid, "error": "marker_missing_fields", "fields": missing})
        continue

    key = (str(marker["pr"]), str(marker["issue"]))
    issue = issue_by_key.get(key)
    if issue is None:
        marker_errors.append({"nodeid": nodeid, "error": "unknown_regression_issue", "pr": key[0], "issue": key[1]})
        continue

    if str(marker["severity"]) != str(issue["severity"]):
        marker_errors.append(
            {
                "nodeid": nodeid,
                "error": "severity_mismatch",
                "expected": issue["severity"],
                "actual": marker["severity"],
            }
        )
        continue

    angle_key = key + (str(marker["coverage_angle"]),)
    existing_angle_nodeid = coverage_angles.get(angle_key)
    if existing_angle_nodeid and existing_angle_nodeid != nodeid:
        marker_errors.append(
            {
                "nodeid": nodeid,
                "error": "duplicate_coverage_angle",
                "first_nodeid": existing_angle_nodeid,
                "coverage_angle": marker["coverage_angle"],
            }
        )
        continue
    coverage_angles[angle_key] = nodeid

    outcome = item.get("outcome") or "unknown"
    severity = str(marker["severity"])
    if severity in {"CRIT", "HIGH"} and outcome in {"skipped", "xfailed"}:
        marker_errors.append({"nodeid": nodeid, "error": "crit_high_regression_not_run", "outcome": outcome})
        continue

    if issue.get("contributes") is True and outcome == "passed":
        weight = weights[issue["severity"]]
        points += weight
        if phase_a_nodeids and nodeid not in phase_a_nodeids and nodeid not in seed_nodeids:
            phase_b_new_points += weight

if marker_errors:
    fail("regression_marker_invalid", marker_errors=marker_errors[:20], marker_error_count=len(marker_errors))
    sys.exit(2)

payload = dict(base_payload)
payload.update(
    {
        "regression_coverage_points": points,
        "regression_coverage_score": round(points / seed_baseline_points, 6)
        if seed_baseline_points
        else 0,
        "regression_marked_tests": marked_count,
        "phase_b_new_points": phase_b_new_points,
    }
)
emit(payload)
PY
