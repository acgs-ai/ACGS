#!/usr/bin/env bash
# scripts/bench.sh — repo-local pytest pass-rate benchmark
# - No network. No secrets. No deploys.
# - Fail-closed: total==0 or unparseable output exits with code 2 and harness_error.
# - Tracked .acgs/audit.jsonl is treated as a fixture and not deleted.
set -euo pipefail
cd "$(dirname "$0")/.."

# Do not delete tracked evidence/fixtures.
if git ls-files --error-unmatch .acgs/audit.jsonl >/dev/null 2>&1; then
  printf '{"pass_rate":0,"passed":0,"failed":0,"errors":0,"skipped":0,"total":0,"harness_error":"tracked_audit_log_would_be_deleted"}\n'
  exit 2
fi

rm -f .acgs/audit.jsonl .acgs/audit.jsonl.lock

TMP="$(mktemp)"
set +e
python -m pytest --tb=no -q --no-header >"$TMP" 2>&1
PYTEST_STATUS=$?
set -e

cat "$TMP" >&2

python - "$TMP" "$PYTEST_STATUS" <<'PY'
import json
import re
import sys

path = sys.argv[1]
pytest_status = int(sys.argv[2])

text = open(path, encoding="utf-8", errors="replace").read()

def count(label: str) -> int:
    matches = re.findall(rf"(\d+)\s+{label}s?\b", text)
    return int(matches[-1]) if matches else 0

passed = count("passed")
failed = count("failed")
errors = count("error")
skipped = count("skipped")
xfailed = count("xfailed")
xpassed = count("xpassed")

total = passed + failed + errors + skipped + xfailed + xpassed

if total == 0:
    print(json.dumps({
        "pass_rate": 0,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
        "xfailed": xfailed,
        "xpassed": xpassed,
        "total": total,
        "pytest_exit_code": pytest_status,
        "harness_error": "no_tests_or_unparseable_pytest_output",
    }, sort_keys=True))
    sys.exit(2)

print(json.dumps({
    "pass_rate": round(passed / total, 6),
    "passed": passed,
    "failed": failed,
    "errors": errors,
    "skipped": skipped,
    "xfailed": xfailed,
    "xpassed": xpassed,
    "total": total,
    "pytest_exit_code": pytest_status,
}, sort_keys=True))
PY
