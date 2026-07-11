#!/usr/bin/env bash
# Prove P0-EVIDENCE-000 from a detached, fresh, hash-locked sibling.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

die() {
  printf 'CLEAN_SIBLING=FAIL phase=%s reason=%s\n' "${PHASE:-B0}" "$*" >&2
  exit 2
}

phase() {
  PHASE="$1"
  printf 'CLEAN_SIBLING_PHASE=%s\n' "$PHASE"
}

lexists() {
  [[ -e "$1" || -L "$1" ]]
}

reject_lexists() {
  lexists "$1" && die "pre-existing path rejected: $1"
  return 0
}

[[ $# -eq 1 ]] || die 'usage: P=<reviewed-parent> prove_clean_sibling.sh <exact-T-commit>'
T="$1"
[[ "$T" =~ ^[0-9a-f]{40}$ ]] || die 'T must be a lowercase 40-hex commit SHA'
[[ -n "${P:-}" ]] || die 'P must be exported as the reviewed parent commit SHA'
[[ "$P" =~ ^[0-9a-f]{40}$ ]] || die 'P must be a lowercase 40-hex commit SHA'
P0_REVIEWED_BASE='26d11c2c7a8da37937a7c50c642f18edc75c9345'
[[ "$P" == "$P0_REVIEWED_BASE" ]] || die "P0 reviewed parent must be exact $P0_REVIEWED_BASE"
[[ "$P" != "$T" ]] || die 'P and T must be distinct'
for variable in \
  VIRTUAL_ENV PYTHONPATH PYTHONHOME UV_PROJECT_ENVIRONMENT \
  UV_WORKING_DIR UV_CONFIG_FILE UV_ENV_FILE UV_CONSTRAINT \
  UV_BUILD_CONSTRAINT UV_OVERRIDE UV_FIND_LINKS UV_PROJECT UV_PYTHON \
  UV_PYTHON_SEARCH_PATH UV_PYTHON_INSTALL_REGISTRY UV_PYTHON_INSTALL_BIN \
  UV_PYTHON_DOWNLOADS_JSON_URL UV_INSTALL_DIR; do
  [[ -z "${!variable:-}" ]] || die "ambient Python identity variable rejected: $variable"
done

SOURCE_REPO="$(git rev-parse --show-toplevel)"
SOURCE_REPO="$(realpath -e "$SOURCE_REPO")"
[[ "$(realpath -e "${BASH_SOURCE[0]}")" == "$SOURCE_REPO/scripts/evidence/prove_clean_sibling.sh" ]] ||
  die 'prover must execute from its owning repository'
CLEANUP_HELPER="$SOURCE_REPO/scripts/evidence/clean_sibling_cleanup.sh"
[[ "$(realpath -e "$CLEANUP_HELPER")" == "$CLEANUP_HELPER" ]] ||
  die 'clean-sibling cleanup helper is missing or noncanonical'
# shellcheck source=scripts/evidence/clean_sibling_cleanup.sh
source "$CLEANUP_HELPER"
git -C "$SOURCE_REPO" cat-file -e "$T^{commit}" || die 'T commit is unavailable'
git -C "$SOURCE_REPO" cat-file -e "$P^{commit}" || die 'P commit is unavailable'
git -C "$SOURCE_REPO" merge-base --is-ancestor "$P" "$T" ||
  die 'P must be an ancestor of exact T'
[[ -z "$(git -C "$SOURCE_REPO" status --porcelain=v1 --untracked-files=all)" ]] ||
  die 'source repository must be clean before proof'
git -C "$SOURCE_REPO" diff --check "$P..$T" || die 'P..T diff check failed'
[[ "$(uname -m)" == 'x86_64' ]] || die 'lock platform requires x86_64'

TMP_PARENT_RAW="${TMPDIR:-/tmp}"
[[ "$TMP_PARENT_RAW" == /* ]] || die 'TMPDIR must be absolute'
[[ -d "$TMP_PARENT_RAW" && ! -L "$TMP_PARENT_RAW" ]] ||
  die 'TMPDIR must be an existing non-symlink directory'
TMP_PARENT="$(realpath -e "$TMP_PARENT_RAW")"
[[ "$TMP_PARENT_RAW" == "$TMP_PARENT" ]] || die 'TMPDIR must already be canonical'
case "$TMP_PARENT" in
  "$SOURCE_REPO" | "$SOURCE_REPO"/*) die 'TMPDIR must be outside source repository' ;;
esac
# A shell redirection cannot request O_NOFOLLOW. On the first pass, a trusted
# helper opens the canonical caller directory with O_NOFOLLOW|O_DIRECTORY,
# makes that descriptor inheritable, and execs this prover in-place. The same
# descriptor therefore survives from the initial snapshot through EXIT cleanup.
if [[ -z "${ACGS_CLEAN_SIBLING_TMP_FD:-}" ]]; then
  SNAPSHOT_PYTHON=/usr/bin/python3
  [[ -x "$SNAPSHOT_PYTHON" && \
    "$(realpath -e "$SNAPSHOT_PYTHON" 2>/dev/null || true)" == /usr/bin/python3.* ]] ||
    die 'trusted snapshot interpreter /usr/bin/python3 is unavailable'
  PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX= \
    "$SNAPSHOT_PYTHON" - "${BASH_SOURCE[0]}" "$@" <<'PY'
import os
import sys

path = os.environ.get("TMPDIR", "/tmp")
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
except OSError as error:
    print(f"CLEAN_SIBLING=FAIL phase=B0 reason=cannot open caller TMPDIR: {error.strerror}",
          file=sys.stderr)
    raise SystemExit(2)
os.set_inheritable(fd, True)
environment = dict(os.environ)
environment["ACGS_CLEAN_SIBLING_TMP_FD"] = str(fd)
environment["PYTHONDONTWRITEBYTECODE"] = "1"
environment.pop("PYTHONPYCACHEPREFIX", None)
os.execve("/bin/bash", ["bash", sys.argv[1], *sys.argv[2:]], environment)
PY
  exit "$?"
fi
TMP_PARENT_DEVICE=''
TMP_PARENT_INODE=''
TMP_PARENT_UID=''
TMP_PARENT_MODE=''
TMP_PARENT_FD="$ACGS_CLEAN_SIBLING_TMP_FD"
SNAPSHOT_PYTHON=/usr/bin/python3
[[ -x "$SNAPSHOT_PYTHON" && \
  "$(realpath -e "$SNAPSHOT_PYTHON" 2>/dev/null || true)" == /usr/bin/python3.* ]] ||
  die 'trusted snapshot interpreter /usr/bin/python3 is unavailable'
[[ "$TMP_PARENT_FD" =~ ^[0-9]+$ && -d "/proc/$$/fd/$TMP_PARENT_FD" ]] ||
  die 'inherited caller TMPDIR descriptor is invalid'
IFS=: read -r TMP_PARENT_DEVICE TMP_PARENT_INODE TMP_PARENT_UID TMP_PARENT_MODE < <(
  stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$TMP_PARENT_FD"
)
[[ "$TMP_PARENT_UID" == "$(id -u)" && "$TMP_PARENT_MODE" == 700 ]] ||
  die 'TMPDIR must be caller-owned mode 0700'
TMP_PARENT_STAT_BEFORE="$TMP_PARENT_DEVICE:$TMP_PARENT_INODE:$TMP_PARENT_UID:$TMP_PARENT_MODE"
[[ "$(stat -c '%d:%i:%u:%a' -- "$TMP_PARENT")" == "$TMP_PARENT_STAT_BEFORE" ]] ||
  die 'TMPDIR path does not refer to authenticated descriptor'
TMP_PARENT_ENTRIES_BEFORE="$(clean_sibling_snapshot_direct_entries \
  "$TMP_PARENT_FD" "$TMP_PARENT_STAT_BEFORE" "$TMP_PARENT")" ||
  die 'cannot snapshot caller TMPDIR direct entries'
WORKTREES_BEFORE="$(git -C "$SOURCE_REPO" worktree list --porcelain)"
SOURCE_STATUS_BEFORE="$(git -C "$SOURCE_REPO" status --porcelain=v1 --untracked-files=all)"
export PYTHONDONTWRITEBYTECODE=1
TMP_ROOT=''
OWNER_MARKER=''
TMP_ROOT_DEVICE=''
TMP_ROOT_INODE=''
TMP_ROOT_UID=''
TMP_ROOT_MODE=''
WORKTREE=''
EVIDENCE_ROOT=''
NODE_ID='P0-EVIDENCE-000'
NODE_EVIDENCE=''
SCRATCH_ROOT=''
RUNTIME_TMP=''
UV_CACHE_DIR=''
UV_PYTHON_BIN_DIR=''
UV_TOOL_DIR=''
UV_TOOL_BIN_DIR=''
UV_PYTHON_CACHE_DIR=''
UV_CREDENTIALS_DIR=''
WORKTREE_ADDED=0
PROOF_COMPLETE=0
TRANSCRIPT_RECORDS=0
R=''

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  clean_sibling_cleanup "$status"
  exit $?
}

TMP_ROOT="$(mktemp -d "$TMP_PARENT/acgs-p0-evidence.XXXXXXXX")"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
TMP_ROOT="$(realpath -e "$TMP_ROOT")"
case "$TMP_ROOT" in
  "$TMP_PARENT"/acgs-p0-evidence.*) ;;
  *) die "mktemp returned an unexpected path: $TMP_ROOT" ;;
esac
[[ "$(stat -c '%d:%i:%u:%a' -- "$TMP_PARENT")" == "$TMP_PARENT_STAT_BEFORE" ]] ||
  die 'TMPDIR changed while creating owned proof root'
IFS=: read -r TMP_ROOT_DEVICE TMP_ROOT_INODE TMP_ROOT_UID TMP_ROOT_MODE < <(
  stat -c '%d:%i:%u:%a' -- "$TMP_ROOT"
)
[[ "$TMP_ROOT_UID" == "$(id -u)" && "$TMP_ROOT_MODE" == 700 ]] ||
  die 'mktemp root ownership/mode is unsafe'
OWNER_MARKER="$TMP_ROOT/.acgs-clean-sibling-owned"
(set -o noclobber; printf '%s\n' "$$" >"$OWNER_MARKER") ||
  die 'cannot create exclusive clean-sibling ownership marker'
WORKTREE="$TMP_ROOT/product"
EVIDENCE_ROOT="$TMP_ROOT/evidence"
NODE_EVIDENCE="$EVIDENCE_ROOT/$NODE_ID"
SCRATCH_ROOT="$TMP_ROOT/scratch"
RUNTIME_TMP="$SCRATCH_ROOT/tmp"
UV_CACHE_DIR="$SCRATCH_ROOT/uv-cache"

phase B0
for path in "$WORKTREE" "$EVIDENCE_ROOT" "$SCRATCH_ROOT"; do
  reject_lexists "$path"
done
mkdir -m 700 "$SCRATCH_ROOT"
mkdir -m 700 \
  "$RUNTIME_TMP" \
  "$UV_CACHE_DIR" \
  "$SCRATCH_ROOT/home" \
  "$SCRATCH_ROOT/xdg-cache" \
  "$SCRATCH_ROOT/xdg-config" \
  "$SCRATCH_ROOT/xdg-data" \
  "$SCRATCH_ROOT/xdg-state" \
  "$SCRATCH_ROOT/pytest-temp" \
  "$SCRATCH_ROOT/mypy-cache" \
  "$SCRATCH_ROOT/ruff-cache" \
  "$SCRATCH_ROOT/coverage" \
  "$SCRATCH_ROOT/uv-python" \
  "$SCRATCH_ROOT/uv-python-bin" \
  "$SCRATCH_ROOT/uv-tools" \
  "$SCRATCH_ROOT/uv-tool-bin" \
  "$SCRATCH_ROOT/uv-python-cache" \
  "$SCRATCH_ROOT/uv-credentials" \
  "$SCRATCH_ROOT/python-user" \
  "$SCRATCH_ROOT/pycache" \
  "$SCRATCH_ROOT/pip-cache" \
  "$SCRATCH_ROOT/hatch-cache"
[[ -z "$(find "$UV_CACHE_DIR" -mindepth 1 -print -quit)" ]] || die 'UV cache must begin empty'
export TMPDIR="$RUNTIME_TMP"
export TMP="$RUNTIME_TMP"
export TEMP="$RUNTIME_TMP"
export HOME="$SCRATCH_ROOT/home"
export XDG_CACHE_HOME="$SCRATCH_ROOT/xdg-cache"
export XDG_CONFIG_HOME="$SCRATCH_ROOT/xdg-config"
export XDG_DATA_HOME="$SCRATCH_ROOT/xdg-data"
export XDG_STATE_HOME="$SCRATCH_ROOT/xdg-state"
export PYTEST_DEBUG_TEMPROOT="$SCRATCH_ROOT/pytest-temp"
export MYPY_CACHE_DIR="$SCRATCH_ROOT/mypy-cache"
export RUFF_CACHE_DIR="$SCRATCH_ROOT/ruff-cache"
export COVERAGE_FILE="$SCRATCH_ROOT/coverage/.coverage"
export UV_PYTHON_INSTALL_DIR="$SCRATCH_ROOT/uv-python"
export UV_PYTHON_BIN_DIR="$SCRATCH_ROOT/uv-python-bin"
export UV_TOOL_DIR="$SCRATCH_ROOT/uv-tools"
export UV_TOOL_BIN_DIR="$SCRATCH_ROOT/uv-tool-bin"
export UV_PYTHON_CACHE_DIR="$SCRATCH_ROOT/uv-python-cache"
export UV_CREDENTIALS_DIR="$SCRATCH_ROOT/uv-credentials"
export UV_NO_CONFIG=1
export UV_NO_ENV_FILE=1
export PYTHONUSERBASE="$SCRATCH_ROOT/python-user"
export PYTHONPYCACHEPREFIX="$SCRATCH_ROOT/pycache"
export PIP_CACHE_DIR="$SCRATCH_ROOT/pip-cache"
export HATCH_CACHE_DIR="$SCRATCH_ROOT/hatch-cache"
export UV_CACHE_DIR
[[ "$(uv --version | awk '{print $2}')" == '0.11.19' ]] || die 'uv must be exactly 0.11.19'
WORKTREE_ADDED=1
git -C "$SOURCE_REPO" worktree add --detach "$WORKTREE" "$T"
[[ "$(git -C "$WORKTREE" rev-parse HEAD)" == "$T" ]] || die 'detached sibling is not exact T'
[[ -z "$(git -C "$WORKTREE" status --porcelain=v1 --untracked-files=all)" ]] ||
  die 'detached sibling is dirty before bootstrap'
git -C "$WORKTREE" cat-file -e "$P^{commit}" || die 'detached sibling cannot resolve P'
git -C "$WORKTREE" merge-base --is-ancestor "$P" "$T" ||
  die 'detached sibling P/T ancestry mismatch'
git -C "$WORKTREE" diff --check "$P..$T" || die 'detached sibling P..T diff check failed'

export REPO_ROOT="$WORKTREE"
export ACGS_EVIDENCE_ROOT="$EVIDENCE_ROOT"
export NODE_ID
export PYTHONNOUSERSITE=1
export PYTEST_ADDOPTS='-p no:cacheprovider'
export ACGS_TEST_SEED=20260710
export PYTHONHASHSEED=0
export ACGS_PROCESS_SCHEDULE='["single-process"]'
export ACGS_CLOCK_SOURCE='system-utc'
export ACGS_SKIPPED_JSON='[]'
export ACGS_EXTERNAL_JSON='[]'
unset UV_OFFLINE UV_NO_INDEX UV_NO_CACHE RUFF_NO_CACHE
unset VIRTUAL_ENV PYTHONPATH PYTHONHOME UV_PROJECT_ENVIRONMENT

for path in \
  "$WORKTREE/.venv-evidence" \
  "$WORKTREE/packages/acgs-control-plane/.venv" \
  "$WORKTREE/packages/gove-zone/.venv-beta" \
  "$NODE_EVIDENCE"; do
  reject_lexists "$path"
done

phase B1
EXPECTED="$TMP_ROOT/expected-locks"
mkdir "$EXPECTED"
LOCK_FILES=(
  requirements/saas-beta/locks.toml
  requirements/saas-beta/evidence-test.in
  requirements/saas-beta/evidence-test.lock
  requirements/saas-beta/cp-test.in
  requirements/saas-beta/cp-test.lock
  requirements/saas-beta/gz-test.in
  requirements/saas-beta/gz-test.lock
  requirements/saas-beta/bootstrap-by-scope.json
)
for relative in "${LOCK_FILES[@]}"; do
  mkdir -p "$EXPECTED/$(dirname "$relative")"
  cp -- "$WORKTREE/$relative" "$EXPECTED/$relative"
done
(
  cd "$WORKTREE"
  LC_ALL=C TZ=UTC PYTHONHASHSEED=0 uv run --no-project --python 3.11 python \
    scripts/evidence/render_lock_inputs.py --config requirements/saas-beta/locks.toml
  LC_ALL=C TZ=UTC uv pip compile --python-version 3.11 \
    --python-platform x86_64-manylinux_2_28 \
    --exclude-newer 2026-07-10T00:00:00Z --generate-hashes \
    requirements/saas-beta/evidence-test.in \
    --output-file requirements/saas-beta/evidence-test.lock
  LC_ALL=C TZ=UTC uv pip compile --python-version 3.11 \
    --python-platform x86_64-manylinux_2_28 \
    --exclude-newer 2026-07-10T00:00:00Z --generate-hashes \
    requirements/saas-beta/cp-test.in \
    --output-file requirements/saas-beta/cp-test.lock
  LC_ALL=C TZ=UTC uv pip compile --python-version 3.11 \
    --python-platform x86_64-manylinux_2_28 \
    --exclude-newer 2026-07-10T00:00:00Z --generate-hashes \
    requirements/saas-beta/gz-test.in \
    --output-file requirements/saas-beta/gz-test.lock
)
for relative in "${LOCK_FILES[@]}"; do
  cmp --silent "$EXPECTED/$relative" "$WORKTREE/$relative" ||
    die "deterministic render/compile drift: $relative"
done
[[ -z "$(git -C "$WORKTREE" status --porcelain=v1 --untracked-files=all)" ]] ||
  die 'lock regeneration left product-tree drift'

phase B2
uv python install 3.11
uv venv --python 3.11 "$WORKTREE/.venv-evidence"
mkdir -p "$NODE_EVIDENCE"
uv pip sync --python "$WORKTREE/.venv-evidence/bin/python" --require-hashes \
  "$WORKTREE/requirements/saas-beta/evidence-test.lock"
export UV_OFFLINE=1 UV_NO_INDEX=1 UV_NO_CACHE=1
export RUFF_NO_CACHE=true PYTHONDONTWRITEBYTECODE=1
EVIDENCE_PY="$WORKTREE/.venv-evidence/bin/python"
"$EVIDENCE_PY" "$WORKTREE/scripts/evidence/verify_environment.py" \
  --code EVID \
  --lock "$WORKTREE/requirements/saas-beta/evidence-test.lock" \
  --expected-interpreter "$EVIDENCE_PY" \
  --expected-python 3.11 \
  --expected-uv 0.11.19 \
  --require-module-root "$WORKTREE/.venv-evidence" \
  --require 'rfc8785==0.1.4' \
  --require 'cryptography>=42' \
  --require jsonschema \
  --require pytest \
  --output "$NODE_EVIDENCE/environment-EVID.json"
uv pip freeze --python "$EVIDENCE_PY" >"$NODE_EVIDENCE/evidence.freeze"
EVID_GATE=(.venv-evidence/bin/python -m pytest -q \
  tests/saas_beta/test_evidence_bootstrap.py::test_universal_evidence_interpreter_offline)
EVID_GATE_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
(
  cd "$WORKTREE"
  "${EVID_GATE[@]}"
) >"$NODE_EVIDENCE/evid-gate.stdout" 2>"$NODE_EVIDENCE/evid-gate.stderr"
EVID_GATE_FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

precheck_product() {
  local code="$1" interpreter="$2" lock="$3" output="$4"
  UV_OFFLINE=1 UV_NO_INDEX=1 UV_NO_CACHE=1 "$interpreter" -I - "$lock" "$code" <<'PY' >"$output"
import importlib.metadata
import json
import pathlib
import re
import sys

lock = pathlib.Path(sys.argv[1]).resolve(strict=True)
code = sys.argv[2]
text = lock.read_text(encoding="utf-8")
match = re.search(r"^editables==([^\s\\]+)\s+\\$", text, re.MULTILINE)
if match is None or match.group(1) != "0.6" or "--hash=sha256:" not in text[match.end():]:
    raise SystemExit(f"{code} lock lacks exact hashed editables==0.6")
import editables
import hatchling
root = pathlib.Path(sys.prefix).resolve(strict=True)
for module, distribution, expected in (
    (editables, "editables", "0.6"),
    (hatchling, "hatchling", None),
):
    path = pathlib.Path(module.__file__).resolve(strict=True)
    version = importlib.metadata.version(distribution)
    if not path.is_relative_to(root) or (expected is not None and version != expected):
        raise SystemExit(f"{code} helper/backend escaped or drifted: {distribution}")
print(json.dumps({"code": code, "editables": "0.6", "prefix": str(root)}, sort_keys=True))
PY
}

verify_freeze_delta() {
  local code="$1" before="$2" after="$3"
  shift 3
  "$EVIDENCE_PY" - "$code" "$before" "$after" "$@" <<'PY'
import pathlib
import sys

code, before_path, after_path, *allowed_roots = sys.argv[1:]
before = set(pathlib.Path(before_path).read_text(encoding="utf-8").splitlines())
after = set(pathlib.Path(after_path).read_text(encoding="utf-8").splitlines())
removed = before - after
added = after - before
if removed:
    raise SystemExit(f"{code} editable install removed locked distributions: {sorted(removed)}")
expected = {f"-e file://{pathlib.Path(root).resolve(strict=True)}" for root in allowed_roots}
if added != expected:
    raise SystemExit(f"{code} freeze delta mismatch: added={sorted(added)} expected={sorted(expected)}")
PY
}

phase B3
uv venv --python 3.11 "$WORKTREE/packages/acgs-control-plane/.venv"
env -u UV_OFFLINE -u UV_NO_INDEX -u UV_NO_CACHE uv pip sync \
  --python "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" --require-hashes \
  "$WORKTREE/requirements/saas-beta/cp-test.lock"
precheck_product CP \
  "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" \
  "$WORKTREE/requirements/saas-beta/cp-test.lock" \
  "$NODE_EVIDENCE/cp-editables-version.txt"
uv pip freeze --python "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" \
  >"$NODE_EVIDENCE/cp-pre-editable.freeze"

uv venv --python 3.11 "$WORKTREE/packages/gove-zone/.venv-beta"
env -u UV_OFFLINE -u UV_NO_INDEX -u UV_NO_CACHE uv pip sync \
  --python "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" --require-hashes \
  "$WORKTREE/requirements/saas-beta/gz-test.lock"
precheck_product GZ \
  "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" \
  "$WORKTREE/requirements/saas-beta/gz-test.lock" \
  "$NODE_EVIDENCE/gz-editables-version.txt"
uv pip freeze --python "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" \
  >"$NODE_EVIDENCE/gz-pre-editable.freeze"

phase B4
uv pip install --python "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" \
  --offline --no-index --no-cache --no-build-isolation --no-deps \
  --editable "$WORKTREE/packages/gove-zone" \
  --editable "$WORKTREE/packages/acgs-control-plane"
uv pip freeze --python "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" \
  >"$NODE_EVIDENCE/cp-post-editable.freeze"
verify_freeze_delta CP \
  "$NODE_EVIDENCE/cp-pre-editable.freeze" \
  "$NODE_EVIDENCE/cp-post-editable.freeze" \
  "$WORKTREE/packages/gove-zone" "$WORKTREE/packages/acgs-control-plane"

uv pip install --python "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" \
  --offline --no-index --no-cache --no-build-isolation --no-deps \
  --editable "$WORKTREE/packages/gove-zone"
uv pip freeze --python "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" \
  >"$NODE_EVIDENCE/gz-post-editable.freeze"
verify_freeze_delta GZ \
  "$NODE_EVIDENCE/gz-pre-editable.freeze" \
  "$NODE_EVIDENCE/gz-post-editable.freeze" \
  "$WORKTREE/packages/gove-zone"

append_record() {
  local started="$1" finished="$2" stdout_file="$3" stderr_file="$4" selector="$5"
  shift 5
  "$EVIDENCE_PY" - "$WORKTREE/scripts/evidence" "$NODE_EVIDENCE/transcript.jsonl" \
    "$started" "$finished" "$stdout_file" "$stderr_file" "$selector" "$@" <<'PY'
import hashlib
import pathlib
import sys

script_root, target, started, finished, stdout_path, stderr_path, selector, *argv = sys.argv[1:]
sys.path.insert(0, script_root)
from _common import EvidenceError, append_safe_transcript_record

def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
record = {
    "argv": argv,
    "exit_code": 0,
    "stdout_sha256": digest(stdout_path),
    "stderr_sha256": digest(stderr_path),
    "started_at_utc": started,
    "finished_at_utc": finished,
    "selectors": [selector],
}
try:
    append_safe_transcript_record(pathlib.Path(target), record)
except EvidenceError:
    print("transcript capture rejected unsafe command metadata", file=sys.stderr)
    raise SystemExit(2)
PY
}

run_recorded_gate() {
  local scope="$1" cwd="$2" basename="$3" selector="$4"
  shift 4
  local started finished stdout_file stderr_file
  stdout_file="$NODE_EVIDENCE/$basename.stdout"
  stderr_file="$NODE_EVIDENCE/$basename.stderr"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "$scope" == GZ ]]; then
    (
      cd "$cwd"
      VIRTUAL_ENV="$WORKTREE/packages/gove-zone/.venv-beta" "$@"
    ) >"$stdout_file" 2>"$stderr_file"
  else
    (
      cd "$cwd"
      "$@"
    ) >"$stdout_file" 2>"$stderr_file"
  fi
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  append_record "$started" "$finished" "$stdout_file" "$stderr_file" "$selector" "$@"
}

phase B5
append_record "$EVID_GATE_STARTED" "$EVID_GATE_FINISHED" \
  "$NODE_EVIDENCE/evid-gate.stdout" "$NODE_EVIDENCE/evid-gate.stderr" \
  'root:EVID-gate' "${EVID_GATE[@]}"

run_recorded_gate CP "$WORKTREE/packages/acgs-control-plane" cp-ruff-check \
  'packages/acgs-control-plane:local-gate' .venv/bin/ruff check .
run_recorded_gate CP "$WORKTREE/packages/acgs-control-plane" cp-ruff-format \
  'packages/acgs-control-plane:local-gate' .venv/bin/ruff format --check .
run_recorded_gate CP "$WORKTREE/packages/acgs-control-plane" cp-mypy \
  'packages/acgs-control-plane:local-gate' .venv/bin/mypy src/
run_recorded_gate CP "$WORKTREE/packages/acgs-control-plane" cp-pytest \
  'packages/acgs-control-plane:local-gate' .venv/bin/pytest -q

GZ_PREFIX=(uv run --active --no-sync --python 3.11 --package gove-zone)
run_recorded_gate GZ "$WORKTREE" gz-ruff-check 'packages/gove-zone:local-gate' \
  "${GZ_PREFIX[@]}" ruff check \
  packages/gove-zone/src packages/gove-zone/tests packages/gove-zone/examples
run_recorded_gate GZ "$WORKTREE" gz-ruff-format 'packages/gove-zone:local-gate' \
  "${GZ_PREFIX[@]}" ruff format --check \
  packages/gove-zone/src packages/gove-zone/tests packages/gove-zone/examples
run_recorded_gate GZ "$WORKTREE" gz-mypy 'packages/gove-zone:local-gate' \
  "${GZ_PREFIX[@]}" mypy packages/gove-zone/src/gove_zone
run_recorded_gate GZ "$WORKTREE" gz-pytest 'packages/gove-zone:local-gate' \
  "${GZ_PREFIX[@]}" python -m pytest packages/gove-zone/tests \
  --import-mode=importlib -q --cov=gove_zone --cov-fail-under=90

"$EVIDENCE_PY" "$WORKTREE/scripts/evidence/capture_environment.py" \
  --code CP \
  --interpreter "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" \
  --lock "$WORKTREE/requirements/saas-beta/cp-test.lock" \
  --require-editables 0.6 \
  --output "$NODE_EVIDENCE/environment-CP.json"
"$EVIDENCE_PY" "$WORKTREE/scripts/evidence/capture_environment.py" \
  --code GZ \
  --interpreter "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" \
  --lock "$WORKTREE/requirements/saas-beta/gz-test.lock" \
  --require-editables 0.6 \
  --output "$NODE_EVIDENCE/environment-GZ.json"
"$EVIDENCE_PY" "$WORKTREE/scripts/evidence/validate_environment_identities.py" \
  --node "$NODE_ID" \
  --assignment-map "$WORKTREE/requirements/saas-beta/bootstrap-by-scope.json" \
  --assignment EVID+CP+GZ \
  --identity-dir "$NODE_EVIDENCE" \
  --require-fresh-bootstrap-records \
  --reject-missing \
  --reject-extra \
  --reject-unassigned-runtime-paths \
  --output "$NODE_EVIDENCE/environment-identities.json"

P0_ROOT_GATE=(.venv-evidence/bin/python -m pytest -q \
  tests/saas_beta/test_evidence_bootstrap.py::test_clean_sibling_hash_locked_bootstraps_and_round_trip \
  tests/saas_beta/test_evidence_bootstrap.py::test_environment_identities_exactly_match_assignment \
  tests/saas_beta/test_evidence_bootstrap.py::test_missing_extra_or_retained_environment_rejected \
  tests/saas_beta/test_evidence_bootstrap.py::test_pep660_helpers_required_for_assigned_python_scopes)
export ACGS_P0_LITERAL_PROVER_INNER_T="$T"
run_recorded_gate P0 "$WORKTREE" p0-root-gate 'root:P0-EVIDENCE-000' \
  "${P0_ROOT_GATE[@]}"
unset ACGS_P0_LITERAL_PROVER_INNER_T

phase B6
TRANSCRIPT_RECORDS="$("$EVIDENCE_PY" - "$NODE_EVIDENCE/transcript.jsonl" <<'PY'
import pathlib
import sys

print(len(pathlib.Path(sys.argv[1]).read_bytes().splitlines()))
PY
)"
[[ "$TRANSCRIPT_RECORDS" == 10 ]] || die 'reviewed transcript must contain exactly ten records'
(
  cd "$WORKTREE"
  "$EVIDENCE_PY" scripts/evidence/generate_run.py \
    --schema schemas/evidence/acgs-run-evidence-v1.schema.json \
    --node "$NODE_ID" --parent "$P" --product "$T" --assignment EVID+CP+GZ \
    --environment-identities "$NODE_EVIDENCE/environment-identities.json" \
    --transcript "$NODE_EVIDENCE/transcript.jsonl" \
    --output "$NODE_EVIDENCE/run.json"
)
(
  cd "$WORKTREE"
  "$EVIDENCE_PY" scripts/evidence/validate_run.py \
    --schema schemas/evidence/acgs-run-evidence-v1.schema.json \
    --expected-node "$NODE_ID" \
    --assignment-map requirements/saas-beta/bootstrap-by-scope.json \
    --expected-environments EVID+CP+GZ \
    --expected-parent "$P" --expected-product "$T" \
    "$NODE_EVIDENCE/run.json"
)
R="$(
  (
    cd "$WORKTREE"
    "$EVIDENCE_PY" scripts/evidence/hash_run_jcs.py "$NODE_EVIDENCE/run.json"
  )
)"
[[ "$R" =~ ^[0-9a-f]{64}$ ]] || die 'JCS run hash is malformed'
PROOF_COMPLETE=1
