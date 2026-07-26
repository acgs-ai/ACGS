#!/bin/bash
# Internal P0 prover. Invoke scripts/evidence/prove_clean_sibling instead.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

STATIC_LAUNCHER_SHA256=98d9040015eb17931e17b45e00b5f49f2451326372d5107a3a280f1cb3aaf3fc
[[ "${ACGS_CLEAN_SIBLING_STATIC_LAUNCHER:-}" == "$STATIC_LAUNCHER_SHA256" ]] || {
  printf '%s\n' \
    'CLEAN_SIBLING=FAIL phase=B0 reason=internal prover requires trusted static launcher' >&2
  exit 2
}
ACGS_EXPECTED_LAUNCHER="$(/usr/bin/readlink -f "${BASH_SOURCE[0]%.sh}")"
ACGS_STATIC_PARENT_PID="$PPID"
if [[ -n "${ACGS_CLEAN_SIBLING_TMP_FD:-}" ]]; then
  # The guardian is a child exec of the first sanitized Bash. That first Bash
  # remains resident under the static launcher while it waits, so authenticate
  # the complete Bash -> BusyBox ancestry on the descriptor-bearing pass.
  ACGS_GUARDIAN_PARENT_EXE="$(
    /usr/bin/readlink -f "/proc/$ACGS_STATIC_PARENT_PID/exe" 2>/dev/null || true
  )"
  [[ "$ACGS_GUARDIAN_PARENT_EXE" == /usr/bin/bash || \
    "$ACGS_GUARDIAN_PARENT_EXE" == /bin/bash ]] || {
    printf '%s\n' \
      'CLEAN_SIBLING=FAIL phase=B0 reason=sanitized guardian parent identity changed' >&2
    exit 2
  }
  mapfile -d '' -t ACGS_GUARDIAN_PARENT_ARGV <"/proc/$ACGS_STATIC_PARENT_PID/cmdline"
  [[ "${#ACGS_GUARDIAN_PARENT_ARGV[@]}" == 5 && \
    "${ACGS_GUARDIAN_PARENT_ARGV[0]}" == /bin/bash && \
    "${ACGS_GUARDIAN_PARENT_ARGV[1]}" == --noprofile && \
    "${ACGS_GUARDIAN_PARENT_ARGV[2]}" == --norc && \
    "${ACGS_GUARDIAN_PARENT_ARGV[3]}" == "${BASH_SOURCE[0]}" && \
    "${ACGS_GUARDIAN_PARENT_ARGV[4]}" == "${1:-}" ]] || {
    printf '%s\n' \
      'CLEAN_SIBLING=FAIL phase=B0 reason=sanitized guardian parent argv changed' >&2
    exit 2
  }
  IFS=' ' read -r _ _ _ ACGS_STATIC_PARENT_PID _ \
    <"/proc/$ACGS_STATIC_PARENT_PID/stat"
fi
[[ "$(/usr/bin/readlink -f "/proc/$ACGS_STATIC_PARENT_PID/exe" 2>/dev/null || true)" == \
  /usr/bin/busybox ]] || {
  printf '%s\n' \
    'CLEAN_SIBLING=FAIL phase=B0 reason=static launcher parent identity changed' >&2
  exit 2
}
[[ "$(/usr/bin/sha256sum "/proc/$ACGS_STATIC_PARENT_PID/exe" | \
  /usr/bin/awk '{print $1}')" == "$STATIC_LAUNCHER_SHA256" ]] || {
  printf '%s\n' \
    'CLEAN_SIBLING=FAIL phase=B0 reason=static launcher parent digest changed' >&2
  exit 2
}
mapfile -d '' -t ACGS_STATIC_PARENT_ARGV <"/proc/$ACGS_STATIC_PARENT_PID/cmdline"
[[ "${#ACGS_STATIC_PARENT_ARGV[@]}" == 4 && \
  "${ACGS_STATIC_PARENT_ARGV[0]}" == /usr/bin/busybox && \
  "${ACGS_STATIC_PARENT_ARGV[1]}" == ash && \
  "${ACGS_STATIC_PARENT_ARGV[2]}" == "$ACGS_EXPECTED_LAUNCHER" && \
  "${ACGS_STATIC_PARENT_ARGV[3]}" == "${1:-}" ]] || {
  printf '%s\n' \
    'CLEAN_SIBLING=FAIL phase=B0 reason=static launcher parent argv changed' >&2
  exit 2
}
unset ACGS_GUARDIAN_PARENT_ARGV ACGS_GUARDIAN_PARENT_EXE \
  ACGS_STATIC_PARENT_ARGV ACGS_EXPECTED_LAUNCHER
ACGS_STATIC_LAUNCHED=1

# Proof authority must not be selected by caller-controlled command lookup,
# ELF loader state, or Git configuration.  This block intentionally uses only
# shell builtins: rejection must happen before the first external command.
# The system toolset is restricted before the first external command; uv is
# separately pinned to its canonical installation path.
for variable in BASH_ENV ENV CDPATH; do
  [[ -z "${!variable:-}" ]] || {
    printf 'CLEAN_SIBLING=FAIL phase=B0 reason=ambient command environment rejected: %s\n' \
      "$variable" >&2
    exit 2
  }
done
for variable in ${!LD_@}; do
  printf 'CLEAN_SIBLING=FAIL phase=B0 reason=ambient loader environment rejected: %s\n' \
    "$variable" >&2
  exit 2
done
if [[ -z "${ACGS_CLEAN_SIBLING_TMP_FD:-}" && -z "${ACGS_STATIC_LAUNCHED:-}" ]]; then
  for variable in ${!GIT_@}; do
    case "$variable" in
      GIT_CONFIG_* | GIT_EXEC_PATH | GIT_TEMPLATE_DIR | GIT_EXTERNAL_DIFF | \
        GIT_ASKPASS | GIT_SSH | GIT_SSH_COMMAND | GIT_PROXY_COMMAND | \
        GIT_ALTERNATE_OBJECT_DIRECTORIES | GIT_OBJECT_DIRECTORY | GIT_INDEX_FILE | \
        GIT_WORK_TREE | GIT_DIR | GIT_COMMON_DIR | GIT_NAMESPACE | \
        GIT_REPLACE_REF_BASE | GIT_ATTR_NOSYSTEM)
        printf 'CLEAN_SIBLING=FAIL phase=B0 reason=ambient Git environment rejected: %s\n' \
          "$variable" >&2
        exit 2
        ;;
    esac
  done
else
  [[ "${GIT_CONFIG_NOSYSTEM:-}" == 1 && "${GIT_CONFIG_GLOBAL:-}" == /dev/null ]] || {
    printf 'CLEAN_SIBLING=FAIL phase=B0 reason=internal Git boundary changed\n' >&2
    exit 2
  }
fi
unset GIT_PAGER GIT_EDITOR GIT_SEQUENCE_EDITOR
GIT_CONFIG_NOSYSTEM=1
GIT_CONFIG_GLOBAL=/dev/null
HOME=/dev/null
XDG_CONFIG_HOME=/dev/null
export GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL HOME XDG_CONFIG_HOME
unset -f command_not_found_handle 2>/dev/null || true
PATH=/usr/bin:/bin
export PATH
hash -r
UV_BIN=/home/martin/.local/bin/uv
UV_SHA256=a00d3a24514fc0403fc232c9c99bf5e542657c38f4ed941e0611731e4cff268b
[[ -x "$UV_BIN" && ! -L "$UV_BIN" ]] || {
  printf 'CLEAN_SIBLING=FAIL phase=B0 reason=trusted uv unavailable: %s\n' "$UV_BIN" >&2
  exit 2
}
[[ "$(/usr/bin/realpath -e "$UV_BIN" 2>/dev/null || true)" == "$UV_BIN" ]] || {
  printf 'CLEAN_SIBLING=FAIL phase=B0 reason=trusted uv path is noncanonical\n' >&2
  exit 2
}
[[ "$(/usr/bin/sha256sum "$UV_BIN" | /usr/bin/awk '{print $1}')" == "$UV_SHA256" ]] || {
  printf 'CLEAN_SIBLING=FAIL phase=B0 reason=trusted uv digest mismatch\n' >&2
  exit 2
}
export UV_BIN

# Every Git call, including EXIT cleanup calls from the sourced helper, crosses
# the same closed boundary.  Hooks and executable fsmonitor authority are
# disabled explicitly rather than relying on ambient HOME or host policy.
git() {
  /usr/bin/git --no-optional-locks \
    -c core.hooksPath=/dev/null \
    -c core.fsmonitor=false \
    -c core.untrackedCache=false \
    -c credential.helper= \
    -c core.askPass= \
    -c core.attributesFile=/dev/null \
    "$@"
}

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

[[ $# -eq 1 ]] || die 'usage: P=<reviewed-parent> scripts/evidence/prove_clean_sibling <exact-T-commit>'
T="$1"
[[ "$T" =~ ^[0-9a-f]{40}$ ]] || die 'T must be a lowercase 40-hex commit SHA'
[[ -n "${P:-}" ]] || die 'P must be exported as the reviewed parent commit SHA'
[[ "$P" =~ ^[0-9a-f]{40}$ ]] || die 'P must be a lowercase 40-hex commit SHA'
REQUESTED_NODE_ID="${NODE_ID:-P0-EVIDENCE-000}"
P0_REVIEWED_BASE='26d11c2c7a8da37937a7c50c642f18edc75c9345'
P1_MIGRATION_REVIEWED_BASE='79a3c39f841cfc5a6c79e85973887814caf0e694'
P1_SCOPE_REVIEWED_BASE='40781e1200289507fcfbcedf6ab14c120ac6aae8'
P1_LEDGER_REVIEWED_BASE='9450db249e4428021c4d98b2f1b81d414693d9af'
P1_TRUST_REVIEWED_BASE='f113d9bc7263ba2607ff9800da9881a3ff624441'
P2_TENANT_BOOTSTRAP_REVIEWED_BASE='70b0d39010b46d6aed86d93572dcbda213350883'
P2_REGISTER_REVIEWED_BASE='3f60e812bece9869b57bf32fdfa4f070a464592a'
P2_IDEMPOTENCY_REVIEWED_BASE='3269252010e5cc394abe5ab451debbaa95298f0c'
ASSIGNED_BOOTSTRAPS=''
INCLUDE_GZ=0
EXPECTED_TRANSCRIPT_RECORDS=''
TMP_BASENAME=''
case "$REQUESTED_NODE_ID" in
  P0-EVIDENCE-000)
    [[ "$P" == "$P0_REVIEWED_BASE" ]] ||
      die "P0 reviewed parent must be exact $P0_REVIEWED_BASE"
    ASSIGNED_BOOTSTRAPS='EVID+CP+GZ'
    INCLUDE_GZ=1
    EXPECTED_TRANSCRIPT_RECORDS=10
    TMP_BASENAME='acgs-p0-evidence'
    ;;
  P1-MIGRATION-001)
    [[ "$P" == "$P1_MIGRATION_REVIEWED_BASE" ]] ||
      die "P1-MIGRATION-001 reviewed parent must be exact $P1_MIGRATION_REVIEWED_BASE"
    ASSIGNED_BOOTSTRAPS='EVID+CP'
    INCLUDE_GZ=0
    EXPECTED_TRANSCRIPT_RECORDS=6
    TMP_BASENAME='acgs-p1-migration'
    ;;
  P1-SCOPE-002)
    [[ "$P" == "$P1_SCOPE_REVIEWED_BASE" ]] ||
      die "P1-SCOPE-002 reviewed parent must be exact $P1_SCOPE_REVIEWED_BASE"
    ASSIGNED_BOOTSTRAPS='EVID+CP'
    INCLUDE_GZ=0
    EXPECTED_TRANSCRIPT_RECORDS=6
    TMP_BASENAME='acgs-p1-scope'
    ;;
  P1-LEDGER-003)
    [[ "$P" == "$P1_LEDGER_REVIEWED_BASE" ]] ||
      die "P1-LEDGER-003 reviewed parent must be exact $P1_LEDGER_REVIEWED_BASE"
    ASSIGNED_BOOTSTRAPS='EVID+CP'
    INCLUDE_GZ=0
    EXPECTED_TRANSCRIPT_RECORDS=6
    TMP_BASENAME='acgs-p1-ledger'
    ;;
  P1-TRUST-004)
    [[ "$P" == "$P1_TRUST_REVIEWED_BASE" ]] ||
      die "P1-TRUST-004 reviewed parent must be exact $P1_TRUST_REVIEWED_BASE"
    ASSIGNED_BOOTSTRAPS='EVID+CP+GZ'
    INCLUDE_GZ=1
    EXPECTED_TRANSCRIPT_RECORDS=11
    TMP_BASENAME='acgs-p1-trust'
    ;;
  P2-TENANT-BOOTSTRAP-000)
    [[ "$P" == "$P2_TENANT_BOOTSTRAP_REVIEWED_BASE" ]] ||
      die "P2-TENANT-BOOTSTRAP-000 reviewed parent must be exact $P2_TENANT_BOOTSTRAP_REVIEWED_BASE"
    ASSIGNED_BOOTSTRAPS='EVID+CP+GZ'
    INCLUDE_GZ=1
    EXPECTED_TRANSCRIPT_RECORDS=11
    TMP_BASENAME='acgs-p2-tenant-bootstrap'
    ;;
  P2-REGISTER-001)
    [[ "$P" == "$P2_REGISTER_REVIEWED_BASE" ]] ||
      die "P2-REGISTER-001 reviewed parent must be exact $P2_REGISTER_REVIEWED_BASE"
    ASSIGNED_BOOTSTRAPS='EVID+CP+GZ'
    INCLUDE_GZ=1
    EXPECTED_TRANSCRIPT_RECORDS=11
    TMP_BASENAME='acgs-p2-register'
    ;;
  P2-IDEMPOTENCY-002)
    [[ "$P" == "$P2_IDEMPOTENCY_REVIEWED_BASE" ]] ||
      die "P2-IDEMPOTENCY-002 reviewed parent must be exact $P2_IDEMPOTENCY_REVIEWED_BASE"
    ASSIGNED_BOOTSTRAPS='EVID+CP'
    INCLUDE_GZ=0
    EXPECTED_TRANSCRIPT_RECORDS=6
    TMP_BASENAME='acgs-p2-idempotency'
    ;;
  *)
    die "unsupported clean-sibling node: $REQUESTED_NODE_ID"
    ;;
esac
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
  PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX='' \
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
git -C "$SOURCE_REPO" cat-file -e "$T^{commit}" || die 'T commit is unavailable'
git -C "$SOURCE_REPO" cat-file -e "$P^{commit}" || die 'P commit is unavailable'
git -C "$SOURCE_REPO" merge-base --is-ancestor "$P" "$T" ||
  die 'P must be an ancestor of exact T'
WORKTREES_BEFORE="$(git -C "$SOURCE_REPO" worktree list --porcelain)"
WORKTREE_PATHS_BEFORE="$(clean_sibling_worktree_paths_digest "$WORKTREES_BEFORE")"
SOURCE_COMMON_GITDIR="$(git -C "$SOURCE_REPO" rev-parse --path-format=absolute --git-common-dir)"
WORKTREE_REGISTRY_ROOT="$SOURCE_COMMON_GITDIR/worktrees"
WORKTREE_REGISTRY_ENTRIES_BEFORE="$(
  clean_sibling_snapshot_worktree_registry "$WORKTREE_REGISTRY_ROOT"
)" || die 'cannot snapshot baseline worktree registry'
SOURCE_STATUS_BEFORE="$(git -C "$SOURCE_REPO" status --porcelain=v1 --untracked-files=all)"
[[ -z "$(git -C "$SOURCE_REPO" status --porcelain=v1 --untracked-files=all)" ]] ||
  die 'source repository must be clean before proof'
git -C "$SOURCE_REPO" diff --check "$P..$T" || die 'P..T diff check failed'
[[ "$(uname -m)" == 'x86_64' ]] || die 'lock platform requires x86_64'
export PYTHONDONTWRITEBYTECODE=1
TMP_ROOT=''
OWNER_MARKER=''
TMP_ROOT_DEVICE=''
TMP_ROOT_INODE=''
TMP_ROOT_UID=''
TMP_ROOT_MODE=''
WORKTREE=''
SOURCE_GIT_COMMON_DIR=''
EVIDENCE_ROOT=''
NODE_ID="$REQUESTED_NODE_ID"
NODE_EVIDENCE=''
SCRATCH_ROOT=''
RUNTIME_TMP=''
UV_CACHE_DIR=''
LOCK_RENDER_ROOT=''
UV_PYTHON_BIN_DIR=''
UV_TOOL_DIR=''
UV_TOOL_BIN_DIR=''
UV_PYTHON_CACHE_DIR=''
UV_CREDENTIALS_DIR=''
WORKTREE_ADDED=0
SOURCE_COMMON_GITDIR="${SOURCE_COMMON_GITDIR:-}"
WORKTREE_REGISTRY_ROOT="${WORKTREE_REGISTRY_ROOT:-}"
WORKTREE_REGISTRY_ROOT_IDENTITY=''
WORKTREE_REGISTRY_ENTRIES_BEFORE="${WORKTREE_REGISTRY_ENTRIES_BEFORE:-}"
WORKTREE_ADMIN_GITDIR=''
WORKTREE_ADMIN_GITDIR_IDENTITY=''
WORKTREE_GITFILE_RETENTION_REQUIRED=0
WORKTREE_GITFILE_FD=''
WORKTREE_GITFILE_PATH=''
WORKTREE_GITFILE_IDENTITY=''
WORKTREE_GITFILE_MODE=''
WORKTREE_GITFILE_LINKS=''
WORKTREE_GITFILE_SIZE=''
WORKTREE_GITFILE_SHA256=''
WORKTREE_GITFILE_CONTENT_B64=''
WORKTREE_ADMIN_SENTINEL=''
WORKTREE_ADMIN_SENTINEL_PATH=''
WORKTREE_ADMIN_SENTINEL_IDENTITY=''
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

TMP_ROOT="$(mktemp -d "$TMP_PARENT/$TMP_BASENAME.XXXXXXXX")"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
TMP_ROOT="$(realpath -e "$TMP_ROOT")"
case "$TMP_ROOT" in
  "$TMP_PARENT"/"$TMP_BASENAME".*) ;;
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
LOCK_RENDER_ROOT="$SCRATCH_ROOT/lock-render"

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
[[ "$("$UV_BIN" --version | awk '{print $2}')" == '0.11.19' ]] || die 'uv must be exactly 0.11.19'
BWRAP_BIN=/usr/bin/bwrap
[[ -x "$BWRAP_BIN" && ! -L "$BWRAP_BIN" ]] ||
  die 'containment runner unavailable: /usr/bin/bwrap'
[[ "$("$BWRAP_BIN" --version | awk '{print $2}')" == '0.11.0' ]] ||
  die 'containment runner version drifted'
WORKTREE_ADDED=1
git -C "$SOURCE_REPO" worktree add --detach "$WORKTREE" "$T"
WORKTREE_GITFILE_PATH="$WORKTREE/.git"
[[ -f "$WORKTREE_GITFILE_PATH" && ! -L "$WORKTREE_GITFILE_PATH" ]] ||
  die 'detached sibling gitfile is not a regular file'
exec {WORKTREE_GITFILE_FD}<"$WORKTREE_GITFILE_PATH" ||
  die 'cannot retain detached sibling gitfile descriptor'
WORKTREE_GITFILE_RETENTION_REQUIRED=1
IFS=: read -r WORKTREE_GITFILE_DEVICE WORKTREE_GITFILE_INODE \
  WORKTREE_GITFILE_UID WORKTREE_GITFILE_MODE WORKTREE_GITFILE_LINKS \
  WORKTREE_GITFILE_SIZE WORKTREE_GITFILE_SHA256 WORKTREE_GITFILE_CONTENT_B64 < <(
  clean_sibling_capture_retained_gitfile "$WORKTREE_GITFILE_FD" "$WORKTREE_GITFILE_PATH"
)
[[ -n "${WORKTREE_GITFILE_CONTENT_B64:-}" ]] ||
  die 'cannot capture detached sibling gitfile descriptor identity'
WORKTREE_GITFILE_IDENTITY="$WORKTREE_GITFILE_DEVICE:$WORKTREE_GITFILE_INODE:$WORKTREE_GITFILE_UID"
clean_sibling_validate_retained_gitfile \
  "$WORKTREE_GITFILE_FD" \
  "$WORKTREE_GITFILE_PATH" \
  "$WORKTREE_GITFILE_IDENTITY" \
  "$WORKTREE_GITFILE_MODE" \
  "$WORKTREE_GITFILE_LINKS" \
  "$WORKTREE_GITFILE_SIZE" \
  "$WORKTREE_GITFILE_SHA256" \
  "$WORKTREE_GITFILE_CONTENT_B64" ||
  die 'detached sibling gitfile descriptor identity is unsafe'
WORKTREE_ADMIN_GITDIR="$(git -C "$WORKTREE" rev-parse --absolute-git-dir)"
case "$WORKTREE_ADMIN_GITDIR" in
  "$WORKTREE_REGISTRY_ROOT"/*) ;;
  *) die 'detached sibling admin gitdir is outside source worktree registry' ;;
esac
IFS=: read -r WORKTREE_REGISTRY_DEVICE WORKTREE_REGISTRY_INODE WORKTREE_REGISTRY_UID < <(
  stat -c '%d:%i:%u' -- "$WORKTREE_REGISTRY_ROOT"
)
WORKTREE_REGISTRY_ROOT_IDENTITY="$WORKTREE_REGISTRY_DEVICE:$WORKTREE_REGISTRY_INODE:$WORKTREE_REGISTRY_UID"
IFS=: read -r WORKTREE_ADMIN_DEVICE WORKTREE_ADMIN_INODE WORKTREE_ADMIN_UID < <(
  stat -c '%d:%i:%u' -- "$WORKTREE_ADMIN_GITDIR"
)
WORKTREE_ADMIN_GITDIR_IDENTITY="$WORKTREE_ADMIN_DEVICE:$WORKTREE_ADMIN_INODE:$WORKTREE_ADMIN_UID"
WORKTREE_ADMIN_SENTINEL="$("$SNAPSHOT_PYTHON" - <<'PY'
import secrets

print(secrets.token_hex(32))
PY
)"
WORKTREE_ADMIN_SENTINEL_PATH="$WORKTREE_ADMIN_GITDIR/acgs-clean-sibling-owner"
(set -C; umask 077; printf '%s\n' "$WORKTREE_ADMIN_SENTINEL" >"$WORKTREE_ADMIN_SENTINEL_PATH") ||
  die 'cannot create detached sibling admin owner sentinel'
chmod 0600 -- "$WORKTREE_ADMIN_SENTINEL_PATH" ||
  die 'cannot seal detached sibling admin owner sentinel'
IFS=: read -r WORKTREE_SENTINEL_DEVICE WORKTREE_SENTINEL_INODE WORKTREE_SENTINEL_UID < <(
  stat -c '%d:%i:%u' -- "$WORKTREE_ADMIN_SENTINEL_PATH"
)
WORKTREE_ADMIN_SENTINEL_IDENTITY="$WORKTREE_SENTINEL_DEVICE:$WORKTREE_SENTINEL_INODE:$WORKTREE_SENTINEL_UID"
[[ "$(git -C "$WORKTREE" rev-parse HEAD)" == "$T" ]] || die 'detached sibling is not exact T'
SOURCE_GIT_COMMON_DIR="$(git -C "$SOURCE_REPO" rev-parse --path-format=absolute --git-common-dir)"
SOURCE_GIT_COMMON_DIR="$(realpath -e "$SOURCE_GIT_COMMON_DIR")"
[[ -d "$SOURCE_GIT_COMMON_DIR" && ! -L "$SOURCE_GIT_COMMON_DIR" ]] ||
  die 'source git common directory is unsafe'
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
if [[ "$NODE_ID" == P2-IDEMPOTENCY-002 ]]; then
  export ACGS_PROCESS_SCHEDULE='["single-process-evidence-and-package-gates","postgres-100-request-multiprocess-agent-registration-idempotency"]'
fi
unset UV_OFFLINE UV_NO_INDEX UV_NO_CACHE RUFF_NO_CACHE
unset VIRTUAL_ENV PYTHONPATH PYTHONHOME UV_PROJECT_ENVIRONMENT

PREEXISTING_REJECT_PATHS=(
  "$WORKTREE/.venv-evidence"
  "$WORKTREE/packages/acgs-control-plane/.venv"
  "$WORKTREE/packages/gove-zone/.venv-beta"
  "$WORKTREE/acgi-ai/node_modules"
  "$NODE_EVIDENCE"
)
for path in "${PREEXISTING_REJECT_PATHS[@]}"; do
  reject_lexists "$path"
done

contained_env_args() {
  local variable
  for variable in \
    PATH LANG LC_ALL TZ \
    HOME TMPDIR TMP TEMP XDG_CACHE_HOME XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME \
    PYTEST_DEBUG_TEMPROOT MYPY_CACHE_DIR RUFF_CACHE_DIR COVERAGE_FILE \
    PIP_CACHE_DIR HATCH_CACHE_DIR \
    UV_BIN UV_CACHE_DIR UV_PYTHON_INSTALL_DIR UV_PYTHON_BIN_DIR UV_TOOL_DIR \
    UV_TOOL_BIN_DIR UV_PYTHON_CACHE_DIR UV_CREDENTIALS_DIR UV_NO_CONFIG UV_NO_ENV_FILE \
    UV_OFFLINE UV_NO_INDEX UV_NO_CACHE RUFF_NO_CACHE \
    PYTHONUSERBASE PYTHONPYCACHEPREFIX PYTHONNOUSERSITE PYTHONDONTWRITEBYTECODE \
    PYTEST_ADDOPTS VIRTUAL_ENV REPO_ROOT ACGS_EVIDENCE_ROOT NODE_ID \
    ACGS_TEST_SEED PYTHONHASHSEED ACGS_PROCESS_SCHEDULE ACGS_CLOCK_SOURCE \
    ACGS_SKIPPED_JSON ACGS_EXTERNAL_JSON ACGS_P0_LITERAL_PROVER_INNER_T; do
    if [[ "${!variable+x}" == x ]]; then
      printf '%s=%s\0' "$variable" "${!variable}"
    fi
  done
}

contained_mount_args() {
  local path
  printf '%s\0%s\0%s\0' --ro-bind "$WORKTREE" "$WORKTREE"
  printf '%s\0%s\0%s\0' --ro-bind "$SOURCE_GIT_COMMON_DIR" "$SOURCE_GIT_COMMON_DIR"
  for path in \
    "$EVIDENCE_ROOT" \
    "$SCRATCH_ROOT" \
    "$WORKTREE/.venv-evidence" \
    "$WORKTREE/packages/acgs-control-plane/.venv" \
    "$WORKTREE/packages/gove-zone/.venv-beta"; do
    if [[ -d "$path" && ! -L "$path" ]]; then
      printf '%s\0%s\0%s\0' --bind "$path" "$path"
    fi
  done
}

runtime_system_mount_args() {
  local path
  for path in \
    /etc/passwd \
    /etc/group \
    /etc/nsswitch.conf; do
    if [[ -e "$path" && ! -L "$path" ]]; then
      printf '%s\0%s\0%s\0' --ro-bind-try "$path" "$path"
    fi
  done
}

runtime_linker_args() {
  if [[ -x /usr/bin/ld.bfd && -L /usr/bin/ld ]]; then
    printf '%s\0%s\0' --dir /etc/alternatives
    printf '%s\0%s\0%s\0' --symlink /usr/bin/ld.bfd /etc/alternatives/ld
  fi
}

bootstrap_mount_args() {
  local path
  contained_mount_args
  runtime_system_mount_args
  for path in \
    /etc/resolv.conf \
    /etc/hosts \
    /etc/nsswitch.conf \
    /etc/ssl \
    /etc/pki; do
    if [[ -e "$path" && ! -L "$path" ]]; then
      printf '%s\0%s\0%s\0' --ro-bind-try "$path" "$path"
    fi
  done
}

run_contained() {
  local cwd="$1"
  shift
  [[ -x "$BWRAP_BIN" && ! -L "$BWRAP_BIN" ]] ||
    die 'containment runner unavailable: /usr/bin/bwrap'
  [[ "$cwd" == "$WORKTREE" || "$cwd" == "$WORKTREE"/* || \
    "$cwd" == "$SCRATCH_ROOT" || "$cwd" == "$SCRATCH_ROOT"/* ]] ||
    die "contained cwd escaped target worktree/scratch: $cwd"
  (
    local fd fd_path
    for fd_path in /proc/"$BASHPID"/fd/*; do
      fd="${fd_path##*/}"
      case "$fd" in
        0 | 1 | 2) ;;
        *) eval "exec $fd<&-" 2>/dev/null || true ;;
      esac
    done
    mapfile -d '' -t ACGS_CONTAINED_ENV < <(contained_env_args)
    mapfile -d '' -t ACGS_CONTAINED_MOUNTS < <(contained_mount_args)
    mapfile -d '' -t ACGS_CONTAINED_SYSTEM_MOUNTS < <(runtime_system_mount_args)
    mapfile -d '' -t ACGS_CONTAINED_LINKER_ARGS < <(runtime_linker_args)
    exec "$BWRAP_BIN" \
      --die-with-parent \
      --unshare-all \
      --unshare-user \
      --unshare-ipc \
      --unshare-net \
      --new-session \
      --disable-userns \
      --proc /proc \
      --dev /dev \
      --tmpfs /tmp \
      --tmpfs /run \
      --dir /run/service \
      --ro-bind /usr /usr \
      --ro-bind /bin /bin \
      --ro-bind-try /lib /lib \
      --ro-bind-try /lib64 /lib64 \
      --ro-bind "$UV_BIN" "$UV_BIN" \
      "${ACGS_CONTAINED_SYSTEM_MOUNTS[@]}" \
      "${ACGS_CONTAINED_LINKER_ARGS[@]}" \
      "${ACGS_CONTAINED_MOUNTS[@]}" \
      --chdir "$cwd" \
      /usr/bin/env -i "${ACGS_CONTAINED_ENV[@]}" "$@"
  )
}

run_contained_bootstrap() {
  local cwd="$1"
  shift
  [[ "${1:-}" == "$UV_BIN" ]] ||
    die 'bootstrap containment only runs the pinned uv executable'
  [[ -x "$BWRAP_BIN" && ! -L "$BWRAP_BIN" ]] ||
    die 'containment runner unavailable: /usr/bin/bwrap'
  [[ "$cwd" == "$WORKTREE" || "$cwd" == "$WORKTREE"/* || \
    "$cwd" == "$SCRATCH_ROOT" || "$cwd" == "$SCRATCH_ROOT"/* ]] ||
    die "bootstrap cwd escaped target worktree/scratch: $cwd"
  (
    local fd fd_path
    for fd_path in /proc/"$BASHPID"/fd/*; do
      fd="${fd_path##*/}"
      case "$fd" in
        0 | 1 | 2) ;;
        *) eval "exec $fd<&-" 2>/dev/null || true ;;
      esac
    done
    unset UV_OFFLINE UV_NO_INDEX UV_NO_CACHE RUFF_NO_CACHE
    mapfile -d '' -t ACGS_CONTAINED_ENV < <(contained_env_args)
    mapfile -d '' -t ACGS_CONTAINED_MOUNTS < <(bootstrap_mount_args)
    exec "$BWRAP_BIN" \
      --die-with-parent \
      --unshare-user \
      --unshare-ipc \
      --unshare-pid \
      --new-session \
      --disable-userns \
      --proc /proc \
      --dev /dev \
      --tmpfs /tmp \
      --tmpfs /run \
      --dir /run/service \
      --ro-bind /usr /usr \
      --ro-bind /bin /bin \
      --ro-bind-try /lib /lib \
      --ro-bind-try /lib64 /lib64 \
      --ro-bind "$UV_BIN" "$UV_BIN" \
      "${ACGS_CONTAINED_MOUNTS[@]}" \
      --chdir "$cwd" \
      /usr/bin/env -i "${ACGS_CONTAINED_ENV[@]}" "$@"
  )
}

phase B1
EXPECTED="$TMP_ROOT/expected-locks"
mkdir "$EXPECTED"
mkdir -p "$LOCK_RENDER_ROOT"
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
  mkdir -p "$LOCK_RENDER_ROOT/$(dirname "$relative")"
  cp -- "$WORKTREE/$relative" "$LOCK_RENDER_ROOT/$relative"
done
LC_ALL=C TZ=UTC PYTHONHASHSEED=0 run_contained "$WORKTREE" \
  /usr/bin/python3 \
  scripts/evidence/render_lock_inputs.py \
  --config requirements/saas-beta/locks.toml \
  --output-root "$LOCK_RENDER_ROOT"
LC_ALL=C TZ=UTC run_contained_bootstrap "$LOCK_RENDER_ROOT" "$UV_BIN" pip compile --python-version 3.11 \
  --python-platform x86_64-manylinux_2_28 \
  --exclude-newer 2026-07-10T00:00:00Z --generate-hashes \
  requirements/saas-beta/evidence-test.in \
  --output-file requirements/saas-beta/evidence-test.lock
LC_ALL=C TZ=UTC run_contained_bootstrap "$LOCK_RENDER_ROOT" "$UV_BIN" pip compile --python-version 3.11 \
  --python-platform x86_64-manylinux_2_28 \
  --exclude-newer 2026-07-10T00:00:00Z --generate-hashes \
  requirements/saas-beta/cp-test.in \
  --output-file requirements/saas-beta/cp-test.lock
LC_ALL=C TZ=UTC run_contained_bootstrap "$LOCK_RENDER_ROOT" "$UV_BIN" pip compile --python-version 3.11 \
  --python-platform x86_64-manylinux_2_28 \
  --exclude-newer 2026-07-10T00:00:00Z --generate-hashes \
  requirements/saas-beta/gz-test.in \
  --output-file requirements/saas-beta/gz-test.lock
for relative in "${LOCK_FILES[@]}"; do
  cmp --silent "$EXPECTED/$relative" "$LOCK_RENDER_ROOT/$relative" ||
    die "deterministic render/compile drift: $relative"
done
[[ -z "$(git -C "$WORKTREE" status --porcelain=v1 --untracked-files=all)" ]] ||
  die 'lock regeneration left product-tree drift'

phase B2
run_contained_bootstrap "$WORKTREE" "$UV_BIN" python install 3.11
mkdir -m 700 "$WORKTREE/.venv-evidence"
run_contained_bootstrap "$WORKTREE" "$UV_BIN" venv --python 3.11 "$WORKTREE/.venv-evidence"
mkdir -p "$NODE_EVIDENCE"
run_contained_bootstrap "$WORKTREE" "$UV_BIN" pip sync \
  --python "$WORKTREE/.venv-evidence/bin/python" --require-hashes \
  "$WORKTREE/requirements/saas-beta/evidence-test.lock"
export UV_OFFLINE=1 UV_NO_INDEX=1 UV_NO_CACHE=1
export RUFF_NO_CACHE=true PYTHONDONTWRITEBYTECODE=1
EVIDENCE_PY="$WORKTREE/.venv-evidence/bin/python"
run_contained "$WORKTREE" "$EVIDENCE_PY" "$WORKTREE/scripts/evidence/verify_environment.py" \
  --code EVID \
  --lock "$WORKTREE/requirements/saas-beta/evidence-test.lock" \
  --expected-interpreter "$EVIDENCE_PY" \
  --expected-python 3.11 \
  --expected-uv 0.11.19 \
  --expected-uv-executable "$UV_BIN" \
  --require-module-root "$WORKTREE/.venv-evidence" \
  --require 'rfc8785==0.1.4' \
  --require 'cryptography>=42' \
  --require jsonschema \
  --require pytest \
  --output "$NODE_EVIDENCE/environment-EVID.json"
run_contained "$WORKTREE" "$UV_BIN" pip freeze --python "$EVIDENCE_PY" \
  >"$NODE_EVIDENCE/evidence.freeze"
EVID_GATE=(.venv-evidence/bin/python -m pytest -q \
  tests/saas_beta/test_evidence_bootstrap.py::test_universal_evidence_interpreter_offline)
EVID_GATE_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_contained "$WORKTREE" "${EVID_GATE[@]}" \
  >"$NODE_EVIDENCE/evid-gate.stdout" 2>"$NODE_EVIDENCE/evid-gate.stderr"
EVID_GATE_FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

precheck_product() {
  local code="$1" interpreter="$2" lock="$3" output="$4"
  UV_OFFLINE=1 UV_NO_INDEX=1 UV_NO_CACHE=1 \
    run_contained "$WORKTREE" "$interpreter" -I - "$lock" "$code" <<'PY' >"$output"
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
  run_contained "$WORKTREE" "$EVIDENCE_PY" - "$code" "$before" "$after" "$@" <<'PY'
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
mkdir -m 700 "$WORKTREE/packages/acgs-control-plane/.venv"
run_contained_bootstrap "$WORKTREE" "$UV_BIN" venv --python 3.11 "$WORKTREE/packages/acgs-control-plane/.venv"
run_contained_bootstrap "$WORKTREE" "$UV_BIN" pip sync \
  --python "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" --require-hashes \
  "$WORKTREE/requirements/saas-beta/cp-test.lock"
precheck_product CP \
  "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" \
  "$WORKTREE/requirements/saas-beta/cp-test.lock" \
  "$NODE_EVIDENCE/cp-editables-version.txt"
run_contained "$WORKTREE" "$UV_BIN" pip freeze \
  --python "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" \
  >"$NODE_EVIDENCE/cp-pre-editable.freeze"

if [[ "$INCLUDE_GZ" == 1 ]]; then
  mkdir -m 700 "$WORKTREE/packages/gove-zone/.venv-beta"
  run_contained_bootstrap "$WORKTREE" "$UV_BIN" venv --python 3.11 "$WORKTREE/packages/gove-zone/.venv-beta"
  run_contained_bootstrap "$WORKTREE" "$UV_BIN" pip sync \
    --python "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" --require-hashes \
    "$WORKTREE/requirements/saas-beta/gz-test.lock"
  precheck_product GZ \
    "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" \
    "$WORKTREE/requirements/saas-beta/gz-test.lock" \
    "$NODE_EVIDENCE/gz-editables-version.txt"
  run_contained "$WORKTREE" "$UV_BIN" pip freeze \
    --python "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" \
    >"$NODE_EVIDENCE/gz-pre-editable.freeze"
fi

phase B4
run_contained "$WORKTREE" "$UV_BIN" pip install \
  --python "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" \
  --offline --no-index --no-cache --no-build-isolation --no-deps \
  --editable "$WORKTREE/packages/gove-zone" \
  --editable "$WORKTREE/packages/acgs-control-plane"
run_contained "$WORKTREE" "$UV_BIN" pip freeze \
  --python "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" \
  >"$NODE_EVIDENCE/cp-post-editable.freeze"
verify_freeze_delta CP \
  "$NODE_EVIDENCE/cp-pre-editable.freeze" \
  "$NODE_EVIDENCE/cp-post-editable.freeze" \
  "$WORKTREE/packages/gove-zone" "$WORKTREE/packages/acgs-control-plane"

if [[ "$INCLUDE_GZ" == 1 ]]; then
  run_contained "$WORKTREE" "$UV_BIN" pip install \
    --python "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" \
    --offline --no-index --no-cache --no-build-isolation --no-deps \
    --editable "$WORKTREE/packages/gove-zone"
  run_contained "$WORKTREE" "$UV_BIN" pip freeze \
    --python "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" \
    >"$NODE_EVIDENCE/gz-post-editable.freeze"
  verify_freeze_delta GZ \
    "$NODE_EVIDENCE/gz-pre-editable.freeze" \
    "$NODE_EVIDENCE/gz-post-editable.freeze" \
    "$WORKTREE/packages/gove-zone"
fi

append_record() {
  local started="$1" finished="$2" stdout_file="$3" stderr_file="$4" selector="$5" cwd_scope="$6"
  shift 6
  run_contained "$WORKTREE" "$EVIDENCE_PY" - \
    "$WORKTREE/scripts/evidence" "$NODE_EVIDENCE/transcript.jsonl" \
    "$NODE_ID" "$started" "$finished" "$stdout_file" "$stderr_file" "$selector" \
    "$cwd_scope" "$@" <<'PY'
import hashlib
import pathlib
import sys

(
    script_root,
    target,
    node_id,
    started,
    finished,
    stdout_path,
    stderr_path,
    selector,
    cwd_scope,
    *argv,
) = sys.argv[1:]
sys.path.insert(0, script_root)
from _common import EvidenceError, append_safe_transcript_record

# Execution uses the hash-authenticated absolute uv binary.  The reviewed
# transcript vocabulary intentionally records the stable public tool identity
# rather than a host-specific installation pathname.  Only that exact pinned
# executable may be normalized; all remaining argv still pass the closed
# command/selector contract below.
if argv and argv[0] == "/home/martin/.local/bin/uv":
    argv[0] = "uv"

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
if cwd_scope != "__NONE__":
    record["cwd_scope"] = cwd_scope
try:
    append_safe_transcript_record(
        pathlib.Path(target),
        record,
        expected_node=node_id,
    )
except EvidenceError:
    print("transcript capture rejected unsafe command metadata", file=sys.stderr)
    raise SystemExit(2)
PY
}

run_recorded_gate() {
  local scope="$1" cwd="$2" basename="$3" selector="$4" cwd_scope="$5"
  shift 5
  local started finished stdout_file stderr_file gate_status stderr_sha256
  stdout_file="$NODE_EVIDENCE/$basename.stdout"
  stderr_file="$NODE_EVIDENCE/$basename.stderr"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "$scope" == GZ ]]; then
    if VIRTUAL_ENV="$WORKTREE/packages/gove-zone/.venv-beta" \
      run_contained "$cwd" "$@" >"$stdout_file" 2>"$stderr_file"; then
      gate_status=0
    else
      gate_status=$?
    fi
  else
    if run_contained "$cwd" "$@" >"$stdout_file" 2>"$stderr_file"; then
      gate_status=0
    else
      gate_status=$?
    fi
  fi
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "$gate_status" -ne 0 ]]; then
    stderr_sha256="$(sha256sum "$stderr_file" | awk '{print $1}')"
    printf 'RECORDED_GATE=FAIL scope=%s selector=%s exit=%s stderr_sha256=%s\n' \
      "$scope" "$selector" "$gate_status" "$stderr_sha256" >&2
    return "$gate_status"
  fi
  append_record "$started" "$finished" "$stdout_file" "$stderr_file" "$selector" \
    "$cwd_scope" "$@"
}

run_trusted_parent_postgres_gate() {
  local scope="$1" cwd="$2" basename="$3" selector="$4" cwd_scope="$5"
  shift 5
  local started finished stdout_file stderr_file gate_status stderr_sha256 tmpdir
  [[ "$scope" == CP ]] || die 'trusted parent PostgreSQL gate is CP-only'
  [[ "$cwd" == "$WORKTREE/packages/acgs-control-plane" ]] ||
    die 'trusted parent PostgreSQL gate cwd must be the control-plane package'
  [[ "${1:-}" == ./scripts/run_postgres_gate.sh ]] ||
    die 'trusted parent PostgreSQL gate only runs the reviewed wrapper'
  tmpdir="${TMPDIR:-/tmp}"
  stdout_file="$NODE_EVIDENCE/$basename.stdout"
  stderr_file="$NODE_EVIDENCE/$basename.stderr"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if (
    cd "$cwd"
    env -i \
      PATH="$PATH" \
      HOME="$HOME" \
      TMPDIR="$tmpdir" \
      UV_BIN="$UV_BIN" \
      UV_PYTHON_INSTALL_DIR="$UV_PYTHON_INSTALL_DIR" \
      ACGS_TEST_SEED=20260710 \
      PYTHONHASHSEED=0 \
      "$@"
  ) >"$stdout_file" 2>"$stderr_file"; then
    gate_status=0
  else
    gate_status=$?
  fi
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "$gate_status" -ne 0 ]]; then
    stderr_sha256="$(sha256sum "$stderr_file" | awk '{print $1}')"
    printf 'RECORDED_GATE=FAIL scope=%s selector=%s exit=%s stderr_sha256=%s\n' \
      "$scope" "$selector" "$gate_status" "$stderr_sha256" >&2
    return "$gate_status"
  fi
  append_record "$started" "$finished" "$stdout_file" "$stderr_file" "$selector" \
    "$cwd_scope" "$@"
}

validate_exact_pytest_junit() {
  local junit_file="$1" expected_tests="$2" selector="$3"
  run_contained "$WORKTREE" "$EVIDENCE_PY" - "$junit_file" "$expected_tests" "$selector" <<'PY'
import sys
import xml.etree.ElementTree as ET

junit_file, expected_tests_raw, selector = sys.argv[1:4]
expected_tests = int(expected_tests_raw)
try:
    root = ET.parse(junit_file).getroot()
except Exception:
    print(f"RECORDED_GATE=FAIL selector={selector} reason=unreadable-junit", file=sys.stderr)
    raise SystemExit(2)

if root.tag == "testsuite":
    suites = [root]
elif root.tag == "testsuites":
    suites = list(root.findall("testsuite"))
else:
    print(f"RECORDED_GATE=FAIL selector={selector} reason=unexpected-junit-root", file=sys.stderr)
    raise SystemExit(2)
if not suites:
    print(f"RECORDED_GATE=FAIL selector={selector} reason=empty-junit-suites", file=sys.stderr)
    raise SystemExit(2)

def count(name: str) -> int:
    total = 0
    for suite in suites:
        if name not in suite.attrib:
            print(
                f"RECORDED_GATE=FAIL selector={selector} reason=missing-junit-{name}",
                file=sys.stderr,
            )
            raise SystemExit(2)
        raw = suite.attrib[name]
        if raw != "0" and (not raw or raw[0] == "0" or not raw.isdecimal()):
            print(
                f"RECORDED_GATE=FAIL selector={selector} reason=invalid-junit-{name}",
                file=sys.stderr,
            )
            raise SystemExit(2)
        if raw == "0":
            value = 0
        else:
            value = int(raw)
        total += value
    return total

actual = {
    "tests": count("tests"),
    "failures": count("failures"),
    "errors": count("errors"),
    "skipped": count("skipped"),
}
if actual != {"tests": expected_tests, "failures": 0, "errors": 0, "skipped": 0}:
    fields = " ".join(f"{key}={value}" for key, value in actual.items())
    print(
        f"RECORDED_GATE=FAIL selector={selector} reason=unexpected-pytest-outcome {fields}",
        file=sys.stderr,
    )
    raise SystemExit(2)
PY
}

run_recorded_exact_pytest_gate() {
  local scope="$1" cwd="$2" basename="$3" selector="$4" cwd_scope="$5" expected_tests="$6"
  shift 6
  local started finished stdout_file stderr_file junit_file gate_status stderr_sha256
  stdout_file="$NODE_EVIDENCE/$basename.stdout"
  stderr_file="$NODE_EVIDENCE/$basename.stderr"
  junit_file="$NODE_EVIDENCE/$basename.junit.xml"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "$scope" == GZ ]]; then
    if PYTEST_ADDOPTS="--junitxml=$junit_file" \
      VIRTUAL_ENV="$WORKTREE/packages/gove-zone/.venv-beta" \
      run_contained "$cwd" "$@" >"$stdout_file" 2>"$stderr_file"; then
      gate_status=0
    else
      gate_status=$?
    fi
  else
    if PYTEST_ADDOPTS="--junitxml=$junit_file" \
      run_contained "$cwd" "$@" >"$stdout_file" 2>"$stderr_file"; then
      gate_status=0
    else
      gate_status=$?
    fi
  fi
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "$gate_status" -ne 0 ]]; then
    stderr_sha256="$(sha256sum "$stderr_file" | awk '{print $1}')"
    printf 'RECORDED_GATE=FAIL scope=%s selector=%s exit=%s stderr_sha256=%s\n' \
      "$scope" "$selector" "$gate_status" "$stderr_sha256" >&2
    return "$gate_status"
  fi
  validate_exact_pytest_junit "$junit_file" "$expected_tests" "$selector"
  append_record "$started" "$finished" "$stdout_file" "$stderr_file" "$selector" \
    "$cwd_scope" "$@"
}

phase B5
node_cwd_scope() {
  local default_scope="$1"
  case "$NODE_ID" in
    P1-MIGRATION-001 | P1-SCOPE-002 | P1-LEDGER-003 | P1-TRUST-004 | \
      P2-TENANT-BOOTSTRAP-000 | P2-REGISTER-001 | P2-IDEMPOTENCY-002)
      printf '%s' "$default_scope"
      ;;
    *) printf __NONE__ ;;
  esac
}

append_record "$EVID_GATE_STARTED" "$EVID_GATE_FINISHED" \
  "$NODE_EVIDENCE/evid-gate.stdout" "$NODE_EVIDENCE/evid-gate.stderr" \
  'root:EVID-gate' "$(node_cwd_scope REPO_ROOT)" \
  "${EVID_GATE[@]}"

run_recorded_gate CP "$WORKTREE/packages/acgs-control-plane" cp-ruff-check \
  'packages/acgs-control-plane:local-gate' "$(node_cwd_scope CP)" \
  .venv/bin/ruff check .
run_recorded_gate CP "$WORKTREE/packages/acgs-control-plane" cp-ruff-format \
  'packages/acgs-control-plane:local-gate' "$(node_cwd_scope CP)" \
  .venv/bin/ruff format --check .
run_recorded_gate CP "$WORKTREE/packages/acgs-control-plane" cp-mypy \
  'packages/acgs-control-plane:local-gate' "$(node_cwd_scope CP)" \
  .venv/bin/mypy src/
run_recorded_gate CP "$WORKTREE/packages/acgs-control-plane" cp-pytest \
  'packages/acgs-control-plane:local-gate' "$(node_cwd_scope CP)" \
  .venv/bin/pytest -q

if [[ "$INCLUDE_GZ" == 1 ]]; then
  GZ_PREFIX=("$UV_BIN" run --active --no-sync --python 3.11 --package gove-zone)
  run_recorded_gate GZ "$WORKTREE" gz-ruff-check \
    'packages/gove-zone:local-gate' "$(node_cwd_scope REPO_ROOT)" \
    "${GZ_PREFIX[@]}" ruff check \
    packages/gove-zone/src packages/gove-zone/tests packages/gove-zone/examples
  run_recorded_gate GZ "$WORKTREE" gz-ruff-format \
    'packages/gove-zone:local-gate' "$(node_cwd_scope REPO_ROOT)" \
    "${GZ_PREFIX[@]}" ruff format --check \
    packages/gove-zone/src packages/gove-zone/tests packages/gove-zone/examples
  run_recorded_gate GZ "$WORKTREE" gz-mypy \
    'packages/gove-zone:local-gate' "$(node_cwd_scope REPO_ROOT)" \
    "${GZ_PREFIX[@]}" mypy packages/gove-zone/src/gove_zone
  run_recorded_gate GZ "$WORKTREE" gz-pytest \
    'packages/gove-zone:local-gate' "$(node_cwd_scope REPO_ROOT)" \
    "${GZ_PREFIX[@]}" python -m pytest packages/gove-zone/tests \
    --import-mode=importlib -q --cov=gove_zone --cov-fail-under=90
fi

run_contained "$WORKTREE" "$EVIDENCE_PY" "$WORKTREE/scripts/evidence/capture_environment.py" \
  --code CP \
  --interpreter "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" \
  --lock "$WORKTREE/requirements/saas-beta/cp-test.lock" \
  --require-editables 0.6 \
  --output "$NODE_EVIDENCE/environment-CP.json"
if [[ "$INCLUDE_GZ" == 1 ]]; then
  run_contained "$WORKTREE" "$EVIDENCE_PY" "$WORKTREE/scripts/evidence/capture_environment.py" \
    --code GZ \
    --interpreter "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" \
    --lock "$WORKTREE/requirements/saas-beta/gz-test.lock" \
    --require-editables 0.6 \
    --output "$NODE_EVIDENCE/environment-GZ.json"
fi
run_contained "$WORKTREE" "$EVIDENCE_PY" \
  "$WORKTREE/scripts/evidence/validate_environment_identities.py" \
  --node "$NODE_ID" \
  --assignment-map "$WORKTREE/requirements/saas-beta/bootstrap-by-scope.json" \
  --assignment "$ASSIGNED_BOOTSTRAPS" \
  --identity-dir "$NODE_EVIDENCE" \
  --require-fresh-bootstrap-records \
  --reject-missing \
  --reject-extra \
  --reject-unassigned-runtime-paths \
  --output "$NODE_EVIDENCE/environment-identities.json"

if [[ "$NODE_ID" == P0-EVIDENCE-000 ]]; then
  P0_ROOT_GATE=(.venv-evidence/bin/python -m pytest -q \
    tests/saas_beta/test_evidence_bootstrap.py::test_clean_sibling_hash_locked_bootstraps_and_round_trip \
    tests/saas_beta/test_evidence_bootstrap.py::test_clean_sibling_rejects_loader_and_git_authority_before_mutation \
    tests/saas_beta/test_evidence_bootstrap.py::test_environment_identities_exactly_match_assignment \
    tests/saas_beta/test_evidence_bootstrap.py::test_missing_extra_or_retained_environment_rejected \
    tests/saas_beta/test_evidence_bootstrap.py::test_pep660_helpers_required_for_assigned_python_scopes)
  export ACGS_P0_LITERAL_PROVER_INNER_T="$T"
  run_recorded_gate P0 "$WORKTREE" p0-root-gate 'root:P0-EVIDENCE-000' __NONE__ \
    "${P0_ROOT_GATE[@]}"
  unset ACGS_P0_LITERAL_PROVER_INNER_T
elif [[ "$NODE_ID" == P1-MIGRATION-001 ]]; then
  P1_MIGRATION_GATE=(./scripts/run_postgres_gate.sh \
    tests/integration/test_migrations_postgres.py::test_empty_and_existing_alpha_upgrade_head \
    tests/integration/test_migrations_postgres.py::test_declared_reversible_round_trip \
    tests/integration/test_migrations_postgres.py::test_mixed_version_rolling_compatibility \
    tests/integration/test_migrations_postgres.py::test_large_table_online_migration_budget \
    tests/integration/test_migrations_postgres.py::test_irreversible_restore_rehearsal \
    tests/integration/test_migrations_postgres.py::test_failed_migration_no_later_state)
  run_trusted_parent_postgres_gate CP "$WORKTREE/packages/acgs-control-plane" p1-migration-postgres \
    'packages/acgs-control-plane:P1-MIGRATION-001-postgres-gate' CP \
    "${P1_MIGRATION_GATE[@]}"
elif [[ "$NODE_ID" == P1-SCOPE-002 ]]; then
  P1_SCOPE_GATE=(.venv/bin/pytest -q \
    tests/test_project_environment_scope.py::test_environment_cannot_reference_a_project_from_another_org \
    tests/test_project_environment_scope.py::test_orm_models_use_the_same_composite_parent_join \
    tests/test_project_environment_scope.py::test_public_api_exposes_no_project_or_environment_mutation_routes \
    tests/test_repositories.py::test_prospective_scope_ids_persist_exactly_without_commit \
    tests/test_repositories.py::test_cross_tenant_reads_are_non_enumerating \
    tests/test_repositories.py::test_cross_tenant_updates_and_deletes_mutate_zero_rows \
    tests/test_repositories.py::test_prospective_id_conflicts_fail_atomically \
    tests/integration/test_production_posture.py::test_tenant_bootstrap_and_register_contract_stub_no_mutation)
  run_recorded_gate CP "$WORKTREE/packages/acgs-control-plane" p1-scope-posture \
    'packages/acgs-control-plane:P1-SCOPE-002-scope-posture-gate' CP \
    "${P1_SCOPE_GATE[@]}"
elif [[ "$NODE_ID" == P1-LEDGER-003 ]]; then
  P1_LEDGER_GATE=(.venv/bin/pytest -q \
    tests/test_managed_mutation_uow.py::test_allow_mutation_commits_consumption_receipt_event_and_outbox_atomically \
    tests/test_managed_mutation_uow.py::test_injected_failure_before_commit_rolls_back_consumption_receipt_event_outbox_and_side_effect \
    tests/test_managed_mutation_uow.py::test_deny_and_escalate_do_not_consume_or_execute_or_persist_success \
    tests/test_managed_mutation_uow.py::test_wrong_scope_receipt_rejected_by_database_tenant_environment_constraints \
    tests/test_managed_mutation_uow.py::test_concurrent_receipt_consumption_has_single_committed_winner \
    tests/test_managed_mutation_uow.py::test_outbox_rows_appear_only_after_sql_commit)
  run_recorded_gate CP "$WORKTREE/packages/acgs-control-plane" p1-ledger-uow \
    'packages/acgs-control-plane:P1-LEDGER-003-managed-mutation-uow-gate' CP \
    "${P1_LEDGER_GATE[@]}"
elif [[ "$NODE_ID" == P1-TRUST-004 ]]; then
  P1_TRUST_CP_GATE=(.venv/bin/pytest -q \
    tests/test_trust_receipt_v2.py::test_receipt_v2_scoped_trust_roots_bind_tenant_scope_and_trust_epoch \
    tests/test_trust_receipt_v2.py::test_active_retired_and_revoked_trust_rotation_preserves_history_and_blocks_new_or_revoked \
    tests/test_trust_receipt_v2.py::test_trust_readiness_report_requires_active_root_and_rotation_window \
    tests/test_trust_receipt_v2.py::test_wrong_scope_missing_trust_and_replay_reject_without_side_effect)
  run_recorded_gate CP "$WORKTREE/packages/acgs-control-plane" p1-trust-control-plane \
    'packages/acgs-control-plane:P1-TRUST-004-trust-control-plane-gate' CP \
    "${P1_TRUST_CP_GATE[@]}"
  P1_TRUST_GZ_GATE=("$UV_BIN" run --active --no-sync --python 3.11 --package gove-zone \
    python -m pytest \
    packages/gove-zone/tests/test_trust_receipt_v2.py::test_receipt_v2_scoped_trust_verification_requires_scope_binding \
    packages/gove-zone/tests/test_trust_receipt_v2.py::test_active_retired_revoked_runtime_rotation_verifies_historical_retired_and_denies_revoked \
    packages/gove-zone/tests/test_trust_receipt_v2.py::test_trust_readiness_runtime_reports_missing_or_expired_roots \
    packages/gove-zone/tests/test_trust_receipt_v2.py::test_wrong_scope_missing_trust_and_replay_runtime_do_not_execute \
    --import-mode=importlib -q)
  run_recorded_gate GZ "$WORKTREE" p1-trust-runtime \
    'packages/gove-zone:P1-TRUST-004-trust-runtime-gate' REPO_ROOT \
    "${P1_TRUST_GZ_GATE[@]}"
elif [[ "$NODE_ID" == P2-TENANT-BOOTSTRAP-000 ]]; then
  P2_TENANT_BOOTSTRAP_CP_GATE=(./scripts/run_postgres_gate.sh \
    tests/integration/test_tenant_bootstrap_vertical.py::test_real_api_postgres_bootstrap_allow_atomic \
    tests/integration/test_tenant_bootstrap_vertical.py::test_real_api_postgres_bootstrap_refusal_matrix \
    tests/integration/test_tenant_bootstrap_vertical.py::test_100_request_multiprocess_bootstrap_once)
  run_trusted_parent_postgres_gate CP \
    "$WORKTREE/packages/acgs-control-plane" p2-tenant-bootstrap-postgres \
    'packages/acgs-control-plane:P2-TENANT-BOOTSTRAP-000-postgres-bootstrap-gate' CP \
    "${P2_TENANT_BOOTSTRAP_CP_GATE[@]}"
  P2_TENANT_BOOTSTRAP_ROOT_GATE=(packages/acgs-control-plane/.venv/bin/python -m pytest -q \
    tests/saas_beta/test_cross_plane_contracts.py::test_tenant_bootstrap_receipt_contract)
  run_recorded_exact_pytest_gate P2 "$WORKTREE" p2-tenant-bootstrap-cross-plane \
    'root:P2-TENANT-BOOTSTRAP-000-cross-plane-contract' REPO_ROOT 1 \
    "${P2_TENANT_BOOTSTRAP_ROOT_GATE[@]}"
elif [[ "$NODE_ID" == P2-REGISTER-001 ]]; then
  P2_REGISTER_CP_GATE=(.venv/bin/pytest -q \
    tests/test_agent_registration_managed_route.py::test_agent_register_route_executes_through_managed_receipt_v2_spine \
    tests/test_agent_registration_managed_route.py::test_agent_register_route_refusal_matrix_has_zero_managed_side_effects \
    tests/test_agent_registration_managed_route.py::test_agent_register_route_scope_and_policy_are_server_owned)
  run_recorded_exact_pytest_gate CP "$WORKTREE/packages/acgs-control-plane" \
    p2-register-control-plane \
    'packages/acgs-control-plane:P2-REGISTER-001-agent-registration-gate' CP 3 \
    "${P2_REGISTER_CP_GATE[@]}"
  P2_REGISTER_GZ_GATE=("$UV_BIN" run --active --no-sync --python 3.11 --package gove-zone \
    python -m pytest \
    packages/gove-zone/tests/test_authz_enforcement.py::test_enforce_allows_registered_principal_through_dispatcher \
    packages/gove-zone/tests/test_authz_enforcement.py::test_enforce_denies_unregistered_actor_through_dispatcher \
    packages/gove-zone/tests/test_mcp_binding.py::test_unregistered_tool_cannot_run_and_is_not_audited \
    packages/gove-zone/tests/test_mcp_binding.py::test_runtime_registered_tool_is_gated_with_zero_binding_changes \
    --import-mode=importlib -q)
  run_recorded_exact_pytest_gate GZ "$WORKTREE" p2-register-runtime \
    'packages/gove-zone:P2-REGISTER-001-runtime-registration-gate' REPO_ROOT 4 \
    "${P2_REGISTER_GZ_GATE[@]}"
elif [[ "$NODE_ID" == P2-IDEMPOTENCY-002 ]]; then
  P2_IDEMPOTENCY_CP_GATE=(./scripts/run_postgres_gate.sh \
    tests/integration/test_agent_registration_idempotency_postgres.py::test_identical_key_and_canonical_request_converges_to_one_terminal_result \
    tests/integration/test_agent_registration_idempotency_postgres.py::test_same_key_different_canonical_request_conflicts_without_additional_side_effects \
    tests/integration/test_agent_registration_idempotency_postgres.py::test_exact_receipt_replay_is_typed_and_nonduplicating \
    tests/integration/test_agent_registration_idempotency_postgres.py::test_100_request_multiprocess_has_at_most_one_authorized_execution)
  run_trusted_parent_postgres_gate CP \
    "$WORKTREE/packages/acgs-control-plane" p2-idempotency-postgres \
    'packages/acgs-control-plane:P2-IDEMPOTENCY-002-postgres-idempotency-gate' CP \
    "${P2_IDEMPOTENCY_CP_GATE[@]}"
else
  die "unsupported clean-sibling node at product gate: $NODE_ID"
fi

phase B6
TRANSCRIPT_RECORDS="$(run_contained "$WORKTREE" \
  "$EVIDENCE_PY" - "$NODE_EVIDENCE/transcript.jsonl" <<'PY'
import pathlib
import sys

print(len(pathlib.Path(sys.argv[1]).read_bytes().splitlines()))
PY
)"
[[ "$TRANSCRIPT_RECORDS" == "$EXPECTED_TRANSCRIPT_RECORDS" ]] ||
  die "reviewed transcript must contain exactly $EXPECTED_TRANSCRIPT_RECORDS records"
run_contained "$WORKTREE" "$EVIDENCE_PY" scripts/evidence/generate_run.py \
  --schema schemas/evidence/acgs-run-evidence-v1.schema.json \
  --node "$NODE_ID" --parent "$P" --product "$T" --assignment "$ASSIGNED_BOOTSTRAPS" \
  --environment-identities "$NODE_EVIDENCE/environment-identities.json" \
  --transcript "$NODE_EVIDENCE/transcript.jsonl" \
  --output "$NODE_EVIDENCE/run.json"
run_contained "$WORKTREE" "$EVIDENCE_PY" scripts/evidence/validate_run.py \
  --schema schemas/evidence/acgs-run-evidence-v1.schema.json \
  --expected-node "$NODE_ID" \
  --assignment-map requirements/saas-beta/bootstrap-by-scope.json \
  --expected-environments "$ASSIGNED_BOOTSTRAPS" \
  --expected-parent "$P" --expected-product "$T" \
  "$NODE_EVIDENCE/run.json"
R="$(
  run_contained "$WORKTREE" "$EVIDENCE_PY" \
    scripts/evidence/hash_run_jcs.py "$NODE_EVIDENCE/run.json"
)"
[[ "$R" =~ ^[0-9a-f]{64}$ ]] || die 'JCS run hash is malformed'
PROOF_COMPLETE=1
