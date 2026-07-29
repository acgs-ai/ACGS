#!/bin/bash
# shellcheck disable=SC2016,SC2034 # inner snippets keep literal vars; helper state is consumed across sourced cleanup functions.
# Internal P0 prover. Invoke scripts/evidence/prove_clean_sibling instead.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077
ACGS_ATTEST_FD="${ACGS_CLEAN_SIBLING_ATTEST_FD:-}"
ACGS_DIAGNOSTIC_FD="${ACGS_CLEAN_SIBLING_DIAGNOSTIC_FD:-}"
ACGS_OUTPUT_MEMFD_FD="${ACGS_CLEAN_SIBLING_MEMFD_FD:-}"
ACGS_OUTPUT_MEMFD_IDENTITY="${ACGS_CLEAN_SIBLING_MEMFD_IDENTITY:-}"
ACGS_OUTPUT_GUARDIAN="${ACGS_CLEAN_SIBLING_OUTPUT_GUARDIAN:-0}"
ACGS_STATUS_FD="${ACGS_CLEAN_SIBLING_STATUS_FD:-}"
ACGS_STARTUP_BARRIER_FD="${ACGS_CLEAN_SIBLING_STARTUP_BARRIER_FD:-}"
ACGS_STARTUP_BARRIER_IDENTITY="${ACGS_CLEAN_SIBLING_STARTUP_BARRIER_IDENTITY:-}"
if [[ "$ACGS_OUTPUT_GUARDIAN" == 1 && -n "${ACGS_CLEAN_SIBLING_TMP_FD:-}" ]]; then
  [[ "$ACGS_STATUS_FD" =~ ^[0-9]+$ ]] || {
    printf 'CLEAN_SIBLING=FAIL phase=B0 reason=guardian output metadata missing\n' >&2
    exit 2
  }
  [[ -z "${ACGS_STARTUP_BARRIER_FD:-}${ACGS_STARTUP_BARRIER_IDENTITY:-}${ACGS_CLEAN_SIBLING_STARTUP_BARRIER_FD:-}${ACGS_CLEAN_SIBLING_STARTUP_BARRIER_IDENTITY:-}" ]] || {
    printf 'CLEAN_SIBLING=FAIL phase=B0 reason=stale startup barrier state on descriptor pass\n' >&2
    exit 2
  }
  [[ "$ACGS_CLEAN_SIBLING_TMP_FD" =~ ^[0-9]+$ &&
    -d "/proc/$$/fd/$ACGS_CLEAN_SIBLING_TMP_FD" ]] || {
    printf 'CLEAN_SIBLING=FAIL phase=B0 reason=trusted TMPDIR descriptor missing\n' >&2
    exit 2
  }
  unset ACGS_CLEAN_SIBLING_OUTPUT_GUARDIAN ACGS_CLEAN_SIBLING_STATUS_FD \
    ACGS_CLEAN_SIBLING_STARTUP_BARRIER_FD ACGS_CLEAN_SIBLING_STARTUP_BARRIER_IDENTITY \
    ACGS_STARTUP_BARRIER_FD ACGS_STARTUP_BARRIER_IDENTITY
elif [[ "$ACGS_OUTPUT_GUARDIAN" == 1 ]]; then
  [[ "$ACGS_STATUS_FD" =~ ^[0-9]+$ ]] || {
    printf 'CLEAN_SIBLING=FAIL phase=B0 reason=guardian output metadata missing\n' >&2
    exit 2
  }
  [[ "$ACGS_STARTUP_BARRIER_FD" =~ ^[0-9]+$ ]] || {
    printf 'CLEAN_SIBLING=FAIL phase=B0 reason=guardian startup barrier missing\n' >&2
    exit 2
  }
  [[ "$ACGS_STARTUP_BARRIER_IDENTITY" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9a-f]+$ ]] || {
    printf 'CLEAN_SIBLING=FAIL phase=B0 reason=guardian startup barrier identity missing\n' >&2
    exit 2
  }
  ACGS_STARTUP_BARRIER_ACTUAL="$(
    /usr/bin/stat -Lc '%d:%i:%u:%f' "/proc/$$/fd/$ACGS_STARTUP_BARRIER_FD" 2>/dev/null || true
  )"
  [[ "$ACGS_STARTUP_BARRIER_ACTUAL" == "$ACGS_STARTUP_BARRIER_IDENTITY" ]] || {
    printf 'CLEAN_SIBLING=FAIL phase=B0 reason=guardian startup barrier identity changed\n' >&2
    exit 2
  }
  if ! IFS= read -r -N 1 -u "$ACGS_STARTUP_BARRIER_FD" _acgs_startup_release; then
    printf 'CLEAN_SIBLING=FAIL phase=B0 reason=guardian startup barrier closed before release\n' >&2
    exit 2
  fi
  [[ "$_acgs_startup_release" == R ]] || {
    printf 'CLEAN_SIBLING=FAIL phase=B0 reason=guardian startup barrier token mismatch\n' >&2
    exit 2
  }
  exec {ACGS_STARTUP_BARRIER_FD}<&-
  ACGS_DEV_NULL_EXPECTED="$(/usr/bin/stat -Lc '%d:%i:%u:%f:%t:%T' /dev/null 2>/dev/null || true)"
  exec 0</dev/null
  ACGS_DEV_NULL_ACTUAL="$(/usr/bin/stat -Lc '%d:%i:%u:%f:%t:%T' /proc/$$/fd/0 2>/dev/null || true)"
  [[ -n "$ACGS_DEV_NULL_EXPECTED" && "$ACGS_DEV_NULL_ACTUAL" == "$ACGS_DEV_NULL_EXPECTED" ]] || {
    printf 'CLEAN_SIBLING=FAIL phase=B0 reason=guardian stdin is not authenticated /dev/null\n' >&2
    exit 2
  }
  unset _acgs_startup_release ACGS_STARTUP_BARRIER_FD ACGS_STARTUP_BARRIER_IDENTITY \
    ACGS_STARTUP_BARRIER_ACTUAL ACGS_CLEAN_SIBLING_STARTUP_BARRIER_FD \
    ACGS_CLEAN_SIBLING_STARTUP_BARRIER_IDENTITY ACGS_DEV_NULL_EXPECTED ACGS_DEV_NULL_ACTUAL
  printf 'ACGS_STARTUP_ACK_V1_CLOSED_UNSET' >&"$ACGS_STATUS_FD"
  ACGS_ATTEST_FD=1
  ACGS_DIAGNOSTIC_FD=2
fi
if [[ -z "$ACGS_ATTEST_FD" ]]; then
  exec {ACGS_ATTEST_FD}>&1
fi
if [[ -z "$ACGS_DIAGNOSTIC_FD" ]]; then
  exec {ACGS_DIAGNOSTIC_FD}>&2
fi
readonly ACGS_ATTEST_FD ACGS_DIAGNOSTIC_FD ACGS_OUTPUT_MEMFD_FD \
  ACGS_OUTPUT_MEMFD_IDENTITY ACGS_OUTPUT_GUARDIAN ACGS_STATUS_FD

early_fail() {
  printf 'CLEAN_SIBLING=FAIL phase=B0 reason=%s\n' "$*" >&"$ACGS_DIAGNOSTIC_FD"
  exit 2
}

if [[ -n "${ACGS_CLEAN_SIBLING_ATOMIC_FAULT+x}" ]]; then
  early_fail 'forbidden test-only atomic fault environment'
fi

STATIC_LAUNCHER_SHA256=98d9040015eb17931e17b45e00b5f49f2451326372d5107a3a280f1cb3aaf3fc
[[ "${ACGS_CLEAN_SIBLING_STATIC_LAUNCHER:-}" == "$STATIC_LAUNCHER_SHA256" ]] || {
  early_fail 'internal prover requires trusted static launcher'
}
ACGS_EXPECTED_INTERNAL="${ACGS_CLEAN_SIBLING_INTERNAL_PATH:-}"
ACGS_EXPECTED_LAUNCHER="${ACGS_CLEAN_SIBLING_LAUNCHER_PATH:-}"
[[ -n "$ACGS_EXPECTED_INTERNAL" && -n "$ACGS_EXPECTED_LAUNCHER" ]] || {
  early_fail 'trusted script descriptor metadata missing'
}
ACGS_STATIC_PARENT_PID="$PPID"
ACGS_GUARDIAN_PARENT_PID=''
ACGS_GUARDIAN_PARENT_START=''
ACGS_GUARDIAN_PARENT_ARGV_SCRIPT=''
ACGS_STATIC_PARENT_RETIRED=0
if [[ -n "${ACGS_CLEAN_SIBLING_TMP_FD:-}" || "$ACGS_OUTPUT_GUARDIAN" == 1 ]]; then
  # The descriptor-bearing pass may either be parented by the legacy sanitized
  # Bash guardian or directly by the static BusyBox launcher when the snapshot
  # handoff uses exec.  Authenticate the intermediate guardian only when it is
  # present; the static parent is still verified below in both cases.
  ACGS_GUARDIAN_PARENT_EXE="$(
    /usr/bin/readlink -f "/proc/$ACGS_STATIC_PARENT_PID/exe" 2>/dev/null || true
  )"
  if [[ "$ACGS_OUTPUT_GUARDIAN" == 1 && -z "$ACGS_GUARDIAN_PARENT_EXE" ]]; then
    ACGS_GUARDIAN_PARENT_PID="$ACGS_STATIC_PARENT_PID"
    ACGS_GUARDIAN_PARENT_START="$(
      /usr/bin/awk '{print $22}' "/proc/$ACGS_GUARDIAN_PARENT_PID/stat" 2>/dev/null || true
    )"
    ACGS_GUARDIAN_PARENT_ARGV_SCRIPT='python-guardian-nondumpable'
    ACGS_STATIC_PARENT_RETIRED=1
  elif [[ "$ACGS_GUARDIAN_PARENT_EXE" == /usr/bin/bash || \
    "$ACGS_GUARDIAN_PARENT_EXE" == /bin/bash ]]; then
    ACGS_GUARDIAN_PARENT_PID="$ACGS_STATIC_PARENT_PID"
    ACGS_GUARDIAN_PARENT_START="$(
      /usr/bin/awk '{print $22}' "/proc/$ACGS_GUARDIAN_PARENT_PID/stat" 2>/dev/null || true
    )"
    mapfile -d '' -t ACGS_GUARDIAN_PARENT_ARGV <"/proc/$ACGS_STATIC_PARENT_PID/cmdline"
    [[ "${#ACGS_GUARDIAN_PARENT_ARGV[@]}" == 5 && \
      "${ACGS_GUARDIAN_PARENT_ARGV[0]}" == /bin/bash && \
      "${ACGS_GUARDIAN_PARENT_ARGV[1]}" == --noprofile && \
      "${ACGS_GUARDIAN_PARENT_ARGV[2]}" == --norc && \
      "${ACGS_GUARDIAN_PARENT_ARGV[3]}" == "${BASH_SOURCE[0]}" && \
      "${ACGS_GUARDIAN_PARENT_ARGV[4]}" == "${1:-}" ]] || {
      early_fail 'sanitized guardian parent argv changed'
    }
    ACGS_GUARDIAN_PARENT_ARGV_SCRIPT="${ACGS_GUARDIAN_PARENT_ARGV[3]}"
    IFS=' ' read -r _ _ _ ACGS_STATIC_PARENT_PID _ \
      <"/proc/$ACGS_STATIC_PARENT_PID/stat"
  elif [[ "$ACGS_GUARDIAN_PARENT_EXE" == /usr/bin/busybox ]]; then
    :
  elif [[ "$ACGS_GUARDIAN_PARENT_EXE" == /usr/bin/python3.* ]]; then
    ACGS_GUARDIAN_PARENT_PID="$ACGS_STATIC_PARENT_PID"
    ACGS_GUARDIAN_PARENT_START="$(
      /usr/bin/awk '{print $22}' "/proc/$ACGS_GUARDIAN_PARENT_PID/stat" 2>/dev/null || true
    )"
    mapfile -d '' -t ACGS_GUARDIAN_PARENT_ARGV <"/proc/$ACGS_STATIC_PARENT_PID/cmdline"
    [[ "${#ACGS_GUARDIAN_PARENT_ARGV[@]}" == 6 && \
      "$(/usr/bin/readlink -f "${ACGS_GUARDIAN_PARENT_ARGV[0]}" 2>/dev/null || true)" == \
        /usr/bin/python3.* && \
      "${ACGS_GUARDIAN_PARENT_ARGV[1]}" == -I && \
      "${ACGS_GUARDIAN_PARENT_ARGV[2]}" == -S && \
      "${ACGS_GUARDIAN_PARENT_ARGV[3]}" == -c && \
      "${ACGS_GUARDIAN_PARENT_ARGV[4]}" == *ACGS_CLEAN_SIBLING_OUTPUT_GUARDIAN* && \
      "${ACGS_GUARDIAN_PARENT_ARGV[4]}" == *os.fork* && \
      "${ACGS_GUARDIAN_PARENT_ARGV[5]}" == "${1:-}" ]] || {
      early_fail 'sanitized Python guardian parent argv changed'
    }
    ACGS_GUARDIAN_PARENT_ARGV_SCRIPT='python-guardian'
    IFS=' ' read -r _ _ _ ACGS_STATIC_PARENT_PID _ \
      <"/proc/$ACGS_STATIC_PARENT_PID/stat"
  else
    early_fail 'sanitized guardian parent identity changed'
  fi
fi
if [[ "$ACGS_STATIC_PARENT_RETIRED" != 1 ]]; then
  [[ "$(/usr/bin/readlink -f "/proc/$ACGS_STATIC_PARENT_PID/exe" 2>/dev/null || true)" == \
    /usr/bin/busybox ]] || {
    early_fail 'static launcher parent identity changed'
  }
  [[ "$(/usr/bin/sha256sum "/proc/$ACGS_STATIC_PARENT_PID/exe" | \
    /usr/bin/awk '{print $1}')" == "$STATIC_LAUNCHER_SHA256" ]] || {
    early_fail 'static launcher parent digest changed'
  }
  mapfile -d '' -t ACGS_STATIC_PARENT_ARGV <"/proc/$ACGS_STATIC_PARENT_PID/cmdline"
  [[ "${#ACGS_STATIC_PARENT_ARGV[@]}" == 4 && \
    "${ACGS_STATIC_PARENT_ARGV[0]}" == /usr/bin/busybox && \
    "${ACGS_STATIC_PARENT_ARGV[1]}" == ash && \
    "$(/usr/bin/readlink -f "${ACGS_STATIC_PARENT_ARGV[2]}" 2>/dev/null || true)" == \
      "$ACGS_EXPECTED_LAUNCHER" && \
    "${ACGS_STATIC_PARENT_ARGV[3]}" == "${1:-}" ]] || {
    early_fail 'static launcher parent argv changed'
  }
fi
unset ACGS_GUARDIAN_PARENT_ARGV ACGS_GUARDIAN_PARENT_EXE \
  ACGS_STATIC_PARENT_ARGV ACGS_EXPECTED_LAUNCHER ACGS_EXPECTED_INTERNAL
ACGS_STATIC_LAUNCHED=1
ACGS_AUTH_TARGET="${1:-}"
ACGS_AUTH_LAUNCHER="$ACGS_CLEAN_SIBLING_LAUNCHER_PATH"
ACGS_AUTH_INTERNAL="$ACGS_CLEAN_SIBLING_INTERNAL_PATH"
ACGS_AUTH_PROVER_PID="$BASHPID"
ACGS_AUTH_PROVER_START="$(
  /usr/bin/awk '{print $22}' "/proc/$ACGS_AUTH_PROVER_PID/stat" 2>/dev/null || true
)"
ACGS_AUTH_STATIC_PARENT_PID="$ACGS_STATIC_PARENT_PID"
ACGS_AUTH_STATIC_PARENT_START="$(
  if [[ "$ACGS_STATIC_PARENT_RETIRED" == 1 ]]; then
    printf retired
  else
    /usr/bin/awk '{print $22}' "/proc/$ACGS_AUTH_STATIC_PARENT_PID/stat" 2>/dev/null || true
  fi
)"
ACGS_AUTH_GUARDIAN_PARENT_PID="$ACGS_GUARDIAN_PARENT_PID"
ACGS_AUTH_GUARDIAN_PARENT_START="$ACGS_GUARDIAN_PARENT_START"
ACGS_AUTH_GUARDIAN_PARENT_ARGV_SCRIPT="$ACGS_GUARDIAN_PARENT_ARGV_SCRIPT"
readonly ACGS_AUTH_TARGET ACGS_AUTH_LAUNCHER ACGS_AUTH_INTERNAL ACGS_AUTH_PROVER_PID \
  ACGS_AUTH_PROVER_START ACGS_AUTH_STATIC_PARENT_PID ACGS_AUTH_STATIC_PARENT_START \
  ACGS_AUTH_GUARDIAN_PARENT_PID ACGS_AUTH_GUARDIAN_PARENT_START \
  ACGS_AUTH_GUARDIAN_PARENT_ARGV_SCRIPT ACGS_STATIC_PARENT_RETIRED

validated_inherited_script_fd() {
  local label="$1"
  local fd_var="$2"
  local path_var="$3"
  local stat_var="$4"
  local sha_var="$5"
  local fd="${!fd_var:-}"
  local path="${!path_var:-}"
  local expected_stat="${!stat_var:-}"
  local expected_sha="${!sha_var:-}"
  [[ "$fd" =~ ^[0-9]+$ && -n "$path" && -n "$expected_stat" && -n "$expected_sha" ]] ||
    die "trusted $label descriptor metadata is missing"
  [[ -r "/proc/$BASHPID/fd/$fd" ]] || die "trusted $label descriptor is unavailable"
  [[ "$(realpath -e "/proc/$BASHPID/fd/$fd")" == "$path" ]] ||
    die "trusted $label descriptor path changed"
  [[ "$(stat -Lc '%d:%i:%u:%a:%h' -- "/proc/$BASHPID/fd/$fd")" == "$expected_stat" ]] ||
    die "trusted $label descriptor identity changed"
  [[ "$(sha256sum "/proc/$BASHPID/fd/$fd" | awk '{print $1}')" == "$expected_sha" ]] ||
    die "trusted $label descriptor digest changed"
}

verify_authenticated_launch_context() {
  local current_start=''
  local current_ppid=''
  local guardian_start=''
  local -a guardian_argv=()
  local static_start=''
  [[ "$BASHPID" == "$ACGS_AUTH_PROVER_PID" ]] || return 2
  current_ppid="$(/usr/bin/awk '{print $4}' "/proc/$ACGS_AUTH_PROVER_PID/stat" 2>/dev/null || true)"
  if [[ -n "$ACGS_AUTH_GUARDIAN_PARENT_PID" ]]; then
    [[ -n "$current_ppid" && "$current_ppid" == "$ACGS_AUTH_GUARDIAN_PARENT_PID" ]] ||
      return 2
    guardian_start="$(
      /usr/bin/awk '{print $22}' "/proc/$ACGS_AUTH_GUARDIAN_PARENT_PID/stat" 2>/dev/null || true
    )"
    [[ -n "$guardian_start" && "$guardian_start" == "$ACGS_AUTH_GUARDIAN_PARENT_START" ]] ||
      return 2
    mapfile -d '' -t guardian_argv <"/proc/$ACGS_AUTH_GUARDIAN_PARENT_PID/cmdline" ||
      return 2
    if [[ "$ACGS_AUTH_GUARDIAN_PARENT_ARGV_SCRIPT" == python-guardian-nondumpable ]]; then
      [[ -z "$(/usr/bin/readlink -f "/proc/$ACGS_AUTH_GUARDIAN_PARENT_PID/exe" 2>/dev/null || true)" ]] ||
        return 2
    elif [[ "$ACGS_AUTH_GUARDIAN_PARENT_ARGV_SCRIPT" == python-guardian ]]; then
      [[ "$(/usr/bin/readlink -f "/proc/$ACGS_AUTH_GUARDIAN_PARENT_PID/exe" 2>/dev/null || true)" == \
        /usr/bin/python3.* ]] || return 2
      [[ "${#guardian_argv[@]}" == 6 && \
        "$(/usr/bin/readlink -f "${guardian_argv[0]}" 2>/dev/null || true)" == \
          /usr/bin/python3.* && \
        "${guardian_argv[1]}" == -I && \
        "${guardian_argv[2]}" == -S && \
        "${guardian_argv[3]}" == -c && \
        "${guardian_argv[4]}" == *ACGS_CLEAN_SIBLING_OUTPUT_GUARDIAN* && \
        "${guardian_argv[4]}" == *os.fork* && \
        "${guardian_argv[5]}" == "$ACGS_AUTH_TARGET" ]] || return 2
    else
      [[ "$(/usr/bin/readlink -f "/proc/$ACGS_AUTH_GUARDIAN_PARENT_PID/exe" 2>/dev/null || true)" == \
        /usr/bin/bash || \
        "$(/usr/bin/readlink -f "/proc/$ACGS_AUTH_GUARDIAN_PARENT_PID/exe" 2>/dev/null || true)" == \
        /bin/bash ]] || return 2
      [[ "${#guardian_argv[@]}" == 5 && \
        "${guardian_argv[0]}" == /bin/bash && \
        "${guardian_argv[1]}" == --noprofile && \
        "${guardian_argv[2]}" == --norc && \
        "${guardian_argv[3]}" == "$ACGS_AUTH_GUARDIAN_PARENT_ARGV_SCRIPT" && \
        "${guardian_argv[4]}" == "$ACGS_AUTH_TARGET" ]] || return 2
    fi
  else
    [[ -n "$current_ppid" && "$current_ppid" == "$ACGS_AUTH_STATIC_PARENT_PID" ]] || return 2
  fi
  current_start="$(/usr/bin/awk '{print $22}' "/proc/$ACGS_AUTH_PROVER_PID/stat" 2>/dev/null || true)"
  [[ -n "$current_start" && "$current_start" == "$ACGS_AUTH_PROVER_START" ]] || return 2
  [[ "$(realpath -e "${BASH_SOURCE[0]}")" == "$ACGS_AUTH_INTERNAL" ]] || return 2
  [[ "${1:-$ACGS_AUTH_TARGET}" == "$ACGS_AUTH_TARGET" ]] || return 2
  validated_inherited_script_fd launcher \
    ACGS_CLEAN_SIBLING_LAUNCHER_FD ACGS_CLEAN_SIBLING_LAUNCHER_PATH \
    ACGS_CLEAN_SIBLING_LAUNCHER_STAT ACGS_CLEAN_SIBLING_LAUNCHER_SHA256 ||
    return 2
  validated_inherited_script_fd internal \
    ACGS_CLEAN_SIBLING_INTERNAL_FD ACGS_CLEAN_SIBLING_INTERNAL_PATH \
    ACGS_CLEAN_SIBLING_INTERNAL_STAT ACGS_CLEAN_SIBLING_INTERNAL_SHA256 ||
    return 2
  validated_inherited_script_fd cleanup \
    ACGS_CLEAN_SIBLING_CLEANUP_FD ACGS_CLEAN_SIBLING_CLEANUP_PATH \
    ACGS_CLEAN_SIBLING_CLEANUP_STAT ACGS_CLEAN_SIBLING_CLEANUP_SHA256 ||
    return 2
  if [[ "$ACGS_STATIC_PARENT_RETIRED" != 1 ]]; then
    static_start="$(
      /usr/bin/awk '{print $22}' "/proc/$ACGS_AUTH_STATIC_PARENT_PID/stat" 2>/dev/null || true
    )"
    [[ -n "$static_start" && "$static_start" == "$ACGS_AUTH_STATIC_PARENT_START" ]] || return 2
    [[ "$(/usr/bin/readlink -f "/proc/$ACGS_AUTH_STATIC_PARENT_PID/exe" 2>/dev/null || true)" == \
      /usr/bin/busybox ]] || return 2
    [[ "$(/usr/bin/sha256sum "/proc/$ACGS_AUTH_STATIC_PARENT_PID/exe" 2>/dev/null | \
      /usr/bin/awk '{print $1}')" == "$STATIC_LAUNCHER_SHA256" ]] || return 2
    local -a static_argv=()
    mapfile -d '' -t static_argv <"/proc/$ACGS_AUTH_STATIC_PARENT_PID/cmdline" || return 2
    [[ "${#static_argv[@]}" == 4 && \
      "${static_argv[0]}" == /usr/bin/busybox && \
      "${static_argv[1]}" == ash && \
      "$(/usr/bin/readlink -f "${static_argv[2]}" 2>/dev/null || true)" == "$ACGS_AUTH_LAUNCHER" && \
      "${static_argv[3]}" == "$ACGS_AUTH_TARGET" ]] || return 2
  fi
}

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
export UV_BIN
UV_FD="${ACGS_CLEAN_SIBLING_UV_FD:-}"
UV_FD_EXPECTED_PATH="${ACGS_CLEAN_SIBLING_UV_PATH:-}"
UV_FD_EXPECTED_STAT="${ACGS_CLEAN_SIBLING_UV_STAT:-}"
UV_FD_EXPECTED_SHA256="${ACGS_CLEAN_SIBLING_UV_SHA256:-}"
readonly UV_FD UV_FD_EXPECTED_PATH UV_FD_EXPECTED_STAT UV_FD_EXPECTED_SHA256
ACGS_SNAPSHOT_MODE="${ACGS_CLEAN_SIBLING_SNAPSHOT_MODE:-}"
ACGS_LAUNCHER_SNAPSHOT_FD="${ACGS_CLEAN_SIBLING_LAUNCHER_SNAPSHOT_FD:-}"
ACGS_LAUNCHER_SNAPSHOT_STAT="${ACGS_CLEAN_SIBLING_LAUNCHER_SNAPSHOT_STAT:-}"
ACGS_INTERNAL_SNAPSHOT_FD="${ACGS_CLEAN_SIBLING_INTERNAL_SNAPSHOT_FD:-}"
ACGS_INTERNAL_SNAPSHOT_STAT="${ACGS_CLEAN_SIBLING_INTERNAL_SNAPSHOT_STAT:-}"
ACGS_CLEANUP_SNAPSHOT_FD="${ACGS_CLEAN_SIBLING_CLEANUP_SNAPSHOT_FD:-}"
ACGS_CLEANUP_SNAPSHOT_STAT="${ACGS_CLEAN_SIBLING_CLEANUP_SNAPSHOT_STAT:-}"
ACGS_UV_SNAPSHOT_FD="${ACGS_CLEAN_SIBLING_UV_SNAPSHOT_FD:-}"
ACGS_UV_SNAPSHOT_STAT="${ACGS_CLEAN_SIBLING_UV_SNAPSHOT_STAT:-}"
readonly ACGS_SNAPSHOT_MODE ACGS_LAUNCHER_SNAPSHOT_FD ACGS_LAUNCHER_SNAPSHOT_STAT \
  ACGS_INTERNAL_SNAPSHOT_FD ACGS_INTERNAL_SNAPSHOT_STAT \
  ACGS_CLEANUP_SNAPSHOT_FD ACGS_CLEANUP_SNAPSHOT_STAT \
  ACGS_UV_SNAPSHOT_FD ACGS_UV_SNAPSHOT_STAT
ACGS_LAUNCHER_DATA_FD=''
ACGS_INTERNAL_DATA_FD=''
ACGS_CLEANUP_DATA_FD=''
ACGS_UV_DATA_FD=''
ACGS_POSTGRES_RUNNER_DATA_FD=''

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

finalize_clean_sibling_output() {
  local allow_pass="$1"
  local failure_reason="${2:-not-complete}"
  if [[ "$ACGS_OUTPUT_GUARDIAN" == 1 ]]; then
    printf 'CLEAN_SIBLING=FAIL phase=%s reason=guardian mode cannot seal visible output\n' \
      "${PHASE:-B0}" >&"$ACGS_DIAGNOSTIC_FD"
    return 2
  fi
  [[ "$ACGS_OUTPUT_MEMFD_FD" =~ ^[0-9]+$ && -n "$ACGS_OUTPUT_MEMFD_IDENTITY" ]] || {
    printf 'CLEAN_SIBLING=FAIL phase=%s reason=visible output memfd metadata missing\n' \
      "${PHASE:-B0}" >&"$ACGS_DIAGNOSTIC_FD"
    return 2
  }
  ACGS_FINALIZE_ALLOW_PASS="$allow_pass" \
  ACGS_FINALIZE_FAILURE_REASON="$failure_reason" \
  ACGS_FINALIZE_MEMFD_FD="$ACGS_OUTPUT_MEMFD_FD" \
  ACGS_FINALIZE_MEMFD_IDENTITY="$ACGS_OUTPUT_MEMFD_IDENTITY" \
  ACGS_FINALIZE_ATTEST_FD="$ACGS_ATTEST_FD" \
  ACGS_FINALIZE_DIAGNOSTIC_FD="$ACGS_DIAGNOSTIC_FD" \
  ACGS_FINALIZE_P="${P:-}" \
  ACGS_FINALIZE_T="${T:-}" \
  ACGS_FINALIZE_R="${R:-}" \
  ACGS_FINALIZE_TRANSCRIPT_RECORDS="${TRANSCRIPT_RECORDS:-}" \
  ACGS_FINALIZE_ASSIGNMENTS="${ASSIGNED_BOOTSTRAPS:-}" \
  exec /usr/bin/python3 -I -S <<'PY'
import fcntl
import mmap
import os
import stat

F_ADD_SEALS = 1033
F_GET_SEALS = 1034
F_SEAL_SEAL = 0x0001
F_SEAL_SHRINK = 0x0002
F_SEAL_GROW = 0x0004
F_SEAL_WRITE = 0x0008
REQUIRED_SEALS = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE
PASS_MARKER = b"CLEAN_SIBLING_TECHNICAL=PASS"


def getenv_fd(name: str) -> int:
    value = os.environ.get(name, "")
    if not value.isdigit():
        raise RuntimeError(f"{name} is not a numeric fd")
    return int(value)


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def fail(message: str, captured: bytes = b"") -> int:
    diagnostic_fd = getenv_fd("ACGS_FINALIZE_DIAGNOSTIC_FD")
    memfd = getenv_fd("ACGS_FINALIZE_MEMFD_FD")
    if captured and diagnostic_fd != memfd:
        write_all(diagnostic_fd, captured)
    write_all(
        diagnostic_fd,
        f"CLEAN_SIBLING=FAIL phase=FINAL reason={message}\n".encode(),
    )
    return 2


try:
    memfd = getenv_fd("ACGS_FINALIZE_MEMFD_FD")
    attest_fd = getenv_fd("ACGS_FINALIZE_ATTEST_FD")
    expected_identity = os.environ["ACGS_FINALIZE_MEMFD_IDENTITY"]
    st = os.fstat(memfd)
    actual_identity = f"{st.st_dev}:{st.st_ino}:{st.st_uid}:{stat.S_IMODE(st.st_mode):o}"
    if actual_identity != expected_identity:
        raise RuntimeError("visible output memfd identity changed")
    os.lseek(memfd, 0, os.SEEK_END)
    size = os.lseek(memfd, 0, os.SEEK_CUR)
    fcntl.fcntl(memfd, F_ADD_SEALS, REQUIRED_SEALS)
    seals = fcntl.fcntl(memfd, F_GET_SEALS)
    if seals != REQUIRED_SEALS:
        raise RuntimeError(f"visible output memfd seals mismatch: {seals}")
    if size:
        try:
            mmap.mmap(memfd, size, flags=mmap.MAP_SHARED, prot=mmap.PROT_WRITE)
        except OSError:
            pass
        else:
            raise RuntimeError("visible output memfd accepted writable mmap after sealing")
    os.lseek(memfd, 0, os.SEEK_SET)
    captured = b""
    while True:
        chunk = os.read(memfd, 1024 * 1024)
        if not chunk:
            break
        captured += chunk
    if PASS_MARKER in captured:
        raise RuntimeError("subordinate proof output attempted to emit technical PASS")
    if os.environ.get("ACGS_FINALIZE_ALLOW_PASS") != "1":
        reason = os.environ.get("ACGS_FINALIZE_FAILURE_REASON", "not-complete")
        raise RuntimeError(reason)
    write_all(attest_fd, captured)
    pass_line = (
        "CLEAN_SIBLING_TECHNICAL=PASS "
        f"P={os.environ['ACGS_FINALIZE_P']} "
        f"T={os.environ['ACGS_FINALIZE_T']} "
        f"R={os.environ['ACGS_FINALIZE_R']} "
        f"records={os.environ['ACGS_FINALIZE_TRANSCRIPT_RECORDS']} "
        f"assignments={os.environ['ACGS_FINALIZE_ASSIGNMENTS']} "
        "attestations=pending-independent-lanes\n"
    ).encode()
    write_all(attest_fd, pass_line)
except BaseException as exc:
    try:
        memfd = getenv_fd("ACGS_FINALIZE_MEMFD_FD")
        os.lseek(memfd, 0, os.SEEK_SET)
        captured_failure = b""
        while True:
            chunk = os.read(memfd, 1024 * 1024)
            if not chunk:
                break
            captured_failure += chunk
    except BaseException:
        captured_failure = b""
    if PASS_MARKER in captured_failure:
        captured_failure = b""
    raise SystemExit(fail(str(exc), captured_failure))
PY
}

die() {
  printf 'CLEAN_SIBLING=FAIL phase=%s reason=%s\n' "${PHASE:-B0}" "$*" >&2
  if [[ "${ACGS_CLEANUP_TRAP_ARMED:-0}" == 1 ]]; then
    exit 2
  fi
  if [[ "$ACGS_OUTPUT_GUARDIAN" == 1 ]]; then
    exit 2
  fi
  finalize_clean_sibling_output 0 "$*"
  exit 2
}

verify_uv_identity() {
  local uv_fd_path
  local uv_expected_identity
  [[ "$UV_FD" =~ ^[0-9]+$ && -n "$UV_FD_EXPECTED_PATH" &&
    -n "$UV_FD_EXPECTED_STAT" && -n "$UV_FD_EXPECTED_SHA256" ]] ||
    die 'trusted uv descriptor metadata is missing'
  [[ "$UV_FD_EXPECTED_PATH" == "$UV_BIN" ]] || die 'trusted uv descriptor path is unexpected'
  uv_fd_path="/proc/$BASHPID/fd/$UV_FD"
  uv_expected_identity="${UV_FD_EXPECTED_STAT%:*}"
  [[ -r "$uv_fd_path" && -x "$uv_fd_path" ]] || die 'trusted uv descriptor is unavailable'
  [[ "$(stat -Lc '%d:%i:%u:%a' -- "$uv_fd_path" 2>/dev/null || true)" == \
    "$uv_expected_identity" ]] || die 'trusted uv descriptor identity changed'
  [[ "$(sha256sum "$uv_fd_path" 2>/dev/null | /usr/bin/awk '{print $1}')" == "$UV_SHA256" &&
    "$UV_FD_EXPECTED_SHA256" == "$UV_SHA256" ]] ||
    die 'trusted uv digest mismatch'
}

verify_uv_identity

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
P2_VERTICAL_GATE_REVIEWED_BASE='7d81e853b56352822286eb08d592d9e87256868e'
P3_POLICY_REVIEWED_BASE='647385084d974322b0f8b9b82738d7b820044ece'
P3_MUTATIONS_REVIEWED_BASE='014fe1806600d52d55f06875a8c30c0b8a5b973b'
P3_APPROVAL_REVIEWED_BASE='a2299d510d792dd04646204653e405e0485204a6'
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
    EXPECTED_TRANSCRIPT_RECORDS=11
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
  P2-VERTICAL-GATE-003)
    [[ "$P" == "$P2_VERTICAL_GATE_REVIEWED_BASE" ]] ||
      die "P2-VERTICAL-GATE-003 reviewed parent must be exact $P2_VERTICAL_GATE_REVIEWED_BASE"
    ASSIGNED_BOOTSTRAPS='EVID+CP+GZ'
    INCLUDE_GZ=1
    EXPECTED_TRANSCRIPT_RECORDS=12
    TMP_BASENAME='acgs-p2-vertical-gate'
    ;;
  P3-POLICY-001)
    [[ "$P" == "$P3_POLICY_REVIEWED_BASE" ]] ||
      die "P3-POLICY-001 reviewed parent must be exact $P3_POLICY_REVIEWED_BASE"
    ASSIGNED_BOOTSTRAPS='EVID+CP'
    INCLUDE_GZ=0
    EXPECTED_TRANSCRIPT_RECORDS=7
    TMP_BASENAME='acgs-p3-policy'
    ;;
  P3-MUTATIONS-002)
    [[ "$P" == "$P3_MUTATIONS_REVIEWED_BASE" ]] ||
      die "P3-MUTATIONS-002 reviewed parent must be exact $P3_MUTATIONS_REVIEWED_BASE"
    ASSIGNED_BOOTSTRAPS='EVID+CP'
    INCLUDE_GZ=0
    EXPECTED_TRANSCRIPT_RECORDS=7
    TMP_BASENAME='acgs-p3-mutations'
    ;;
  P3-APPROVAL-003)
    [[ "$P" == "$P3_APPROVAL_REVIEWED_BASE" ]] ||
      die "P3-APPROVAL-003 reviewed parent must be exact $P3_APPROVAL_REVIEWED_BASE"
    ASSIGNED_BOOTSTRAPS='EVID+CP+GZ'
    INCLUDE_GZ=1
    EXPECTED_TRANSCRIPT_RECORDS=12
    TMP_BASENAME='acgs-p3-approval'
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
validated_inherited_script_fd launcher \
  ACGS_CLEAN_SIBLING_LAUNCHER_FD ACGS_CLEAN_SIBLING_LAUNCHER_PATH \
  ACGS_CLEAN_SIBLING_LAUNCHER_STAT ACGS_CLEAN_SIBLING_LAUNCHER_SHA256
validated_inherited_script_fd internal \
  ACGS_CLEAN_SIBLING_INTERNAL_FD ACGS_CLEAN_SIBLING_INTERNAL_PATH \
  ACGS_CLEAN_SIBLING_INTERNAL_STAT ACGS_CLEAN_SIBLING_INTERNAL_SHA256
validated_inherited_script_fd cleanup \
  ACGS_CLEAN_SIBLING_CLEANUP_FD ACGS_CLEAN_SIBLING_CLEANUP_PATH \
  ACGS_CLEAN_SIBLING_CLEANUP_STAT ACGS_CLEAN_SIBLING_CLEANUP_SHA256
# shellcheck source=scripts/evidence/clean_sibling_cleanup.sh
# shellcheck source=scripts/evidence/clean_sibling_cleanup.sh
source "/proc/$BASHPID/fd/$ACGS_CLEAN_SIBLING_CLEANUP_FD"
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
    exec "$SNAPSHOT_PYTHON" -I -S - "${BASH_SOURCE[0]}" "$@" <<'PY'
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
ACGS_POSTGRES_RECOVERY_ROOT=''
ACGS_POSTGRES_RECOVERY_ROOT_DEVICE=''
ACGS_POSTGRES_RECOVERY_ROOT_INODE=''
ACGS_POSTGRES_RECOVERY_ROOT_UID=''
ACGS_POSTGRES_RECOVERY_ROOT_MODE=''
ACGS_POSTGRES_RECOVERY_ROOT_MNT_ID=''
ACGS_POSTGRES_RECOVERY_OWNER_MARKER=''
QUOTA_ROOT=''
QUOTA_IMAGE=''
QUOTA_LOG=''
QUOTA_IMAGE_FD=''
QUOTA_IMAGE_IDENTITY=''
QUOTA_LOG_FD=''
QUOTA_LOG_IDENTITY=''
QUOTA_ROOT_FD=''
QUOTA_ROOT_IDENTITY=''
QUOTA_UNDERLAY_MNT_ID=''
QUOTA_MOUNT_IDENTITY=''
QUOTA_MOUNT_MNT_ID=''
QUOTA_MOUNT_FSTYPE=''
QUOTA_MOUNT_ROOT=''
QUOTA_MOUNT_POINT=''
QUOTA_MOUNTED=0
QUOTA_FUSE_PID=''
QUOTA_FUSE_STARTTIME=''
OWNER_MARKER=''
TMP_ROOT_DEVICE=''
TMP_ROOT_INODE=''
TMP_ROOT_UID=''
TMP_ROOT_MODE=''
TMP_ROOT_MNT_ID=''
WORKTREE=''
SOURCE_GIT_COMMON_DIR=''
EVIDENCE_ROOT=''
NODE_ID="$REQUESTED_NODE_ID"
NODE_EVIDENCE=''
SCRATCH_ROOT=''
RUNTIME_ROOT=''
BOOTSTRAP_ROOT=''
BOOTSTRAP_CACHE_ROOT=''
TRUSTED_LOCK_INPUT_ROOT=''
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
WORKTREE_GITFILE_PRE_DETACH_WITNESS=''
WORKTREE_ADMIN_SENTINEL=''
WORKTREE_ADMIN_SENTINEL_PATH=''
WORKTREE_ADMIN_SENTINEL_IDENTITY=''
TMP_ROOT_FD=''
TMP_ROOT_FD_IDENTITY=''
OWNER_MARKER_FD=''
OWNER_MARKER_FD_IDENTITY=''
OWNER_MARKER_CONTENT=''
RUN_JSON_FD=''
RUN_JSON_FD_IDENTITY=''
RUN_JSON_FD_SIZE=''
RUN_JSON_FD_SHA256=''
RUN_JSON_PATH=''
TRUSTED_LEDGER_ROOT=''
TRUSTED_LEDGER_FD=''
TRUSTED_LEDGER_ROOT_IDENTITY=''
ACGS_QUOTA_RECOVERY_BUNDLE_NAME=''
ACGS_QUOTA_RECOVERY_BUNDLE_FD=''
ACGS_QUOTA_RECOVERY_BUNDLE_IDENTITY=''
ACGS_QUOTA_RECOVERY_BUNDLE_SHA256=''
TRUSTED_TRANSCRIPT=''
TRUSTED_RUN_PATH=''
PROOF_COMPLETE=0
TRANSCRIPT_RECORDS=0
R=''

readonly ACGS_PROOF_QUOTA_BYTES=8589934592
readonly ACGS_PROOF_QUOTA_INODES=100000
readonly ACGS_DESCENDANT_FSIZE_BYTES=67108864
readonly ACGS_DESCENDANT_FSIZE_BLOCKS=65536
readonly FUSE2FS_BIN=/usr/bin/fuse2fs
readonly MKFS_EXT4_BIN=/usr/bin/mkfs.ext4
readonly FUSERMOUNT_BIN=/usr/bin/fusermount3
readonly MOUNTPOINT_BIN=/usr/bin/mountpoint

advance_transcript_records_after_append() {
  [[ "$TRANSCRIPT_RECORDS" =~ ^[0-9]+$ ]] ||
    die 'trusted transcript record counter is malformed'
  TRANSCRIPT_RECORDS=$((TRANSCRIPT_RECORDS + 1))
}

validate_exact_tool() {
  local tool="$1"
  local label="$2"
  local owner=''
  local mode=''
  [[ -x "$tool" && -f "$tool" && ! -L "$tool" ]] ||
    die "$label unavailable: $tool"
  IFS=: read -r owner mode < <(stat -c '%u:%a' -- "$tool")
  [[ "$owner" == 0 ]] || die "$label has unsafe ownership: $tool"
  (( (8#$mode & 0022) == 0 )) ||
    die "$label has unsafe ownership or mode: $tool"
}

configured_quota_bytes() {
  if [[ "${ACGS_CLEAN_SIBLING_TEST_QUOTA_ENABLE:-0}" == 1 ]]; then
    [[ "${ACGS_CLEAN_SIBLING_TEST_QUOTA_BYTES:-}" =~ ^[1-9][0-9]{6,}$ ]] ||
      die 'test quota byte override must be at least 1MiB'
    printf '%s\n' "$ACGS_CLEAN_SIBLING_TEST_QUOTA_BYTES"
    return
  fi
  printf '%s\n' "$ACGS_PROOF_QUOTA_BYTES"
}

configured_quota_inodes() {
  if [[ "${ACGS_CLEAN_SIBLING_TEST_QUOTA_ENABLE:-0}" == 1 ]]; then
    [[ "${ACGS_CLEAN_SIBLING_TEST_QUOTA_INODES:-}" =~ ^[1-9][0-9]{1,}$ ]] ||
      die 'test quota inode override must be at least 10'
    printf '%s\n' "$ACGS_CLEAN_SIBLING_TEST_QUOTA_INODES"
    return
  fi
  printf '%s\n' "$ACGS_PROOF_QUOTA_INODES"
}

lower_descendant_file_size_limit() {
  local limit=''
  ulimit -f "$ACGS_DESCENDANT_FSIZE_BLOCKS" ||
    die 'cannot lower descendant file size limit'
  limit="$("$SNAPSHOT_PYTHON" -I -S - "$ACGS_DESCENDANT_FSIZE_BYTES" <<'PY'
import resource
import sys

expected = int(sys.argv[1])
soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
print(f"{soft}:{hard}")
if soft != expected or hard != expected:
    raise SystemExit(2)
PY
  )" || die "descendant file size hard limit is not 64MiB: $limit"
  [[ "$limit" == "$ACGS_DESCENDANT_FSIZE_BYTES:$ACGS_DESCENDANT_FSIZE_BYTES" ]] ||
    die "descendant file size hard limit is not 64MiB: $limit"
}

mount_quota_root() {
  local quota_bytes=''
  local quota_inodes=''
  local deadline=0
  local image_identity=''
  local log_identity=''
  local mounted_dev_ino=''
  local mounted_fstype=''
  local mounted_mnt_id=''
  local mounted_point=''
  local mounted_root=''
  local root_binding=''
  local root_identity=''
  local root_mnt_id=''
  local mount_timeout="${ACGS_CLEAN_SIBLING_TEST_QUOTA_MOUNT_TIMEOUT_SECONDS:-30}"
  [[ "$mount_timeout" =~ ^[1-9][0-9]*$ ]] || die 'quota mount timeout must be a positive integer'
  validate_exact_tool "$FUSE2FS_BIN" 'quota filesystem mounter'
  validate_exact_tool "$MKFS_EXT4_BIN" 'quota filesystem formatter'
  validate_exact_tool "$FUSERMOUNT_BIN" 'quota filesystem unmount helper'
  validate_exact_tool "$MOUNTPOINT_BIN" 'quota mount verifier'
  [[ -c /dev/fuse ]] || die 'quota filesystem requires /dev/fuse'
  quota_bytes="$(configured_quota_bytes)"
  quota_inodes="$(configured_quota_inodes)"
  QUOTA_IMAGE="$(quota_create_private_file "$TMP_PARENT" "$TMP_BASENAME-quota" img)" ||
    die 'cannot create quota backing image'
  QUOTA_LOG="$(quota_create_private_file "$TMP_PARENT" "$TMP_BASENAME-quota" log)" ||
    die 'cannot create quota log'
  exec {QUOTA_IMAGE_FD}<>"$QUOTA_IMAGE" || die 'cannot hold quota backing image descriptor'
  exec {QUOTA_LOG_FD}<>"$QUOTA_LOG" || die 'cannot hold quota log descriptor'
  truncate -s "$quota_bytes" -- "/proc/$$/fd/$QUOTA_IMAGE_FD" ||
    die 'cannot size quota backing image'
  "$MKFS_EXT4_BIN" -q -F -N "$quota_inodes" "/proc/$$/fd/$QUOTA_IMAGE_FD" ||
    die 'cannot format quota backing image'
  image_identity="$(stat -Lc '%d:%i:%u:%a:%s' -- "/proc/$$/fd/$QUOTA_IMAGE_FD")"
  [[ "$image_identity" == *":$(id -u):600:$quota_bytes" ]] ||
    die 'quota backing image identity changed'
  [[ "$(stat -Lc '%d:%i:%u:%a:%s' -- "$QUOTA_IMAGE")" == "$image_identity" ]] ||
    die 'quota backing image path changed'
  QUOTA_IMAGE_IDENTITY="$image_identity"
  log_identity="$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$QUOTA_LOG_FD")"
  [[ "$log_identity" == *":$(id -u):600" ]] || die 'quota log identity changed'
  [[ "$(stat -Lc '%d:%i:%u:%a' -- "$QUOTA_LOG")" == "$log_identity" ]] ||
    die 'quota log path changed'
  QUOTA_LOG_IDENTITY="$log_identity"
  mkdir -m 700 "$QUOTA_ROOT" || die 'cannot create quota mountpoint'
  exec {QUOTA_ROOT_FD}<"$QUOTA_ROOT" || die 'cannot hold quota mountpoint descriptor'
  root_identity="$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$QUOTA_ROOT_FD")"
  [[ "$root_identity" == *":$(id -u):700" ]] || die 'quota mountpoint descriptor identity changed'
  [[ "$(stat -Lc '%d:%i:%u:%a' -- "$QUOTA_ROOT")" == "$root_identity" ]] ||
    die 'quota mountpoint path changed'
  QUOTA_ROOT_IDENTITY="$root_identity"
  root_binding="$(quota_root_fd_binding)" || die 'quota underlay mount binding is unsafe'
  IFS=$'\t' read -r root_identity root_mnt_id _ _ _ <<<"$root_binding"
  [[ "$root_identity" == "$QUOTA_ROOT_IDENTITY" ]] || die 'quota underlay identity changed'
  [[ "$root_mnt_id" =~ ^[0-9]+$ ]] || die 'quota underlay mount id is unsafe'
  QUOTA_UNDERLAY_MNT_ID="$root_mnt_id"
  (
    local fd=''
    local fd_num=''
    for fd in "/proc/$$/fd"/*; do
      fd_num="${fd##*/}"
      [[ "$fd_num" =~ ^[0-9]+$ && "$fd_num" -gt 2 && "$fd_num" != "$QUOTA_IMAGE_FD" ]] ||
        continue
      eval "exec ${fd_num}>&-"
    done
    exec "$FUSE2FS_BIN" -f -o fakeroot,auto_unmount "/proc/$$/fd/$QUOTA_IMAGE_FD" "$QUOTA_ROOT"
  ) >"/proc/$$/fd/$QUOTA_LOG_FD" 2>&1 &
  QUOTA_FUSE_PID=$!
  QUOTA_FUSE_STARTTIME="$(awk '{print $22}' "/proc/$QUOTA_FUSE_PID/stat" 2>/dev/null || true)"
  [[ "$QUOTA_FUSE_STARTTIME" =~ ^[0-9]+$ ]] ||
    die 'quota filesystem mounter identity is unavailable'
  deadline=$((SECONDS + mount_timeout))
  while (( SECONDS < deadline )); do
    case "$(quota_mountpoint_state)" in
      mounted)
        QUOTA_MOUNTED=1
        break
        ;;
      absent) ;;
      *) die 'quota mount verifier failed' ;;
    esac
    if ! kill -0 "$QUOTA_FUSE_PID" >/dev/null 2>&1; then
      die "quota filesystem mount failed: $(quota_log_summary)"
    fi
    sleep 0.1
  done
  [[ "$QUOTA_MOUNTED" == 1 ]] || die 'timed out mounting quota filesystem'
  [[ "$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$QUOTA_ROOT_FD")" == "$QUOTA_ROOT_IDENTITY" ]] ||
    die 'quota mountpoint identity is unsafe'
  quota_capture_mount_binding || die 'quota mount binding is unsafe'
  mounted_dev_ino="${QUOTA_MOUNT_IDENTITY%:*:*}"
  mounted_mnt_id="$QUOTA_MOUNT_MNT_ID"
  mounted_fstype="$QUOTA_MOUNT_FSTYPE"
  mounted_root="$QUOTA_MOUNT_ROOT"
  mounted_point="$QUOTA_MOUNT_POINT"
  quota_harden_mounted_root \
    "$QUOTA_MOUNT_IDENTITY"$'\t'"$QUOTA_MOUNT_MNT_ID"$'\t'"$QUOTA_MOUNT_FSTYPE"$'\t'"$QUOTA_MOUNT_ROOT"$'\t'"$QUOTA_MOUNT_POINT" ||
    die 'quota mounted root hardening is unsafe'
  quota_capture_mount_binding || die 'quota hardened mount binding is unsafe'
  [[ "${QUOTA_MOUNT_IDENTITY%:*:*}" == "$mounted_dev_ino" &&
    "$QUOTA_MOUNT_MNT_ID" == "$mounted_mnt_id" &&
    "$QUOTA_MOUNT_FSTYPE" == "$mounted_fstype" &&
    "$QUOTA_MOUNT_ROOT" == "$mounted_root" &&
    "$QUOTA_MOUNT_POINT" == "$mounted_point" ]] ||
    die 'quota hardened mount binding changed'
  [[ "$QUOTA_MOUNT_IDENTITY" == *":$(id -u):700" ]] ||
    die "quota mounted root must be owned by current user with mode 700: $QUOTA_MOUNT_IDENTITY"
}

quota_create_private_file() {
  local parent="$1"
  local prefix="$2"
  local suffix="$3"
  /usr/bin/python3 -I -S - "$parent" "$prefix" "$suffix" <<'PY'
import os
import secrets
import stat
import sys


def fail() -> None:
    raise SystemExit(2)


parent, prefix, suffix = sys.argv[1:4]
if not parent.startswith("/") or "/" in prefix or "/" in suffix:
    fail()
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    parent_stat = os.fstat(parent_fd)
    if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.getuid():
        fail()
    for _ in range(128):
        name = f"{prefix}.{secrets.token_hex(8)}.{suffix}"
        try:
            fd = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            continue
        try:
            os.fchmod(fd, 0o600)
            file_stat = os.fstat(fd)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_uid != os.getuid()
                or stat.S_IMODE(file_stat.st_mode) != 0o600
                or file_stat.st_nlink != 1
            ):
                fail()
            path = os.path.join(parent, name)
            path_stat = os.stat(path, follow_symlinks=False)
            if (
                path_stat.st_dev,
                path_stat.st_ino,
                path_stat.st_uid,
                stat.S_IMODE(path_stat.st_mode),
            ) != (
                file_stat.st_dev,
                file_stat.st_ino,
                file_stat.st_uid,
                stat.S_IMODE(file_stat.st_mode),
            ):
                fail()
            print(path)
            raise SystemExit(0)
        finally:
            os.close(fd)
    fail()
finally:
    os.close(parent_fd)
PY
}

quota_log_summary() {
  local payload=''
  [[ "$QUOTA_LOG_FD" =~ ^[0-9]+$ ]] || {
    printf 'unavailable'
    return
  }
  payload="$(head -c 4096 "/proc/$$/fd/$QUOTA_LOG_FD" 2>/dev/null | tr -cd '[:print:] \t' || true)"
  printf '%s' "$payload"
}

quota_root_fd_binding() {
  "$SNAPSHOT_PYTHON" -I -S - "${TMP_ROOT_FD:-}" <<'PY'
import os
import stat
import sys


def fail() -> None:
    raise SystemExit(2)


def decode_mountinfo_path(value: str) -> str:
    decoded = bytearray()
    index = 0
    while index < len(value):
        if (
            value[index] == "\\"
            and index + 3 < len(value)
            and all(ch in "01234567" for ch in value[index + 1:index + 4])
        ):
            decoded.append(int(value[index + 1:index + 4], 8))
            index += 4
            continue
        decoded.extend(value[index].encode("utf-8"))
        index += 1
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        fail()
    if "\t" in text or "\n" in text or "\x00" in text:
        fail()
    return text


try:
    parent_fd = int(sys.argv[1])
except (IndexError, ValueError):
    fail()
flags = (
    getattr(os, "O_PATH", os.O_RDONLY)
    | os.O_DIRECTORY
    | os.O_NOFOLLOW
    | os.O_CLOEXEC
)
try:
    fd = os.open("quota", flags, dir_fd=parent_fd)
except OSError:
    fail()
try:
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        fail()
    mnt_id = ""
    with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as fdinfo:
        for line in fdinfo:
            if line.startswith("mnt_id:"):
                mnt_id = line.split(":", 1)[1].strip()
                break
    if not mnt_id.isdigit():
        fail()
    fstype = ""
    mount_root = ""
    mount_point = ""
    with open("/proc/self/mountinfo", encoding="utf-8") as mountinfo:
        for line in mountinfo:
            parts = line.rstrip("\n").split()
            if not parts or parts[0] != mnt_id:
                continue
            try:
                sep = parts.index("-")
            except ValueError:
                fail()
            if sep + 3 > len(parts):
                fail()
            mount_root = decode_mountinfo_path(parts[3])
            mount_point = decode_mountinfo_path(parts[4])
            fstype = parts[sep + 1]
            break
    if not fstype or "/" in fstype or "\t" in fstype or "\n" in fstype:
        fail()
    if not mount_root.startswith("/") or not mount_point.startswith("/"):
        fail()
    mode = stat.S_IMODE(st.st_mode)
    print(
        f"{st.st_dev}:{st.st_ino}:{st.st_uid}:{mode:o}"
        f"\t{mnt_id}\t{fstype}\t{mount_root}\t{mount_point}"
    )
finally:
    os.close(fd)
PY
}

quota_recorded_mount_state() {
  "$SNAPSHOT_PYTHON" -I -S - \
    "${QUOTA_MOUNT_MNT_ID:-}" \
    "${QUOTA_MOUNT_FSTYPE:-}" \
    "${QUOTA_MOUNT_ROOT:-}" \
    "${QUOTA_MOUNT_POINT:-}" <<'PY'
import sys


def fail() -> None:
    raise SystemExit(2)


def decode_mountinfo_path(value: str) -> str:
    decoded = bytearray()
    index = 0
    while index < len(value):
        if (
            value[index] == "\\"
            and index + 3 < len(value)
            and all(ch in "01234567" for ch in value[index + 1:index + 4])
        ):
            decoded.append(int(value[index + 1:index + 4], 8))
            index += 4
            continue
        decoded.extend(value[index].encode("utf-8"))
        index += 1
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        fail()
    if "\t" in text or "\n" in text or "\x00" in text:
        fail()
    return text


try:
    expected_mnt_id, expected_fstype, expected_root, expected_point = sys.argv[1:5]
except ValueError:
    fail()
if not expected_mnt_id.isdigit() or not expected_fstype or not expected_root or not expected_point:
    fail()
with open("/proc/self/mountinfo", encoding="utf-8") as mountinfo:
    for line in mountinfo:
        parts = line.rstrip("\n").split()
        if not parts or parts[0] != expected_mnt_id:
            continue
        try:
            sep = parts.index("-")
        except ValueError:
            fail()
        if sep + 3 > len(parts):
            fail()
        observed_root = decode_mountinfo_path(parts[3])
        observed_point = decode_mountinfo_path(parts[4])
        observed_fstype = parts[sep + 1]
        if (
            observed_fstype == expected_fstype
            and observed_root == expected_root
            and observed_point == expected_point
        ):
            print("exact")
            raise SystemExit(0)
        print("mismatch")
        raise SystemExit(0)
print("absent")
PY
}

quota_gc_committed_parent_recovery_bundle() {
  [[ -n "${ACGS_QUOTA_RECOVERY_BUNDLE_NAME:-}" ]] || return 0
  [[ -n "${TMP_ROOT:-}" && ! -e "$TMP_ROOT" && ! -L "$TMP_ROOT" ]] || return 2
  [[ "$TMP_PARENT_FD" =~ ^[0-9]+$ && "$ACGS_QUOTA_RECOVERY_BUNDLE_FD" =~ ^[0-9]+$ ]] || return 2
  "$SNAPSHOT_PYTHON" -I -S - \
    "$TMP_PARENT_FD" "$ACGS_QUOTA_RECOVERY_BUNDLE_FD" \
    "$ACGS_QUOTA_RECOVERY_BUNDLE_NAME" "$ACGS_QUOTA_RECOVERY_BUNDLE_IDENTITY" \
    "$ACGS_QUOTA_RECOVERY_BUNDLE_SHA256" <<'PY'
import os
import stat
import sys


def fail(message: str) -> "None":
    print(f"quota artifact recovery GC refused: {message}", file=sys.stderr)
    raise SystemExit(2)


FAULT = os.environ.get("ACGS_CLEAN_SIBLING_TEST_QUOTA_ARTIFACT_FAULT", "")


def maybe_fault(stage: str) -> None:
    if FAULT == stage:
        fail(f"injected {stage}")


parent_fd = int(sys.argv[1])
bundle_fd = int(sys.argv[2])
bundle_name = sys.argv[3]
identity_text = sys.argv[4]
expected_sha256 = sys.argv[5]
gc_name = f"{bundle_name}.gc-pending"


def parse_identity(value: str) -> tuple[int, int, int, int, int]:
    parts = value.split(":")
    if len(parts) != 5:
        fail("bundle identity malformed")
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3], 8), int(parts[4]))
    except ValueError:
        fail("bundle identity malformed")


def bundle_identity(st: os.stat_result) -> tuple[int, int, int, int, int]:
    if not stat.S_ISREG(st.st_mode):
        fail("bundle descriptor is not a regular file")
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_size)


def sha256_fd(fd: int) -> str:
    import hashlib

    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def rename_noreplace(src_name: str, dst_name: str, src_dir_fd: int, dst_dir_fd: int) -> None:
    import ctypes

    SYS_RENAMEAT2 = 316
    RENAME_NOREPLACE = 1
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(
        SYS_RENAMEAT2,
        src_dir_fd,
        os.fsencode(src_name),
        dst_dir_fd,
        os.fsencode(dst_name),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), dst_name)


if not bundle_name.startswith(".acgs-quota-artifact-recovery-") or not bundle_name.endswith(".bundle"):
    fail("bundle basename is not recognized")
if "/" in bundle_name or bundle_name in {"", ".", ".."} or any(
    ord(ch) < 32 or ord(ch) == 127 for ch in bundle_name
):
    fail("bundle basename unsafe")
expected = parse_identity(identity_text)
fd_stat = os.fstat(bundle_fd)
path_stat = os.stat(bundle_name, dir_fd=parent_fd, follow_symlinks=False)
if bundle_identity(fd_stat) != expected or bundle_identity(path_stat) != expected:
    fail("bundle identity changed before GC")
if fd_stat.st_ino != path_stat.st_ino or fd_stat.st_dev != path_stat.st_dev:
    fail("bundle path does not match descriptor")
if fd_stat.st_nlink != 1:
    fail("bundle link count is not ready for final GC")
if sha256_fd(bundle_fd) != expected_sha256:
    fail("bundle digest changed before GC")
maybe_fault("ledger-bundle-final-gc-rename")
try:
    rename_noreplace(bundle_name, gc_name, parent_fd, parent_fd)
except OSError as exc:
    fail(f"bundle GC quarantine rename failed: {exc.strerror}")
maybe_fault("ledger-bundle-final-gc-parent-fsync")
os.fsync(parent_fd)
renamed_stat = os.stat(gc_name, dir_fd=parent_fd, follow_symlinks=False)
if bundle_identity(os.fstat(bundle_fd)) != expected or bundle_identity(renamed_stat) != expected:
    fail("bundle identity changed after GC quarantine")
if sha256_fd(bundle_fd) != expected_sha256:
    fail("bundle digest changed after GC quarantine")
maybe_fault("ledger-bundle-final-gc-unlink")
os.unlink(gc_name, dir_fd=parent_fd)
maybe_fault("ledger-bundle-final-gc-unlink-fsync")
os.fsync(parent_fd)
if os.fstat(bundle_fd).st_nlink != 0:
    fail("bundle descriptor still linked after final GC")
PY
}

quota_bound_artifacts_removed() {
  [[ "${QUOTA_MOUNTED:-0}" == 0 ]] || return 2
  [[ "$(quota_mountpoint_state)" == absent ]] || return 2
  [[ "$TMP_PARENT_FD" =~ ^[0-9]+$ ]] || return 2
  if [[ -z "${QUOTA_IMAGE:-}" && -z "${QUOTA_LOG:-}" ]]; then
    return 0
  fi
  local bundle_nonce=''
  local cleanup_rc=0
  local recovery_metadata=''
  local recovery_name=''
  local recovery_identity=''
  local recovery_sha256=''
  local recovery_fields=()
  bundle_nonce="$(/usr/bin/python3 -I -S - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)" || return 2
  [[ "$bundle_nonce" =~ ^[0-9a-f]{32}$ ]] || return 2
  [[ "$TRUSTED_LEDGER_FD" =~ ^[0-9]+$ ]] || return 2
  if recovery_metadata="$("$SNAPSHOT_PYTHON" -I -S - \
    "$TMP_PARENT_FD" "$TRUSTED_LEDGER_FD" \
    "$TRUSTED_LEDGER_ROOT" "$TRUSTED_LEDGER_ROOT_IDENTITY" "$bundle_nonce" \
    "${QUOTA_IMAGE:-}" "${QUOTA_IMAGE_FD:-}" "${QUOTA_IMAGE_IDENTITY:-}" \
    "${QUOTA_LOG:-}" "${QUOTA_LOG_FD:-}" "${QUOTA_LOG_IDENTITY:-}" <<'PY'
import os
import hashlib
import secrets
import stat
import sys


def fail(message: str) -> "None":
    print(f"quota artifact cleanup refused: {message}", file=sys.stderr)
    raise SystemExit(2)


FAULT = os.environ.get("ACGS_CLEAN_SIBLING_TEST_QUOTA_ARTIFACT_FAULT", "")


def maybe_fault(stage: str) -> None:
    if FAULT == stage:
        fail(f"injected {stage}")


def parse_identity(value: str, include_size: bool) -> tuple[int, ...]:
    expected_parts = 5 if include_size else 4
    parts = value.split(":")
    if len(parts) != expected_parts:
        fail("artifact identity malformed")
    parsed = []
    for index, part in enumerate(parts):
        base = 8 if index == 3 else 10
        try:
            parsed.append(int(part, base))
        except ValueError:
            fail("artifact identity malformed")
    return tuple(parsed)


def fd_identity(fd: int, include_size: bool, expected_links: int = 1) -> tuple[int, ...]:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        fail("artifact descriptor is not a regular file")
    if st.st_nlink != expected_links:
        fail("artifact descriptor link count changed")
    fields: tuple[int, ...] = (
        st.st_dev,
        st.st_ino,
        st.st_uid,
        stat.S_IMODE(st.st_mode),
    )
    if include_size:
        fields += (st.st_size,)
    return fields


def validate_item(
    label: str,
    parent_fd: int,
    parent_path: str,
    path: str,
    held_fd_text: str,
    identity_text: str,
    include_size: bool,
) -> dict[str, object]:
    if not path:
        return {}
    if not held_fd_text.isdigit():
        fail(f"{label} descriptor missing")
    held_fd = int(held_fd_text)
    expected = parse_identity(identity_text, include_size)
    if os.path.dirname(path) != parent_path:
        fail(f"{label} escaped authenticated parent")
    name = os.path.basename(path)
    if not name or "/" in name or name in {".", ".."}:
        fail(f"{label} basename unsafe")
    if fd_identity(held_fd, include_size) != expected:
        fail(f"{label} held descriptor identity changed")
    path_fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        if fd_identity(path_fd, include_size) != expected:
            fail(f"{label} path identity changed")
        if os.fstat(path_fd).st_nlink != 1:
            fail(f"{label} path link count changed")
        if os.stat(name, dir_fd=parent_fd, follow_symlinks=False).st_ino != os.fstat(path_fd).st_ino:
            fail(f"{label} path raced during validation")
    except Exception:
        os.close(path_fd)
        raise
    return {
        "label": label,
        "name": name,
        "held_fd": held_fd,
        "path_fd": path_fd,
        "expected": expected,
        "include_size": include_size,
        "tomb": f".acgs-quota-artifact-{label}-{secrets.token_hex(16)}",
        "moved": False,
        "size": expected[-1] if include_size else os.fstat(path_fd).st_size,
    }


parent_fd = int(sys.argv[1])
ledger_fd = int(sys.argv[2])
ledger_path = sys.argv[3]
ledger_identity = sys.argv[4]
bundle_nonce = sys.argv[5]
parent_path = os.readlink(f"/proc/self/fd/{parent_fd}")
bundle_tmp_name = f".acgs-quota-artifact-recovery-{bundle_nonce}.tmp"
bundle_name = f".acgs-quota-artifact-recovery-{bundle_nonce}.bundle"
ledger_bundle_name = f"quota-artifact-recovery-{bundle_nonce}.bundle"
bundle_fd = -1
bundle_committed = False
ledger_bundle_committed = False
items: list[dict[str, object]] = []


def parse_dir_identity(value: str) -> tuple[int, int, int, int]:
    parts = value.split(":")
    if len(parts) != 4:
        fail("trusted ledger identity malformed")
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3], 8))
    except ValueError:
        fail("trusted ledger identity malformed")


def fd_dir_identity(fd: int) -> tuple[int, int, int, int]:
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        fail("trusted ledger descriptor is not a directory")
    return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))


def validate_ledger_fd() -> None:
    if not ledger_path or not os.path.isabs(ledger_path):
        fail("trusted ledger path must be absolute")
    if fd_dir_identity(ledger_fd) != parse_dir_identity(ledger_identity):
        fail("trusted ledger descriptor identity changed")
    try:
        path_stat = os.stat(ledger_path, follow_symlinks=False)
    except OSError:
        fail("trusted ledger path is unavailable")
    fd_stat = os.fstat(ledger_fd)
    if (
        path_stat.st_dev,
        path_stat.st_ino,
        path_stat.st_uid,
        stat.S_IMODE(path_stat.st_mode),
    ) != (
        fd_stat.st_dev,
        fd_stat.st_ino,
        fd_stat.st_uid,
        stat.S_IMODE(fd_stat.st_mode),
    ):
        fail("trusted ledger path does not match descriptor")
    fd_path = os.path.realpath(f"/proc/self/fd/{ledger_fd}")
    if fd_path != os.path.realpath(ledger_path):
        fail("trusted ledger descriptor path changed")


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def copy_sparse_entry(src_fd: int, dst_fd: int, label: str, size: int) -> None:
    import hashlib
    import json

    write_all(
        dst_fd,
        (
            json.dumps({"entry": label, "size": size}, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8"),
    )
    offset = 0
    while offset < size:
        try:
            data_start = os.lseek(src_fd, offset, os.SEEK_DATA)
        except OSError as exc:
            if exc.errno == getattr(os, "ENXIO", 6):
                break
            raise
        try:
            data_end = os.lseek(src_fd, data_start, os.SEEK_HOLE)
        except OSError:
            data_end = size
        data_end = min(data_end, size)
        os.lseek(src_fd, data_start, os.SEEK_SET)
        remaining = data_end - data_start
        digest = hashlib.sha256()
        write_all(
            dst_fd,
            (
                json.dumps(
                    {"extent": label, "offset": data_start, "length": remaining},
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
        )
        while remaining > 0:
            chunk = os.read(src_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise OSError("short read while preserving quota artifact")
            digest.update(chunk)
            write_all(dst_fd, chunk)
            remaining -= len(chunk)
        write_all(
            dst_fd,
            (
                "\n"
                + json.dumps(
                    {"extent_sha256": label, "offset": data_start, "sha256": digest.hexdigest()},
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
        )
        offset = data_end


def sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def rename_noreplace(src_name: str, dst_name: str, src_dir_fd: int, dst_dir_fd: int) -> None:
    import ctypes

    SYS_RENAMEAT2 = 316
    RENAME_NOREPLACE = 1
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(
        SYS_RENAMEAT2,
        src_dir_fd,
        os.fsencode(src_name),
        dst_dir_fd,
        os.fsencode(dst_name),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), dst_name)


def write_recovery_bundle(fd: int) -> None:
    import json

    write_all(fd, b"ACGS-QUOTA-ARTIFACT-RECOVERY-v1\n")
    for item in items:
        maybe_fault(f"{item['label']}-copy")
        metadata = {
            "label": item["label"],
            "name": item["name"],
            "identity": item["expected"],
            "size": item["size"],
        }
        write_all(
            fd,
            (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "utf-8"
            ),
        )
        copy_sparse_entry(int(item["path_fd"]), fd, str(item["label"]), int(item["size"]))


def commit_ledger_recovery_bundle() -> None:
    global ledger_bundle_committed

    maybe_fault("ledger-bundle-link")
    os.link(bundle_name, ledger_bundle_name, src_dir_fd=parent_fd, dst_dir_fd=ledger_fd)
    parent_stat = os.stat(bundle_name, dir_fd=parent_fd, follow_symlinks=False)
    ledger_stat = os.stat(ledger_bundle_name, dir_fd=ledger_fd, follow_symlinks=False)
    if (
        parent_stat.st_dev != ledger_stat.st_dev
        or parent_stat.st_ino != ledger_stat.st_ino
        or parent_stat.st_nlink != 2
        or ledger_stat.st_nlink != 2
    ):
        fail("ledger recovery hardlink identity mismatch")
    ledger_check_fd = os.open(
        ledger_bundle_name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=ledger_fd
    )
    try:
        if sha256_fd(bundle_fd) != sha256_fd(ledger_check_fd):
            fail("ledger recovery hardlink digest mismatch")
    finally:
        os.close(ledger_check_fd)
    maybe_fault("ledger-bundle-destination-fsync")
    os.fsync(ledger_fd)
    maybe_fault("ledger-bundle-source-fsync")
    os.fsync(parent_fd)
    recovery_sha256 = sha256_fd(bundle_fd)
    print(bundle_name)
    print(
        ":".join(
            str(value)
            for value in (
                parent_stat.st_dev,
                parent_stat.st_ino,
                parent_stat.st_uid,
                f"{stat.S_IMODE(parent_stat.st_mode):o}",
                parent_stat.st_size,
            )
        )
    )
    print(recovery_sha256)
    sys.stdout.flush()
    ledger_bundle_committed = True

def commit_recovery_bundle() -> None:
    global bundle_committed, bundle_fd

    if not items:
        return
    maybe_fault("bundle-create")
    bundle_fd = os.open(
        bundle_tmp_name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
        dir_fd=parent_fd,
    )
    try:
        write_recovery_bundle(bundle_fd)
        maybe_fault("bundle-fsync")
        os.fsync(bundle_fd)
        maybe_fault("bundle-rename")
        rename_noreplace(bundle_tmp_name, bundle_name, parent_fd, parent_fd)
        os.fsync(parent_fd)
        bundle_committed = True
        commit_ledger_recovery_bundle()
    except Exception:
        raise


def main() -> None:
    global items
    validate_ledger_fd()
    if not bundle_nonce or any(ch not in "0123456789abcdef" for ch in bundle_nonce) or len(bundle_nonce) != 32:
        fail("bundle nonce malformed")
    items = [
        validate_item("image", parent_fd, parent_path, sys.argv[6], sys.argv[7], sys.argv[8], True),
        validate_item("log", parent_fd, parent_path, sys.argv[9], sys.argv[10], sys.argv[11], False),
    ]
    items = [item for item in items if item]
    commit_recovery_bundle()
    for item in items:
        os.rename(item["name"], item["tomb"], src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        item["moved"] = True
    for item in items:
        tomb_fd = os.open(
            item["tomb"],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            if fd_identity(tomb_fd, item["include_size"]) != item["expected"]:
                fail(f"{item['label']} tomb identity changed")
            if os.fstat(tomb_fd).st_nlink != 1:
                fail(f"{item['label']} tomb link count changed")
            if os.fstat(tomb_fd).st_ino != os.fstat(item["path_fd"]).st_ino:
                fail(f"{item['label']} renamed a different artifact")
            if fd_identity(item["held_fd"], item["include_size"]) != item["expected"]:
                fail(f"{item['label']} held descriptor changed after rename")
        finally:
            os.close(tomb_fd)
    for item in items:
        maybe_fault(f"{item['label']}-unlink")
        os.unlink(item["tomb"], dir_fd=parent_fd)
    maybe_fault("after-original-unlink-before-parent-fsync")
    os.fsync(parent_fd)
    maybe_fault("after-original-unlink-after-parent-fsync")
    for item in items:
        if fd_identity(item["held_fd"], item["include_size"], expected_links=0) != item["expected"]:
            fail(f"{item['label']} held descriptor changed after unlink")
        if os.fstat(item["held_fd"]).st_nlink != 0:
            fail(f"{item['label']} still linked after cleanup")


try:
    main()
except SystemExit:
    raise
except Exception as exc:
    fail(f"artifact pair transaction failed: {exc}")
finally:
    for item in reversed(items):
        if item.get("moved"):
            try:
                os.stat(item["tomb"], dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                pass
            else:
                try:
                    os.rename(item["tomb"], item["name"], src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                except OSError:
                    pass
        path_fd = item.get("path_fd")
        if isinstance(path_fd, int):
            os.close(path_fd)
    if bundle_fd >= 0:
        os.close(bundle_fd)
PY
  )"; then
    cleanup_rc=0
  else
    cleanup_rc=$?
  fi
  if [[ -n "$recovery_metadata" ]]; then
    mapfile -t recovery_fields <<<"$recovery_metadata"
    [[ "${#recovery_fields[@]}" == 3 ]] || return 2
    recovery_name="${recovery_fields[0]}"
    recovery_identity="${recovery_fields[1]}"
    recovery_sha256="${recovery_fields[2]}"
    [[ "$recovery_name" == ".acgs-quota-artifact-recovery-$bundle_nonce.bundle" ]] || return 2
    [[ "$recovery_identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-7]+:[0-9]+$ ]] || return 2
    [[ "$recovery_sha256" =~ ^[0-9a-f]{64}$ ]] || return 2
    [[ -f "$TMP_PARENT/$recovery_name" && ! -L "$TMP_PARENT/$recovery_name" ]] ||
      return 2
    exec {ACGS_QUOTA_RECOVERY_BUNDLE_FD}<"$TMP_PARENT/$recovery_name"
    ACGS_QUOTA_RECOVERY_BUNDLE_NAME="$recovery_name"
    ACGS_QUOTA_RECOVERY_BUNDLE_IDENTITY="$(
      stat -Lc '%d:%i:%u:%a:%s' -- "/proc/$$/fd/$ACGS_QUOTA_RECOVERY_BUNDLE_FD"
    )" || return 2
    ACGS_QUOTA_RECOVERY_BUNDLE_SHA256="$(
      sha256sum "/proc/$$/fd/$ACGS_QUOTA_RECOVERY_BUNDLE_FD" | awk '{print $1}'
    )" || return 2
    [[ "$ACGS_QUOTA_RECOVERY_BUNDLE_IDENTITY" == "$recovery_identity" ]] || return 2
    [[ "$ACGS_QUOTA_RECOVERY_BUNDLE_SHA256" == "$recovery_sha256" ]] || return 2
  fi
  [[ "$cleanup_rc" == 0 ]] || return "$cleanup_rc"
}

quota_capture_mount_binding() {
  local binding=''
  local confirmed=''
  local identity=''
  local mnt_id=''
  local fstype=''
  local mount_root=''
  local mount_point=''
  binding="$(quota_root_fd_binding)" || return 2
  IFS=$'\t' read -r identity mnt_id fstype mount_root mount_point <<<"$binding"
  [[ "$identity" != "$QUOTA_ROOT_IDENTITY" ]] || return 2
  [[ "$mnt_id" =~ ^[0-9]+$ ]] || return 2
  [[ "$mnt_id" != "$QUOTA_UNDERLAY_MNT_ID" ]] || return 2
  case "$fstype" in
    fuse | fuse.* | fuse2fs) ;;
    *) return 2 ;;
  esac
  [[ "$mount_root" == /* && "$mount_point" == /* ]] || return 2
  [[ "$mount_point" == "$QUOTA_ROOT" ]] || return 2
  confirmed="$(quota_root_fd_binding)" || return 2
  [[ "$confirmed" == "$binding" ]] || return 2
  QUOTA_MOUNT_IDENTITY="$identity"
  QUOTA_MOUNT_MNT_ID="$mnt_id"
  QUOTA_MOUNT_FSTYPE="$fstype"
  QUOTA_MOUNT_ROOT="$mount_root"
  QUOTA_MOUNT_POINT="$mount_point"
}

quota_harden_mounted_root() {
  "$SNAPSHOT_PYTHON" -I -S - "${TMP_ROOT_FD:-}" "${1:-}" "$(id -u)" "$(id -g)" <<'PY'
import os
import stat
import sys


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def fd_mnt_id(fd: int) -> str:
    with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as fdinfo:
        for line in fdinfo:
            if line.startswith("mnt_id:"):
                mnt_id = line.split(":", 1)[1].strip()
                if not mnt_id.isdigit():
                    fail("quota mounted root descriptor mount id is unsafe")
                return mnt_id
    fail("quota mounted root descriptor mount id is unavailable")


def stat_identity(fd: int) -> tuple[int, int, int, int, int]:
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        fail("quota mounted root descriptor is not a directory")
    return st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)


fd = -1
try:
    try:
        parent_fd = int(sys.argv[1])
        expected = tuple(sys.argv[2].split("\t"))
        expected_uid = int(sys.argv[3])
        expected_gid = int(sys.argv[4])
    except (IndexError, ValueError):
        fail("quota mounted root hardening arguments are invalid")
    if len(expected) != 5:
        fail("quota mounted root expected binding is invalid")
    try:
        expected_dev, expected_ino, expected_pre_uid, expected_pre_mode = (
            int(part, 8 if index == 3 else 10)
            for index, part in enumerate(expected[0].split(":"))
        )
    except ValueError:
        fail("quota mounted root expected identity is invalid")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("quota", flags, dir_fd=parent_fd)
    before_dev, before_ino, before_uid, _before_gid, before_mode = stat_identity(fd)
    before_mnt_id = fd_mnt_id(fd)
    if (
        before_dev != expected_dev
        or before_ino != expected_ino
        or before_uid != expected_pre_uid
        or before_mode != expected_pre_mode
        or before_mnt_id != expected[1]
    ):
        fail("quota mounted root binding changed before hardening")
    fault = os.environ.get("ACGS_CLEAN_SIBLING_TEST_QUOTA_HARDEN_FAULT", "")
    if fault == "chmod_success_chown_fail":
        os.fchmod(fd, 0o700)
        fail("injected quota mounted root chown failure")
    os.fchown(fd, expected_uid, expected_gid)
    if fault == "chown_success_chmod_fail":
        fail("injected quota mounted root chmod failure")
    os.fchmod(fd, 0o700)
    after_dev, after_ino, after_uid, after_gid, after_mode = stat_identity(fd)
    after_mnt_id = fd_mnt_id(fd)
    if after_dev != expected_dev or after_ino != expected_ino or after_mnt_id != expected[1]:
        fail("quota mounted root binding changed after hardening")
    if after_uid != expected_uid or after_gid != expected_gid or after_mode != 0o700:
        fail(
            "quota mounted root must be owned by current user with mode 700: "
            f"{after_dev}:{after_ino}:{after_uid}:{after_gid}:{after_mode:o}"
        )
except OSError as exc:
    fail(f"quota mounted root descriptor hardening failed: {exc.strerror or exc.__class__.__name__}")
except UnicodeError:
    fail("quota mountinfo path is unsafe")
finally:
    if fd >= 0:
        os.close(fd)
PY
}

quota_mountpoint_state() {
  local binding=''
  local identity=''
  local mnt_id=''
  local fstype=''
  local mount_root=''
  local mount_point=''
  local recorded_state=''
  local rc=0
  if [[ -n "${QUOTA_MOUNT_IDENTITY:-}" && -n "${QUOTA_MOUNT_MNT_ID:-}" ]]; then
    binding="$(quota_root_fd_binding)" || {
      recorded_state="$(quota_recorded_mount_state 2>/dev/null || true)"
      if [[ "$recorded_state" == exact ]]; then
        printf 'mounted\n'
      else
        printf 'error\n'
      fi
      return
    }
    IFS=$'\t' read -r identity mnt_id fstype mount_root mount_point <<<"$binding"
    if [[ "$identity" == "$QUOTA_MOUNT_IDENTITY" &&
      "$mnt_id" == "$QUOTA_MOUNT_MNT_ID" &&
      "$fstype" == "$QUOTA_MOUNT_FSTYPE" &&
      "$mount_root" == "$QUOTA_MOUNT_ROOT" &&
      "$mount_point" == "$QUOTA_MOUNT_POINT" ]]; then
      printf 'mounted\n'
      return
    fi
    recorded_state="$(quota_recorded_mount_state 2>/dev/null || true)"
    [[ "$recorded_state" != mismatch ]] || {
      printf 'error\n'
      return
    }
    if [[ "$recorded_state" == exact &&
      "${identity%:*:*}" == "${QUOTA_MOUNT_IDENTITY%:*:*}" &&
      "$mnt_id" == "$QUOTA_MOUNT_MNT_ID" &&
      "$fstype" == "$QUOTA_MOUNT_FSTYPE" &&
      "$mount_root" == "$QUOTA_MOUNT_ROOT" &&
      "$mount_point" == "$QUOTA_MOUNT_POINT" ]]; then
      printf 'mounted\n'
      return
    fi
    if [[ "$identity" == "$QUOTA_ROOT_IDENTITY" &&
      "$mnt_id" == "$QUOTA_UNDERLAY_MNT_ID" &&
      "$recorded_state" == absent ]]; then
      printf 'absent\n'
      return
    fi
    printf 'error\n'
    return
  fi
  "$MOUNTPOINT_BIN" -q "$QUOTA_ROOT"
  rc=$?
  case "$rc" in
    0) printf 'mounted\n' ;;
    32) printf 'absent\n' ;;
    *) printf 'error\n' ;;
  esac
}

quota_mountpoint_absent() {
  [[ "$(quota_mountpoint_state)" == absent ]]
}

quota_bound_descriptors_match() {
  local observed=''
  if [[ -n "${QUOTA_IMAGE_FD:-}" ]]; then
    observed="$(stat -Lc '%d:%i:%u:%a:%s' -- "/proc/$$/fd/$QUOTA_IMAGE_FD" 2>/dev/null || true)"
    [[ "$observed" == "$QUOTA_IMAGE_IDENTITY" ]] || return 1
    [[ "$(stat -Lc '%d:%i:%u:%a:%s' -- "$QUOTA_IMAGE" 2>/dev/null || true)" == "$QUOTA_IMAGE_IDENTITY" ]] ||
      return 1
  fi
  if [[ -n "${QUOTA_LOG_FD:-}" ]]; then
    observed="$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$QUOTA_LOG_FD" 2>/dev/null || true)"
    [[ "$observed" == "$QUOTA_LOG_IDENTITY" ]] || return 1
    [[ "$(stat -Lc '%d:%i:%u:%a' -- "$QUOTA_LOG" 2>/dev/null || true)" == "$QUOTA_LOG_IDENTITY" ]] ||
      return 1
  fi
  if [[ -n "${QUOTA_ROOT_FD:-}" ]]; then
    observed="$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$QUOTA_ROOT_FD" 2>/dev/null || true)"
    [[ "$observed" == "$QUOTA_ROOT_IDENTITY" ]] || return 1
  fi
}

quota_fuse_read_stat() {
  local rest=''
  local stat_line=''
  stat_line="$(<"/proc/$QUOTA_FUSE_PID/stat")" || return 1
  rest="${stat_line##*) }"
  [[ "$rest" != "$stat_line" ]] || return 1
  # Intentional proc-stat field splitting after the parenthesized comm field.
  local IFS=' '
  # shellcheck disable=SC2086
  set -- $rest
  [[ "$#" -ge 20 ]] || return 1
  QUOTA_FUSE_STATE="$1"
  QUOTA_FUSE_PPID="$2"
  QUOTA_FUSE_CURRENT_STARTTIME="${20}"
}

quota_fuse_pid_started() {
  [[ "$QUOTA_FUSE_PID" =~ ^[0-9]+$ ]]
}

quota_fuse_started() {
  quota_fuse_pid_started && [[ "$QUOTA_FUSE_STARTTIME" =~ ^[0-9]+$ ]]
}

quota_fuse_pid_is_current_job() {
  local job_pid=''
  quota_fuse_pid_started || return 1
  while read -r job_pid; do
    [[ "$job_pid" == "$QUOTA_FUSE_PID" ]] && return 0
  done < <(jobs -pr)
  return 1
}

quota_fuse_read_pid_state() {
  local rest=''
  local stat_line=''
  stat_line="$(<"/proc/$QUOTA_FUSE_PID/stat")" || return 1
  rest="${stat_line##*) }"
  [[ "$rest" != "$stat_line" ]] || return 1
  # Intentional proc-stat field splitting after the parenthesized comm field.
  local IFS=' '
  # shellcheck disable=SC2086
  set -- $rest
  [[ "$#" -ge 1 ]] || return 1
  QUOTA_FUSE_STATE="$1"
}

quota_fuse_child_matches() {
  quota_fuse_started || return 1
  kill -0 "$QUOTA_FUSE_PID" >/dev/null 2>&1 || return 1
  quota_fuse_read_stat || return 1
  [[ "$QUOTA_FUSE_CURRENT_STARTTIME" == "$QUOTA_FUSE_STARTTIME" && "$QUOTA_FUSE_PPID" == "$$" ]]
}

quota_fuse_child_reaped_cleanly() {
  local wait_status=0
  quota_fuse_pid_started || return 0
  quota_fuse_started || return 2
  if [[ ! -r "/proc/$QUOTA_FUSE_PID/stat" ]]; then
    wait "$QUOTA_FUSE_PID" 2>/dev/null
    wait_status=$?
    QUOTA_FUSE_PID=''
    QUOTA_FUSE_STARTTIME=''
    [[ "$wait_status" == 0 ]] || return 2
    return 0
  fi
  quota_fuse_read_stat || return 2
  [[ "$QUOTA_FUSE_CURRENT_STARTTIME" == "$QUOTA_FUSE_STARTTIME" && "$QUOTA_FUSE_PPID" == "$$" ]] ||
    return 2
  [[ "$QUOTA_FUSE_STATE" == Z ]] || return 1
  wait "$QUOTA_FUSE_PID" 2>/dev/null
  wait_status=$?
  QUOTA_FUSE_PID=''
  QUOTA_FUSE_STARTTIME=''
  [[ "$wait_status" == 0 ]] || return 2
  return 0
}

quota_fuse_reap_unverified_pid() {
  quota_fuse_pid_started || return 0
  return 2
}

quota_fuse_force_terminate() {
  local reap_status=0
  quota_fuse_pid_started || return 0
  quota_fuse_started || {
    quota_fuse_reap_unverified_pid >/dev/null 2>&1 || true
    return 2
  }
  if ! quota_fuse_child_matches; then
    quota_fuse_child_reaped_cleanly >/dev/null 2>&1 || true
    return 2
  fi
  kill -KILL "$QUOTA_FUSE_PID" >/dev/null 2>&1 || true
  for _ in {1..20}; do
    if quota_fuse_child_reaped_cleanly; then
      reap_status=0
    else
      reap_status=$?
    fi
    case "$reap_status" in
      0 | 2) return 2 ;;
      1) ;;
      *) return 2 ;;
    esac
    sleep 0.05
  done
  return 2
}

detach_quota_root() {
  local reap_status=0
  local mount_present=0
  quota_bound_descriptors_match || return 2
  case "$(quota_mountpoint_state)" in
    mounted)
      mount_present=1
      QUOTA_MOUNTED=1
      ;;
    absent)
      QUOTA_MOUNTED=0
      ;;
    *) return 2 ;;
  esac
  if [[ "$mount_present" == 1 ]]; then
    quota_fuse_force_terminate >/dev/null 2>&1 || true
    for _ in {1..100}; do
      case "$(quota_mountpoint_state)" in
        absent)
          QUOTA_MOUNTED=0
          mount_present=0
          break
          ;;
        mounted) ;;
        *) quota_fuse_force_terminate >/dev/null 2>&1 || true; return 2 ;;
      esac
      sleep 0.1
    done
  fi
  [[ "$mount_present" == 0 && "$QUOTA_MOUNTED" == 0 ]] || {
    quota_fuse_force_terminate >/dev/null 2>&1 || true
    return 2
  }
  quota_fuse_pid_started || {
    quota_mountpoint_absent || return 2
    return 0
  }
  quota_fuse_started || {
    quota_fuse_reap_unverified_pid >/dev/null 2>&1 || true
    return 2
  }
  for _ in {1..100}; do
    if quota_fuse_child_reaped_cleanly; then
      reap_status=0
    else
      reap_status=$?
    fi
    case "$reap_status" in
      0)
        quota_mountpoint_absent || return 2
        quota_bound_descriptors_match || return 2
        return 0
        ;;
      1) ;;
      *)
        quota_fuse_force_terminate
        return 2
        ;;
    esac
    sleep 0.1
  done
  kill -TERM "$QUOTA_FUSE_PID" >/dev/null 2>&1 || true
  for _ in {1..10}; do
    if quota_fuse_child_reaped_cleanly; then
      reap_status=0
    else
      reap_status=$?
    fi
    case "$reap_status" in
      0) return 2 ;;
      1) ;;
      *)
        quota_fuse_force_terminate
        return 2
        ;;
    esac
    sleep 0.1
  done
  quota_fuse_force_terminate >/dev/null 2>&1 || true
  return 2
}

clean_sibling_gitfile_pre_detach_witness() {
  /usr/bin/python3 -I -S - \
    "$WORKTREE_GITFILE_PATH" \
    "$WORKTREE_GITFILE_IDENTITY" \
    "$WORKTREE_GITFILE_MODE" \
    "$WORKTREE_GITFILE_SIZE" \
    "$WORKTREE_GITFILE_SHA256" \
    "$WORKTREE_GITFILE_CONTENT_B64" <<'PY'
import hashlib
import json
import sys

payload = {
    "content_b64": sys.argv[6],
    "identity": sys.argv[2],
    "mode": sys.argv[3],
    "path": sys.argv[1],
    "sha256": sys.argv[5],
    "size": sys.argv[4],
}
encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
print(hashlib.sha256(encoded).hexdigest())
PY
}

record_worktree_gitfile_pre_detach_witness() {
  [[ "${WORKTREE_GITFILE_RETENTION_REQUIRED:-0}" == 1 ]] || return 0
  [[ -n "${WORKTREE_GITFILE_PATH:-}" &&
    -n "${WORKTREE_GITFILE_IDENTITY:-}" &&
    -n "${WORKTREE_GITFILE_MODE:-}" &&
    -n "${WORKTREE_GITFILE_SIZE:-}" &&
    -n "${WORKTREE_GITFILE_SHA256:-}" &&
    -n "${WORKTREE_GITFILE_CONTENT_B64:-}" ]] ||
    return 2
  [[ "$WORKTREE_GITFILE_IDENTITY" =~ ^[0-9]+:[0-9]+:[0-9]+$ &&
    "$WORKTREE_GITFILE_MODE" =~ ^[0-7]+$ &&
    "$WORKTREE_GITFILE_SIZE" =~ ^[0-9]+$ &&
    "$WORKTREE_GITFILE_SHA256" =~ ^[0-9a-f]{64}$ &&
    "$WORKTREE_GITFILE_CONTENT_B64" =~ ^[A-Za-z0-9+/=]+$ ]] ||
    return 2
  [[ -f "$WORKTREE_GITFILE_PATH" && ! -L "$WORKTREE_GITFILE_PATH" ]] ||
    return 2
  clean_sibling_validate_retained_gitfile \
    "${WORKTREE_GITFILE_FD:-}" \
    "$WORKTREE_GITFILE_PATH" \
    "$WORKTREE_GITFILE_IDENTITY" \
    "$WORKTREE_GITFILE_MODE" \
    "${WORKTREE_GITFILE_LINKS:-}" \
    "$WORKTREE_GITFILE_SIZE" \
    "$WORKTREE_GITFILE_SHA256" \
    "$WORKTREE_GITFILE_CONTENT_B64" \
    linked ||
    return 2
  WORKTREE_GITFILE_PRE_DETACH_WITNESS="$(clean_sibling_gitfile_pre_detach_witness)"
  [[ "$WORKTREE_GITFILE_PRE_DETACH_WITNESS" =~ ^[0-9a-f]{64}$ ]] || return 2
}

close_worktree_gitfile_after_witness() {
  [[ "${WORKTREE_GITFILE_RETENTION_REQUIRED:-0}" == 1 ]] || return 0
  [[ -n "${WORKTREE_GITFILE_FD:-}" &&
    -n "${WORKTREE_GITFILE_PATH:-}" &&
    -n "${WORKTREE_GITFILE_IDENTITY:-}" &&
    -n "${WORKTREE_GITFILE_MODE:-}" &&
    -n "${WORKTREE_GITFILE_SIZE:-}" &&
    -n "${WORKTREE_GITFILE_SHA256:-}" &&
    -n "${WORKTREE_GITFILE_CONTENT_B64:-}" &&
    -n "${WORKTREE_GITFILE_PRE_DETACH_WITNESS:-}" ]] ||
    return 2
  [[ "$WORKTREE_GITFILE_FD" =~ ^[0-9]+$ &&
    "$WORKTREE_GITFILE_IDENTITY" =~ ^[0-9]+:[0-9]+:[0-9]+$ &&
    "$WORKTREE_GITFILE_MODE" =~ ^[0-7]+$ &&
    "$WORKTREE_GITFILE_SIZE" =~ ^[0-9]+$ &&
    "$WORKTREE_GITFILE_SHA256" =~ ^[0-9a-f]{64}$ &&
    "$WORKTREE_GITFILE_CONTENT_B64" =~ ^[A-Za-z0-9+/=]+$ &&
    "$WORKTREE_GITFILE_PRE_DETACH_WITNESS" =~ ^[0-9a-f]{64}$ ]] ||
    return 2
  [[ -f "$WORKTREE_GITFILE_PATH" && ! -L "$WORKTREE_GITFILE_PATH" ]] ||
    return 2
  clean_sibling_validate_retained_gitfile \
    "$WORKTREE_GITFILE_FD" \
    "$WORKTREE_GITFILE_PATH" \
    "$WORKTREE_GITFILE_IDENTITY" \
    "$WORKTREE_GITFILE_MODE" \
    "${WORKTREE_GITFILE_LINKS:-}" \
    "$WORKTREE_GITFILE_SIZE" \
    "$WORKTREE_GITFILE_SHA256" \
    "$WORKTREE_GITFILE_CONTENT_B64" \
    linked ||
    return 2
  [[ "$(clean_sibling_gitfile_pre_detach_witness)" == "$WORKTREE_GITFILE_PRE_DETACH_WITNESS" ]] ||
    return 2
  local gitfile_fd="$WORKTREE_GITFILE_FD"
  exec {WORKTREE_GITFILE_FD}<&- || return 2
  WORKTREE_GITFILE_FD=''
  [[ ! -e "/proc/$$/fd/$gitfile_fd" && ! -L "/proc/$$/fd/$gitfile_fd" ]] ||
    return 2
  [[ -f "$WORKTREE_GITFILE_PATH" && ! -L "$WORKTREE_GITFILE_PATH" ]] ||
    return 2
}

cleanup() {
  local status=$?
  local cleanup_status=0
  local op_status=0
  local detach_status=0
  local quota_detach_failed=0
  local quota_cleanup_unsafe=0
  ACGS_CLEANUP_TRAP_ARMED=0
  set +e
  trap '' INT TERM
  record_worktree_gitfile_pre_detach_witness
  op_status=$?
  if [[ "$op_status" == 0 ]]; then
    close_worktree_gitfile_after_witness
    op_status=$?
  fi
  if [[ "$op_status" != 0 && "$cleanup_status" == 0 ]]; then
    cleanup_status=$op_status
  fi
  clean_sibling_retain_recovery_contracts
  op_status=$?
  if [[ "$op_status" != 0 && "$cleanup_status" == 0 ]]; then
    cleanup_status=$op_status
  fi
  detach_quota_root
  detach_status=$?
  if [[ "$detach_status" != 0 ]]; then
    if [[ "$cleanup_status" == 0 ]]; then
      cleanup_status=$detach_status
    fi
    quota_detach_failed=1
  fi
  if [[ "$quota_detach_failed" == 0 ]]; then
    quota_bound_artifacts_removed
    op_status=$?
    if [[ "$op_status" != 0 && "$cleanup_status" == 0 ]]; then
      cleanup_status=$op_status
    fi
    if [[ "$op_status" != 0 && -z "${ACGS_QUOTA_RECOVERY_BUNDLE_NAME:-}" ]]; then
      quota_cleanup_unsafe=1
    fi
  fi
  clean_sibling_cleanup "$status" "$quota_detach_failed" "$quota_cleanup_unsafe"
  op_status=$?
  if [[ "$op_status" != 0 && "$cleanup_status" == 0 ]]; then
    cleanup_status=$op_status
  fi
  trap - EXIT
  if [[ "$ACGS_OUTPUT_GUARDIAN" == 1 ]]; then
    if [[ "$cleanup_status" != 0 ]]; then
      printf 'CLEAN_SIBLING=FAIL phase=FINAL reason=cleanup-status-%s\n' "$cleanup_status" >&2
      if [[ "$status" != 0 ]]; then
        exit "$status"
      fi
      exit 2
    fi
    exit "$status"
  fi
  finalize_clean_sibling_output 0 "cleanup-status-$status"
  exit $?
}

emit_exact_clean_sibling_pass() {
  verify_authenticated_launch_context "$T" || die 'authenticated launch context changed'
  verify_post_cleanup_descriptors || die 'owned proof lifecycle changed during cleanup'
  verify_uv_identity
  [[ "$TRANSCRIPT_RECORDS" == "$EXPECTED_TRANSCRIPT_RECORDS" ]] ||
    die "reviewed transcript must contain exactly $EXPECTED_TRANSCRIPT_RECORDS records"
  [[ "$R" =~ ^[0-9a-f]{64}$ ]] || die 'JCS run hash is malformed'
  if [[ "$ACGS_OUTPUT_GUARDIAN" == 1 ]]; then
    /usr/bin/python3 -I -S - "$ACGS_STATUS_FD" "$P" "$T" "$R" \
      "$TRANSCRIPT_RECORDS" "$ASSIGNED_BOOTSTRAPS" "$RUN_JSON_FD" \
      "$RUN_JSON_FD_IDENTITY" "$RUN_JSON_FD_SIZE" "$RUN_JSON_FD_SHA256" <<'PY'
import array
import hashlib
import os
import socket
import stat
import sys

fd = int(sys.argv[1])
run_fd = int(sys.argv[7])
expected_identity = sys.argv[8]
expected_size = int(sys.argv[9])
expected_sha256 = sys.argv[10]
st = os.fstat(run_fd)
actual_identity = f"{st.st_dev}:{st.st_ino}:{st.st_uid}:{stat.S_IMODE(st.st_mode):o}"
if actual_identity != expected_identity or st.st_nlink != 0 or st.st_size != expected_size:
    raise SystemExit(2)
read_fd = os.dup(run_fd)
try:
    os.lseek(read_fd, 0, os.SEEK_SET)
    chunks = []
    remaining = expected_size
    while remaining:
        chunk = os.read(read_fd, min(1024 * 1024, remaining))
        if not chunk:
            raise SystemExit(2)
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(read_fd, 1):
        raise SystemExit(2)
finally:
    os.close(read_fd)
run_bytes = b"".join(chunks)
if hashlib.sha256(run_bytes).hexdigest() != expected_sha256:
    raise SystemExit(2)
frame = b"\0".join(
    [argument.encode() for argument in sys.argv[2:7]]
    + [
        expected_identity.encode(),
        str(expected_size).encode(),
        expected_sha256.encode(),
    ]
) + b"\0"
def send_status_body_once(sock, body, ancillary):
    sent = sock.sendmsg([body], ancillary)
    if sent <= 0:
        raise SystemExit(2)
    remaining = memoryview(body)[sent:]
    while remaining:
        sent = sock.send(remaining)
        if sent <= 0:
            raise SystemExit(2)
        remaining = remaining[sent:]
status_socket = socket.socket(fileno=fd)
status_socket.sendall(len(frame).to_bytes(4, "big"))
send_status_body_once(
    status_socket,
    frame,
    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [run_fd]))],
)
status_socket.detach()
PY
    exec {ACGS_STATUS_FD}>&-
    exit 0
  fi
  trap '' INT TERM
  finalize_clean_sibling_output 1 complete
}

verify_post_cleanup_descriptors() {
  local root_identity_after=''
  local root_links_after=''
  local marker_identity_after=''
  local marker_links_after=''
  local marker_content_after=''
  local run_json_identity_after=''
  local run_json_links_after=''
  local run_json_size_after=''
  local run_json_sha_after=''
  [[ -n "${TMP_ROOT_FD:-}" && -n "${TMP_ROOT_FD_IDENTITY:-}" ]] || return 2
  [[ -n "${OWNER_MARKER_FD:-}" && -n "${OWNER_MARKER_FD_IDENTITY:-}" ]] || return 2
  [[ -n "${RUN_JSON_FD:-}" && -n "${RUN_JSON_FD_IDENTITY:-}" && \
    -n "${RUN_JSON_FD_SIZE:-}" && -n "${RUN_JSON_FD_SHA256:-}" && \
    -n "${RUN_JSON_PATH:-}" ]] || return 2
  root_identity_after="$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$TMP_ROOT_FD" 2>/dev/null || true)"
  root_links_after="$(stat -Lc '%h' -- "/proc/$$/fd/$TMP_ROOT_FD" 2>/dev/null || true)"
  [[ "$root_identity_after" == "$TMP_ROOT_FD_IDENTITY" && "$root_links_after" == 0 ]] ||
    return 2
  marker_identity_after="$(stat -Lc '%d:%i:%u:%a:%s' -- "/proc/$$/fd/$OWNER_MARKER_FD" 2>/dev/null || true)"
  marker_links_after="$(stat -Lc '%h' -- "/proc/$$/fd/$OWNER_MARKER_FD" 2>/dev/null || true)"
  marker_content_after="$(cat "/proc/$$/fd/$OWNER_MARKER_FD" 2>/dev/null || true)"
  [[ "$marker_identity_after" == "$OWNER_MARKER_FD_IDENTITY" && "$marker_links_after" == 0 ]] ||
    return 2
  [[ "$marker_content_after" == "$OWNER_MARKER_CONTENT" ]] || return 2
  [[ ! -e "$RUN_JSON_PATH" && ! -L "$RUN_JSON_PATH" ]] || return 2
  run_json_identity_after="$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$RUN_JSON_FD" 2>/dev/null || true)"
  run_json_links_after="$(stat -Lc '%h' -- "/proc/$$/fd/$RUN_JSON_FD" 2>/dev/null || true)"
  run_json_size_after="$(stat -Lc '%s' -- "/proc/$$/fd/$RUN_JSON_FD" 2>/dev/null || true)"
  [[ "$run_json_identity_after" == "$RUN_JSON_FD_IDENTITY" && "$run_json_links_after" == 0 && \
    "$run_json_size_after" == "$RUN_JSON_FD_SIZE" ]] || return 2
  run_json_sha_after="$(sha256sum "/proc/$$/fd/$RUN_JSON_FD" 2>/dev/null |
    awk '{print $1}')"
  [[ "$run_json_sha_after" == "$RUN_JSON_FD_SHA256" ]] || return 2
  if [[ "${WORKTREE_GITFILE_RETENTION_REQUIRED:-0}" == 1 ]]; then
    local gitfile_witness_after=''
    [[ "${WORKTREE_REGISTRATION_REMOVED:-0}" == 1 &&
      "${WORKTREE_POST_REMOVE_GITFILE_VALIDATED:-0}" == 1 ]] ||
      return 2
    [[ -n "${WORKTREE_GITFILE_PATH:-}" &&
      -n "${WORKTREE_GITFILE_IDENTITY:-}" &&
      -n "${WORKTREE_GITFILE_MODE:-}" &&
      -n "${WORKTREE_GITFILE_SIZE:-}" &&
      -n "${WORKTREE_GITFILE_SHA256:-}" &&
      -n "${WORKTREE_GITFILE_CONTENT_B64:-}" &&
      -n "${WORKTREE_GITFILE_PRE_DETACH_WITNESS:-}" ]] ||
      return 2
    [[ "$WORKTREE_GITFILE_IDENTITY" =~ ^[0-9]+:[0-9]+:[0-9]+$ &&
      "$WORKTREE_GITFILE_MODE" =~ ^[0-7]+$ &&
      "$WORKTREE_GITFILE_SIZE" =~ ^[0-9]+$ &&
      "$WORKTREE_GITFILE_SHA256" =~ ^[0-9a-f]{64}$ &&
      "$WORKTREE_GITFILE_CONTENT_B64" =~ ^[A-Za-z0-9+/=]+$ &&
      "$WORKTREE_GITFILE_PRE_DETACH_WITNESS" =~ ^[0-9a-f]{64}$ ]] ||
      return 2
    [[ ! -e "$WORKTREE_GITFILE_PATH" && ! -L "$WORKTREE_GITFILE_PATH" ]] ||
      return 2
    gitfile_witness_after="$(clean_sibling_gitfile_pre_detach_witness)"
    [[ "$gitfile_witness_after" == "$WORKTREE_GITFILE_PRE_DETACH_WITNESS" ]] || return 2
  fi
  [[ ! -e "$TMP_ROOT" && ! -L "$TMP_ROOT" ]] || return 2
}

TMP_ROOT="$(mktemp -d "$TMP_PARENT/$TMP_BASENAME.XXXXXXXX")"
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
exec {TMP_ROOT_FD}<"$TMP_ROOT"
exec {OWNER_MARKER_FD}<"$OWNER_MARKER"
TMP_ROOT_FD_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$TMP_ROOT_FD")"
[[ "$TMP_ROOT_FD_IDENTITY" == "$TMP_ROOT_DEVICE:$TMP_ROOT_INODE:$TMP_ROOT_UID:700" ]] ||
  die 'owned root descriptor identity mismatch'
TMP_ROOT_MNT_ID="$(awk '$1 == "mnt_id:" {print $2; exit}' "/proc/$$/fdinfo/$TMP_ROOT_FD")"
[[ "$TMP_ROOT_MNT_ID" =~ ^[0-9]+$ ]] || die 'owned root mount id is unsafe'
OWNER_MARKER_FD_IDENTITY="$(stat -Lc '%d:%i:%u:%a:%s' -- "/proc/$$/fd/$OWNER_MARKER_FD")"
OWNER_MARKER_CONTENT="$(cat "/proc/$$/fd/$OWNER_MARKER_FD")"
[[ "$OWNER_MARKER_CONTENT" == "$$" ]] || die 'owned marker descriptor content mismatch'
readonly TMP_ROOT_FD TMP_ROOT_FD_IDENTITY OWNER_MARKER_FD OWNER_MARKER_FD_IDENTITY \
  OWNER_MARKER_CONTENT
ACGS_CLEANUP_TRAP_ARMED=1
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ACGS_POSTGRES_RECOVERY_ROOT="$(mktemp -d "$TMP_PARENT/$TMP_BASENAME.postgres-recovery.XXXXXXXX")"
ACGS_POSTGRES_RECOVERY_ROOT="$(realpath -e "$ACGS_POSTGRES_RECOVERY_ROOT")"
case "$ACGS_POSTGRES_RECOVERY_ROOT" in
  "$TMP_PARENT"/"$TMP_BASENAME".postgres-recovery.*) ;;
  *) die "mktemp returned an unexpected PostgreSQL recovery path: $ACGS_POSTGRES_RECOVERY_ROOT" ;;
esac
case "$ACGS_POSTGRES_RECOVERY_ROOT" in
  "$TMP_ROOT" | "$TMP_ROOT"/*) die 'PostgreSQL recovery root must not live under recursive proof root' ;;
esac
IFS=: read -r ACGS_POSTGRES_RECOVERY_ROOT_DEVICE ACGS_POSTGRES_RECOVERY_ROOT_INODE \
  ACGS_POSTGRES_RECOVERY_ROOT_UID ACGS_POSTGRES_RECOVERY_ROOT_MODE < <(
  stat -c '%d:%i:%u:%a' -- "$ACGS_POSTGRES_RECOVERY_ROOT"
)
ACGS_POSTGRES_RECOVERY_ROOT_MNT_ID="$(
  /usr/bin/python3 -I -S - "$ACGS_POSTGRES_RECOVERY_ROOT" <<'PY'
import os
import sys

fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("mnt_id:"):
                print(line.split(":", 1)[1].strip())
                raise SystemExit(0)
finally:
    os.close(fd)
raise SystemExit(2)
PY
)" || die 'PostgreSQL recovery root mount id is unsafe'
[[ "$ACGS_POSTGRES_RECOVERY_ROOT_MNT_ID" =~ ^[0-9]+$ ]] ||
  die 'PostgreSQL recovery root mount id is unsafe'
[[ "$ACGS_POSTGRES_RECOVERY_ROOT_UID" == "$(id -u)" &&
  "$ACGS_POSTGRES_RECOVERY_ROOT_MODE" == 700 ]] ||
  die 'PostgreSQL recovery root ownership/mode is unsafe'
ACGS_POSTGRES_RECOVERY_OWNER_MARKER="$ACGS_POSTGRES_RECOVERY_ROOT/.acgs-clean-sibling-owned"
(set -o noclobber; printf '%s\n' "$$" >"$ACGS_POSTGRES_RECOVERY_OWNER_MARKER") ||
  die 'cannot create exclusive PostgreSQL recovery root ownership marker'
chmod 0600 -- "$ACGS_POSTGRES_RECOVERY_OWNER_MARKER" ||
  die 'cannot seal PostgreSQL recovery root ownership marker'
/usr/bin/python3 -I -S - "$ACGS_POSTGRES_RECOVERY_ROOT" "$ACGS_POSTGRES_RECOVERY_OWNER_MARKER" <<'PY' ||
import os
import sys

root, marker = sys.argv[1:3]
marker_fd = os.open(marker, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    os.fsync(marker_fd)
finally:
    os.close(marker_fd)
root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    os.fsync(root_fd)
finally:
    os.close(root_fd)
PY
  die 'cannot fsync PostgreSQL recovery root ownership marker'
QUOTA_ROOT="$TMP_ROOT/quota"
mount_quota_root
WORKTREE="$QUOTA_ROOT/product"
EVIDENCE_ROOT="$QUOTA_ROOT/evidence"
NODE_EVIDENCE="$EVIDENCE_ROOT/$NODE_ID"
if [[ "$ACGS_OUTPUT_GUARDIAN" != 1 ]]; then
  [[ "$ACGS_OUTPUT_MEMFD_FD" =~ ^[0-9]+$ && -n "$ACGS_OUTPUT_MEMFD_IDENTITY" ]] ||
    die 'visible output memfd metadata missing'
  [[ "$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$ACGS_OUTPUT_MEMFD_FD" 2>/dev/null || true)" == \
    "$ACGS_OUTPUT_MEMFD_IDENTITY" ]] || die 'visible output memfd identity changed'
fi
SCRATCH_ROOT="$QUOTA_ROOT/scratch"
RUNTIME_ROOT="$QUOTA_ROOT/runtime"
BOOTSTRAP_ROOT="$QUOTA_ROOT/bootstrap"
BOOTSTRAP_CACHE_ROOT="$BOOTSTRAP_ROOT/cache"
TRUSTED_LOCK_INPUT_ROOT="$BOOTSTRAP_ROOT/trusted-lock-inputs"
TRUSTED_LEDGER_ROOT="$TMP_ROOT/trusted-ledger"
TRUSTED_TRANSCRIPT="$TRUSTED_LEDGER_ROOT/transcript.jsonl"
TRUSTED_RUN_PATH="$TRUSTED_LEDGER_ROOT/run.json"
RUNTIME_TMP="$SCRATCH_ROOT/tmp"
LOCK_RENDER_ROOT="$SCRATCH_ROOT/lock-render"
UV_CACHE_DIR="$BOOTSTRAP_CACHE_ROOT/uv-cache"

phase B0
for path in "$WORKTREE" "$EVIDENCE_ROOT" "$SCRATCH_ROOT" "$RUNTIME_ROOT" "$BOOTSTRAP_ROOT" \
  "$TRUSTED_LEDGER_ROOT"; do
  reject_lexists "$path"
done
mkdir -m 700 "$SCRATCH_ROOT" "$RUNTIME_ROOT" "$BOOTSTRAP_ROOT" "$TRUSTED_LEDGER_ROOT"
exec {TRUSTED_LEDGER_FD}<"$TRUSTED_LEDGER_ROOT"
TRUSTED_LEDGER_ROOT_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$TRUSTED_LEDGER_FD")"
mkdir -m 700 \
  "$RUNTIME_TMP" \
  "$SCRATCH_ROOT/home" \
  "$SCRATCH_ROOT/xdg-cache" \
  "$SCRATCH_ROOT/xdg-config" \
  "$SCRATCH_ROOT/xdg-data" \
  "$SCRATCH_ROOT/xdg-state" \
  "$SCRATCH_ROOT/pytest-temp" \
  "$SCRATCH_ROOT/mypy-cache" \
  "$SCRATCH_ROOT/ruff-cache" \
  "$SCRATCH_ROOT/coverage" \
  "$SCRATCH_ROOT/python-user" \
  "$SCRATCH_ROOT/pycache" \
  "$SCRATCH_ROOT/pip-cache" \
  "$SCRATCH_ROOT/hatch-cache"
mkdir -m 700 \
  "$BOOTSTRAP_CACHE_ROOT" \
  "$UV_CACHE_DIR" \
  "$RUNTIME_ROOT/uv-python" \
  "$RUNTIME_ROOT/uv-python-bin" \
  "$RUNTIME_ROOT/uv-tools" \
  "$RUNTIME_ROOT/uv-tool-bin" \
  "$RUNTIME_ROOT/uv-python-cache" \
  "$RUNTIME_ROOT/uv-credentials"
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
export UV_PYTHON_INSTALL_DIR="$RUNTIME_ROOT/uv-python"
export UV_PYTHON_BIN_DIR="$RUNTIME_ROOT/uv-python-bin"
export UV_TOOL_DIR="$RUNTIME_ROOT/uv-tools"
export UV_TOOL_BIN_DIR="$RUNTIME_ROOT/uv-tool-bin"
export UV_PYTHON_CACHE_DIR="$RUNTIME_ROOT/uv-python-cache"
export UV_CREDENTIALS_DIR="$RUNTIME_ROOT/uv-credentials"
export UV_NO_CONFIG=1
export UV_NO_ENV_FILE=1
export PYTHONUSERBASE="$SCRATCH_ROOT/python-user"
export PYTHONPYCACHEPREFIX="$SCRATCH_ROOT/pycache"
export PIP_CACHE_DIR="$SCRATCH_ROOT/pip-cache"
export HATCH_CACHE_DIR="$SCRATCH_ROOT/hatch-cache"
export UV_CACHE_DIR
verify_uv_identity
UV_FD_SOURCE="/proc/$BASHPID/fd/$UV_FD"
[[ "$("$UV_FD_SOURCE" --version | awk '{print $2}')" == '0.11.19' ]] ||
  die 'uv must be exactly 0.11.19'
BWRAP_BIN=/usr/bin/bwrap
[[ -x "$BWRAP_BIN" && ! -L "$BWRAP_BIN" ]] ||
  die 'containment runner unavailable: /usr/bin/bwrap'
[[ "$("$BWRAP_BIN" --version | awk '{print $2}')" == '0.11.0' ]] ||
  die 'containment runner version drifted'
WORKTREE_ADDED=1
WORKTREE_REGISTRATION_REMOVED=0
WORKTREE_POST_REMOVE_GITFILE_VALIDATED=0
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
  clean_sibling_capture_retained_gitfile "$WORKTREE_GITFILE_FD" "$WORKTREE_GITFILE_PATH" linked
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
  "$WORKTREE_GITFILE_CONTENT_B64" \
  linked ||
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
elif [[ "$NODE_ID" == P2-VERTICAL-GATE-003 ]]; then
  export ACGS_PROCESS_SCHEDULE='["single-process-evidence-and-package-gates","postgres-vertical-bootstrap-register"]'
elif [[ "$NODE_ID" == P3-POLICY-001 ]]; then
  export ACGS_PROCESS_SCHEDULE='["single-process-evidence-and-package-gates","postgres-pg6-policy-registry-lifecycle"]'
elif [[ "$NODE_ID" == P3-MUTATIONS-002 ]]; then
  export ACGS_PROCESS_SCHEDULE='["single-process-evidence-and-package-gates","postgres-pg6-mutation-inventory-drift"]'
elif [[ "$NODE_ID" == P3-APPROVAL-003 ]]; then
  export ACGS_PROCESS_SCHEDULE='["single-process-evidence-and-package-gates","postgres-pg9-approval-resume-multiprocess"]'
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

validate_anonymous_snapshot_fd() {
  local label="$1"
  local fd="$2"
  local expected_stat="$3"
  local expected_sha256="$4"
  [[ "$ACGS_SNAPSHOT_MODE" == anonymous ]] ||
    die 'trusted artifact snapshot mode is not anonymous'
  [[ "$fd" =~ ^[0-9]+$ && -r "/proc/$BASHPID/fd/$fd" ]] ||
    die "trusted $label snapshot descriptor is unavailable"
  [[ "$(stat -Lc '%d:%i:%u:%a:%s' -- "/proc/$BASHPID/fd/$fd")" == "$expected_stat" ]] ||
    die "trusted $label snapshot identity changed"
  [[ "$(stat -Lc '%h' -- "/proc/$BASHPID/fd/$fd")" == 0 ]] ||
    die "trusted $label snapshot is not anonymous"
  /usr/bin/python3 -I -S - "$fd" "$expected_sha256" <<'PY' ||
import hashlib
import fcntl
import os
import sys

F_GET_SEALS = 1034
F_SEAL_SEAL = 0x0001
F_SEAL_SHRINK = 0x0002
F_SEAL_GROW = 0x0004
F_SEAL_WRITE = 0x0008
REQUIRED_SEALS = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE
fd = int(sys.argv[1])
expected = sys.argv[2]
if fcntl.fcntl(fd, F_GET_SEALS) != REQUIRED_SEALS:
    raise SystemExit(2)
digest = hashlib.sha256()
size = os.fstat(fd).st_size
if size > 64 * 1024 * 1024:
    raise SystemExit(2)
remaining = size
offset = 0
while remaining:
    chunk = os.pread(fd, min(1024 * 1024, remaining), offset)
    if not chunk:
        raise SystemExit(2)
    digest.update(chunk)
    remaining -= len(chunk)
    offset += len(chunk)
if digest.hexdigest() != expected:
    raise SystemExit(2)
PY
    die "trusted $label snapshot seal/hash changed"
}

validate_anonymous_snapshot_artifacts() {
  validate_anonymous_snapshot_fd launcher "$ACGS_LAUNCHER_SNAPSHOT_FD" \
    "$ACGS_LAUNCHER_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_LAUNCHER_SHA256"
  validate_anonymous_snapshot_fd internal "$ACGS_INTERNAL_SNAPSHOT_FD" \
    "$ACGS_INTERNAL_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_INTERNAL_SHA256"
  validate_anonymous_snapshot_fd cleanup "$ACGS_CLEANUP_SNAPSHOT_FD" \
    "$ACGS_CLEANUP_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_CLEANUP_SHA256"
  validate_anonymous_snapshot_fd uv "$ACGS_UV_SNAPSHOT_FD" \
    "$ACGS_UV_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_UV_SHA256"
}

validate_snapshot_data_fd() {
  local label="$1"
  local data_fd="$2"
  local expected_stat="$3"
  local expected_sha256="$4"
  [[ "$data_fd" =~ ^[0-9]+$ ]] || die "trusted $label data descriptor is invalid"
  validate_anonymous_snapshot_fd "$label" "$data_fd" "$expected_stat" "$expected_sha256"
}

open_snapshot_data_fd() {
  local label="$1"
  local attest_fd="$2"
  local expected_stat="$3"
  local expected_sha256="$4"
  local output_var="$5"
  local data_fd
  validate_anonymous_snapshot_fd "$label" "$attest_fd" "$expected_stat" "$expected_sha256"
  exec {data_fd}<"/proc/$BASHPID/fd/$attest_fd" ||
    die "trusted $label snapshot data descriptor cannot be opened"
  [[ "$data_fd" != "$attest_fd" ]] || die "trusted $label data descriptor is not independent"
  validate_snapshot_data_fd "$label" "$data_fd" "$expected_stat" "$expected_sha256"
  printf -v "$output_var" '%s' "$data_fd"
}

open_all_snapshot_data_fds() {
  open_snapshot_data_fd launcher "$ACGS_LAUNCHER_SNAPSHOT_FD" \
    "$ACGS_LAUNCHER_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_LAUNCHER_SHA256" \
    ACGS_LAUNCHER_DATA_FD
  open_snapshot_data_fd internal "$ACGS_INTERNAL_SNAPSHOT_FD" \
    "$ACGS_INTERNAL_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_INTERNAL_SHA256" \
    ACGS_INTERNAL_DATA_FD
  open_snapshot_data_fd cleanup "$ACGS_CLEANUP_SNAPSHOT_FD" \
    "$ACGS_CLEANUP_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_CLEANUP_SHA256" \
    ACGS_CLEANUP_DATA_FD
  open_snapshot_data_fd uv "$ACGS_UV_SNAPSHOT_FD" \
    "$ACGS_UV_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_UV_SHA256" ACGS_UV_DATA_FD
}

open_uv_snapshot_data_fd() {
  open_snapshot_data_fd uv "$ACGS_UV_SNAPSHOT_FD" \
    "$ACGS_UV_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_UV_SHA256" ACGS_UV_DATA_FD
}

validate_regular_data_fd() {
  local label="$1"
  local data_fd="$2"
  local expected_stat="$3"
  local expected_sha256="$4"
  [[ "$data_fd" =~ ^[0-9]+$ ]] || die "trusted $label data descriptor is invalid"
  [[ "$(stat -Lc '%d:%i:%u:%a:%h' -- "/proc/$BASHPID/fd/$data_fd")" == "$expected_stat" ]] ||
    die "trusted $label data descriptor identity changed"
  /usr/bin/python3 -I -S - "$data_fd" "$expected_sha256" <<'PY' ||
import hashlib
import os
import sys

fd = int(sys.argv[1])
expected = sys.argv[2]
digest = hashlib.sha256()
size = os.fstat(fd).st_size
if size > 64 * 1024 * 1024:
    raise SystemExit(2)
remaining = size
offset = 0
while remaining:
    chunk = os.pread(fd, min(1024 * 1024, remaining), offset)
    if not chunk:
        raise SystemExit(2)
    digest.update(chunk)
    remaining -= len(chunk)
    offset += len(chunk)
if digest.hexdigest() != expected:
    raise SystemExit(2)
PY
    die "trusted $label data descriptor digest changed"
}

open_regular_data_fd() {
  local label="$1"
  local attest_fd="$2"
  local expected_stat="$3"
  local expected_sha256="$4"
  local output_var="$5"
  local data_fd
  exec {data_fd}<"/proc/$BASHPID/fd/$attest_fd" ||
    die "trusted $label data descriptor cannot be opened"
  [[ "$data_fd" != "$attest_fd" ]] || die "trusted $label data descriptor is not independent"
  validate_regular_data_fd "$label" "$data_fd" "$expected_stat" "$expected_sha256"
  printf -v "$output_var" '%s' "$data_fd"
}

snapshot_data_fd_is_retained() {
  case "$1" in
    "$ACGS_LAUNCHER_DATA_FD" | "$ACGS_INTERNAL_DATA_FD" | \
      "$ACGS_CLEANUP_DATA_FD" | "$ACGS_UV_DATA_FD" | "$ACGS_POSTGRES_RUNNER_DATA_FD")
      [[ -n "$1" ]] && return 0
      return 1
      ;;
    *) return 1 ;;
  esac
}

close_noncontained_fds() {
  local fd fd_path
  for fd_path in /proc/"$BASHPID"/fd/*; do
    fd="${fd_path##*/}"
    case "$fd" in
      0 | 1 | 2) ;;
      *)
        if ! snapshot_data_fd_is_retained "$fd"; then
          eval "exec $fd<&-" 2>/dev/null || true
        fi
        ;;
    esac
  done
}

contained_snapshot_data_mount_args() {
  validate_snapshot_data_fd launcher "$ACGS_LAUNCHER_DATA_FD" \
    "$ACGS_LAUNCHER_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_LAUNCHER_SHA256"
  validate_snapshot_data_fd internal "$ACGS_INTERNAL_DATA_FD" \
    "$ACGS_INTERNAL_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_INTERNAL_SHA256"
  validate_snapshot_data_fd cleanup "$ACGS_CLEANUP_DATA_FD" \
    "$ACGS_CLEANUP_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_CLEANUP_SHA256"
  validate_snapshot_data_fd uv "$ACGS_UV_DATA_FD" \
    "$ACGS_UV_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_UV_SHA256"
  printf '%s\0%s\0%s\0%s\0%s\0' --perms 500 --ro-bind-data \
    "$ACGS_LAUNCHER_DATA_FD" "$ACGS_CLEAN_SIBLING_LAUNCHER_PATH"
  printf '%s\0%s\0%s\0%s\0%s\0' --perms 400 --ro-bind-data \
    "$ACGS_INTERNAL_DATA_FD" "$ACGS_CLEAN_SIBLING_INTERNAL_PATH"
  printf '%s\0%s\0%s\0%s\0%s\0' --perms 400 --ro-bind-data \
    "$ACGS_CLEANUP_DATA_FD" "$ACGS_CLEAN_SIBLING_CLEANUP_PATH"
  printf '%s\0%s\0%s\0%s\0%s\0' --perms 500 --ro-bind-data \
    "$ACGS_UV_DATA_FD" "$UV_BIN"
}

contained_uv_snapshot_data_mount_args() {
  validate_snapshot_data_fd uv "$ACGS_UV_DATA_FD" \
    "$ACGS_UV_SNAPSHOT_STAT" "$ACGS_CLEAN_SIBLING_UV_SHA256"
  printf '%s\0%s\0%s\0%s\0%s\0' --perms 500 --ro-bind-data "$ACGS_UV_DATA_FD" "$UV_BIN"
}

snapshot_size_from_stat() {
  printf '%s' "${1##*:}"
}

mounted_artifact_preflight_env_args_all() {
  printf '%s\0' PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8
  printf '%s=%s|%s|%s\0' ACGS_PREFLIGHT_LAUNCHER \
    "$ACGS_CLEAN_SIBLING_LAUNCHER_PATH" "$ACGS_CLEAN_SIBLING_LAUNCHER_SHA256" \
    "$(snapshot_size_from_stat "$ACGS_LAUNCHER_SNAPSHOT_STAT")"
  printf '%s=%s|%s|%s\0' ACGS_PREFLIGHT_INTERNAL \
    "$ACGS_CLEAN_SIBLING_INTERNAL_PATH" "$ACGS_CLEAN_SIBLING_INTERNAL_SHA256" \
    "$(snapshot_size_from_stat "$ACGS_INTERNAL_SNAPSHOT_STAT")"
  printf '%s=%s|%s|%s\0' ACGS_PREFLIGHT_CLEANUP \
    "$ACGS_CLEAN_SIBLING_CLEANUP_PATH" "$ACGS_CLEAN_SIBLING_CLEANUP_SHA256" \
    "$(snapshot_size_from_stat "$ACGS_CLEANUP_SNAPSHOT_STAT")"
  printf '%s=%s|%s|%s\0' ACGS_PREFLIGHT_UV \
    "$UV_BIN" "$ACGS_CLEAN_SIBLING_UV_SHA256" "$(snapshot_size_from_stat "$ACGS_UV_SNAPSHOT_STAT")"
}

mounted_artifact_preflight_env_args_uv() {
  printf '%s\0' PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8
  printf '%s=%s|%s|%s\0' ACGS_PREFLIGHT_UV \
    "$UV_BIN" "$ACGS_CLEAN_SIBLING_UV_SHA256" "$(snapshot_size_from_stat "$ACGS_UV_SNAPSHOT_STAT")"
}

mounted_artifact_preflight_env_args_postgres() {
  local runner_path="$1" runner_sha="$2" runner_size="$3"
  mounted_artifact_preflight_env_args_uv
  printf '%s=%s|%s|%s\0' ACGS_PREFLIGHT_POSTGRES_RUNNER \
    "$runner_path" "$runner_sha" "$runner_size"
}

ACGS_MOUNTED_ARTIFACT_PREFLIGHT_SCRIPT='
set -Eeuo pipefail
check_artifact() {
  local record="$1" label="$2" path expected_sha expected_size actual_sha actual_size
  [[ -z "$record" ]] && return 0
  IFS="|" read -r path expected_sha expected_size <<<"$record"
  [[ "$path" == /* && -n "$expected_sha" && "$expected_size" =~ ^[0-9]+$ ]] ||
    exit 126
  [[ -f "$path" && ! -L "$path" ]] || exit 126
  actual_size="$(stat -Lc "%s" -- "$path")" || exit 126
  [[ "$actual_size" == "$expected_size" ]] || exit 126
  actual_sha="$(sha256sum "$path" | awk "{print \$1}")" || exit 126
  [[ "$actual_sha" == "$expected_sha" ]] || exit 126
}
check_artifact "${ACGS_PREFLIGHT_LAUNCHER:-}" launcher
check_artifact "${ACGS_PREFLIGHT_INTERNAL:-}" internal
check_artifact "${ACGS_PREFLIGHT_CLEANUP:-}" cleanup
check_artifact "${ACGS_PREFLIGHT_UV:-}" uv
check_artifact "${ACGS_PREFLIGHT_POSTGRES_RUNNER:-}" postgres-runner
exec "$@"
'
readonly ACGS_MOUNTED_ARTIFACT_PREFLIGHT_SCRIPT

contained_mount_args() {
  local path
  printf '%s\0%s\0%s\0' --ro-bind "$WORKTREE" "$WORKTREE"
  printf '%s\0%s\0%s\0' --ro-bind "$SOURCE_GIT_COMMON_DIR" "$SOURCE_GIT_COMMON_DIR"
  if [[ "${ACGS_RUNTIME_WRITABLE:-0}" != 1 && -d "$RUNTIME_ROOT" && ! -L "$RUNTIME_ROOT" ]]; then
    printf '%s\0%s\0%s\0' --ro-bind "$RUNTIME_ROOT" "$RUNTIME_ROOT"
  fi
  for path in "$EVIDENCE_ROOT" "$SCRATCH_ROOT"; do
    if [[ -d "$path" && ! -L "$path" ]]; then
      printf '%s\0%s\0%s\0' --bind "$path" "$path"
    fi
  done
  for path in \
    "$WORKTREE/.venv-evidence" \
    "$WORKTREE/packages/acgs-control-plane/.venv" \
    "$WORKTREE/packages/gove-zone/.venv-beta"; do
    if [[ -d "$path" && ! -L "$path" ]]; then
      printf '%s\0%s\0%s\0' --ro-bind "$path" "$path"
    fi
  done
  contained_snapshot_data_mount_args
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
  for path in "$BOOTSTRAP_CACHE_ROOT" "$TRUSTED_LOCK_INPUT_ROOT"; do
    if [[ -d "$path" && ! -L "$path" ]]; then
      printf '%s\0%s\0%s\0' --bind "$path" "$path"
    fi
  done
  for path in \
    "$WORKTREE/.venv-evidence" \
    "$WORKTREE/packages/acgs-control-plane/.venv" \
    "$WORKTREE/packages/gove-zone/.venv-beta"; do
    if [[ -d "$path" && ! -L "$path" ]]; then
      printf '%s\0%s\0%s\0' --bind "$path" "$path"
    fi
  done
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

python_install_bootstrap_mount_args() {
  bootstrap_mount_args
  if [[ -d "$RUNTIME_ROOT" && ! -L "$RUNTIME_ROOT" ]]; then
    printf '%s\0%s\0%s\0' --bind "$RUNTIME_ROOT" "$RUNTIME_ROOT"
  fi
}

run_contained() {
  local cwd="$1"
  shift
  [[ -x "$BWRAP_BIN" && ! -L "$BWRAP_BIN" ]] ||
    die 'containment runner unavailable: /usr/bin/bwrap'
  [[ "$cwd" == "$WORKTREE" || "$cwd" == "$WORKTREE"/* || \
    "$cwd" == "$SCRATCH_ROOT" || "$cwd" == "$SCRATCH_ROOT"/* ]] ||
    die "contained cwd escaped target worktree/scratch: $cwd"
  verify_uv_identity
  (
    local -a ACGS_PREFLIGHT_ENV
    open_all_snapshot_data_fds
    close_noncontained_fds
    mapfile -d '' -t ACGS_CONTAINED_ENV < <(contained_env_args)
    mapfile -d '' -t ACGS_CONTAINED_MOUNTS < <(contained_mount_args)
    mapfile -d '' -t ACGS_CONTAINED_SYSTEM_MOUNTS < <(runtime_system_mount_args)
    mapfile -d '' -t ACGS_CONTAINED_LINKER_ARGS < <(runtime_linker_args)
    mapfile -d '' -t ACGS_PREFLIGHT_ENV < <(mounted_artifact_preflight_env_args_all)
    lower_descendant_file_size_limit
    # shellcheck disable=SC2016 # inner isolated Bash must receive literal $fd_path/$fd
    exec "$BWRAP_BIN" \
      --die-with-parent \
      --unshare-all \
      --unshare-user \
      --unshare-ipc \
      --unshare-net \
      --unshare-pid \
      --new-session \
      --cap-drop ALL \
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
      "${ACGS_CONTAINED_SYSTEM_MOUNTS[@]}" \
      "${ACGS_CONTAINED_LINKER_ARGS[@]}" \
      "${ACGS_CONTAINED_MOUNTS[@]}" \
      --chdir "$cwd" \
      /usr/bin/env -i "${ACGS_PREFLIGHT_ENV[@]}" \
        /bin/bash --noprofile --norc -c "$ACGS_MOUNTED_ARTIFACT_PREFLIGHT_SCRIPT" _ \
        /usr/bin/env -i "${ACGS_CONTAINED_ENV[@]}" "$@"
  )
}

run_contained_bootstrap() {
  local cwd="$1"
  shift
  [[ "${1:-}" == "$UV_BIN" || \
    ( "${1:-}" == "$EVIDENCE_PY" && \
      ( "${2:-}" == "$WORKTREE/scripts/evidence/verify_environment.py" || \
        "${2:-}" == "$WORKTREE/scripts/evidence/capture_environment.py" ) ) ]] ||
    die 'bootstrap containment only runs pinned bootstrap executables'
  [[ -x "$BWRAP_BIN" && ! -L "$BWRAP_BIN" ]] ||
    die 'containment runner unavailable: /usr/bin/bwrap'
  [[ "$cwd" == "$WORKTREE" || "$cwd" == "$WORKTREE"/* || \
    "$cwd" == "$SCRATCH_ROOT" || "$cwd" == "$SCRATCH_ROOT"/* || \
    "$cwd" == "$BOOTSTRAP_ROOT" || "$cwd" == "$BOOTSTRAP_ROOT"/* ]] ||
    die "bootstrap cwd escaped target worktree/scratch/bootstrap: $cwd"
  verify_uv_identity
  (
    local -a ACGS_PREFLIGHT_ENV
    open_all_snapshot_data_fds
    close_noncontained_fds
    if [[ "${1:-}" == "$UV_BIN" ]]; then
      unset UV_OFFLINE UV_NO_INDEX UV_NO_CACHE RUFF_NO_CACHE
    fi
    mapfile -d '' -t ACGS_CONTAINED_ENV < <(contained_env_args)
    mapfile -d '' -t ACGS_CONTAINED_MOUNTS < <(bootstrap_mount_args)
    mapfile -d '' -t ACGS_PREFLIGHT_ENV < <(mounted_artifact_preflight_env_args_all)
    lower_descendant_file_size_limit
    exec "$BWRAP_BIN" \
      --die-with-parent \
      --unshare-user \
      --unshare-ipc \
      --unshare-net \
      --unshare-pid \
      --new-session \
      --cap-drop ALL \
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
      "${ACGS_CONTAINED_MOUNTS[@]}" \
      --chdir "$cwd" \
      /usr/bin/env -i "${ACGS_PREFLIGHT_ENV[@]}" \
        /bin/bash --noprofile --norc -c "$ACGS_MOUNTED_ARTIFACT_PREFLIGHT_SCRIPT" _ \
        /usr/bin/env -i "${ACGS_CONTAINED_ENV[@]}" "$@"
  )
}

run_contained_python_install() {
  local cwd="$1"
  shift
  [[ "${1:-}" == "$UV_BIN" && "${2:-}" == python && "${3:-}" == install ]] ||
    die 'python install bootstrap only runs pinned uv python install'
  [[ -x "$BWRAP_BIN" && ! -L "$BWRAP_BIN" ]] ||
    die 'containment runner unavailable: /usr/bin/bwrap'
  [[ "$cwd" == "$BOOTSTRAP_ROOT" || "$cwd" == "$BOOTSTRAP_ROOT"/* ]] ||
    die "python install bootstrap cwd escaped bootstrap root: $cwd"
  verify_uv_identity
  (
    local -a ACGS_PREFLIGHT_ENV
    open_all_snapshot_data_fds
    close_noncontained_fds
    unset UV_OFFLINE UV_NO_INDEX UV_NO_CACHE RUFF_NO_CACHE
    ACGS_RUNTIME_WRITABLE=1
    mapfile -d '' -t ACGS_CONTAINED_ENV < <(contained_env_args)
    mapfile -d '' -t ACGS_CONTAINED_MOUNTS < <(python_install_bootstrap_mount_args)
    mapfile -d '' -t ACGS_PREFLIGHT_ENV < <(mounted_artifact_preflight_env_args_all)
    lower_descendant_file_size_limit
    exec "$BWRAP_BIN" \
      --die-with-parent \
      --unshare-user \
      --unshare-ipc \
      --unshare-pid \
      --new-session \
      --cap-drop ALL \
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
      "${ACGS_CONTAINED_MOUNTS[@]}" \
      --chdir "$cwd" \
      /usr/bin/env -i "${ACGS_PREFLIGHT_ENV[@]}" \
        /bin/bash --noprofile --norc -c "$ACGS_MOUNTED_ARTIFACT_PREFLIGHT_SCRIPT" _ \
        /usr/bin/env -i "${ACGS_CONTAINED_ENV[@]}" "$@"
  )
}

validate_and_publish_trusted_lock_inputs() {
  local rendered_root="$1" trusted_root="$2" expected_root="$3"
  "$SNAPSHOT_PYTHON" - "$rendered_root" "$trusted_root" "$expected_root" <<'PY'
import re
import shutil
import sys
from pathlib import Path

rendered_root = Path(sys.argv[1]).resolve(strict=True)
trusted_root = Path(sys.argv[2]).resolve(strict=False)
expected_root = Path(sys.argv[3]).resolve(strict=True)
expected_relatives = (
    Path("requirements/saas-beta/locks.toml"),
    Path("requirements/saas-beta/evidence-test.in"),
    Path("requirements/saas-beta/cp-test.in"),
    Path("requirements/saas-beta/gz-test.in"),
    Path("requirements/saas-beta/bootstrap-by-scope.json"),
    Path("requirements/saas-beta/evidence-test.lock"),
    Path("requirements/saas-beta/cp-test.lock"),
    Path("requirements/saas-beta/gz-test.lock"),
)
registry_requirement = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:\[[A-Za-z0-9][A-Za-z0-9._-]*(?:\s*,\s*[A-Za-z0-9][A-Za-z0-9._-]*)*\])?"
    r"\s*(?:(?:~=|==|!=|<=|>=|<|>|===)\s*[A-Za-z0-9][A-Za-z0-9._!*+~-]*"
    r"(?:\s*,\s*(?:~=|==|!=|<=|>=|<|>|===)\s*[A-Za-z0-9][A-Za-z0-9._!*+~-]*)*)?"
    r"(?:\s*;\s*[A-Za-z0-9_.\"' <>=!~(),-]+)?$"
)
unsafe = re.compile(
    r"(?i)(?:^|[^\w.+-])(?:https?|file|ssh|git)://|(?:^|[^\w.+-])(?:git|ssh|file)\+"
)
if trusted_root.exists():
    raise SystemExit(f"trusted lock input root already exists: {trusted_root}")
trusted_root.mkdir(mode=0o700, parents=True)
try:
    for relative in expected_relatives:
        source = (rendered_root / relative).resolve(strict=True)
        expected = (expected_root / relative).resolve(strict=True)
        if not source.is_relative_to(rendered_root):
            raise SystemExit(f"rendered lock input escaped root: {relative}")
        if source.is_symlink() or not source.is_file():
            raise SystemExit(f"rendered lock input is not a regular file: {relative}")
        payload = source.read_bytes()
        if payload != expected.read_bytes():
            raise SystemExit(f"rendered lock input drifted from reviewed bytes: {relative}")
        if relative.suffix == ".in":
            for number, line in enumerate(payload.decode("utf-8").splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if (
                    stripped.startswith(("-", ".", "/", "~"))
                    or "@" in stripped
                    or "://" in stripped
                    or unsafe.search(stripped)
                    or not registry_requirement.fullmatch(stripped)
                ):
                    raise SystemExit(
                        f"unsafe lock input requirement in {relative}:{number}: {stripped!r}"
                    )
        destination = trusted_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        with open(destination, "xb") as handle:
            handle.write(payload)
except BaseException:
    shutil.rmtree(trusted_root, ignore_errors=True)
    raise
PY
}

validate_trusted_network_requirement_file() {
  local requirement_file="$1"
  local line stripped
  [[ -f "$requirement_file" && ! -L "$requirement_file" ]] ||
    die 'trusted network resolver requirement file is unsafe'
  while IFS= read -r line || [[ -n "$line" ]]; do
    stripped="${line#"${line%%[![:space:]]*}"}"
    stripped="${stripped%"${stripped##*[![:space:]]}"}"
    [[ -z "$stripped" || "${stripped:0:1}" == "#" ]] && continue
    case "$stripped" in
      -* | .* | /* | ~* | *@* | *://* | git+* | ssh+* | file+* | \
        *' --index'* | *' --default-index'* | *' --extra-index-url'* | \
        *' --find-links'* | *' -f '* | *' --requirement'* | *' -r '* | \
        *' --constraint'* | *' -c '* | *' --build-constraint'* | *' --config-setting'*)
        die "trusted network resolver rejected unsafe requirement: $stripped"
        ;;
    esac
  done <"$requirement_file"
}

run_trusted_network_uv_compile() {
  [[ "$#" == 3 ]] || die 'trusted network resolver rejected unsupported uv command'
  local trusted_root="$1" input_relative="$2" output_relative="$3"
  local custom_compile_command
  local network_cache_root="$BOOTSTRAP_CACHE_ROOT/trusted-network-uv-cache"
  local network_python_root="$network_cache_root/uv-python"
  local network_python_bin="$network_cache_root/uv-python-bin"
  local network_python_cache="$network_cache_root/uv-python-cache"
  local network_hydrate_root="$network_cache_root/hydrate/${output_relative//\//__}"
  [[ "$trusted_root" == "$TRUSTED_LOCK_INPUT_ROOT" ]] ||
    die 'trusted network resolver requires retained trusted lock input root'
  [[ -d "$trusted_root" && ! -L "$trusted_root" ]] ||
    die 'trusted network resolver input root is unsafe'
  case "$input_relative:$output_relative" in
    requirements/saas-beta/evidence-test.in:requirements/saas-beta/evidence-test.lock | \
      requirements/saas-beta/cp-test.in:requirements/saas-beta/cp-test.lock | \
      requirements/saas-beta/gz-test.in:requirements/saas-beta/gz-test.lock) ;;
    *) die 'trusted network resolver rejected unsupported lock target' ;;
  esac
  [[ -f "$trusted_root/$input_relative" && ! -L "$trusted_root/$input_relative" ]] ||
    die 'trusted network resolver input is unavailable'
  [[ -f "$trusted_root/$output_relative" && ! -L "$trusted_root/$output_relative" ]] ||
    die 'trusted network resolver expected lock is unavailable'
  validate_trusted_network_requirement_file "$trusted_root/$input_relative"
  mkdir -p \
    "$network_cache_root" \
    "$network_python_root" \
    "$network_python_bin" \
    "$network_python_cache" \
    "$network_hydrate_root"
  [[ -d "$network_cache_root" && ! -L "$network_cache_root" ]] ||
    die 'trusted network resolver cache root is unsafe'
  [[ -d "$network_python_root" && ! -L "$network_python_root" ]] ||
    die 'trusted network resolver python root is unsafe'
  [[ -d "$network_python_bin" && ! -L "$network_python_bin" ]] ||
    die 'trusted network resolver python bin root is unsafe'
  [[ -d "$network_python_cache" && ! -L "$network_python_cache" ]] ||
    die 'trusted network resolver python cache root is unsafe'
  [[ -d "$network_hydrate_root" && ! -L "$network_hydrate_root" ]] ||
    die 'trusted network resolver hydrate root is unsafe'
  verify_uv_identity
  custom_compile_command="uv pip compile --python-version 3.11 --python-platform x86_64-manylinux_2_28 --exclude-newer 2026-07-10T00:00:00Z --generate-hashes $input_relative --output-file $output_relative"
  (
    local -a ACGS_UV_SNAPSHOT_MOUNT
    local -a ACGS_PREFLIGHT_ENV
    open_uv_snapshot_data_fd
    close_noncontained_fds
    mapfile -d '' -t ACGS_UV_SNAPSHOT_MOUNT < <(contained_uv_snapshot_data_mount_args)
    mapfile -d '' -t ACGS_PREFLIGHT_ENV < <(mounted_artifact_preflight_env_args_uv)
    lower_descendant_file_size_limit
    exec "$BWRAP_BIN" \
      --die-with-parent \
      --unshare-user \
      --unshare-ipc \
      --unshare-pid \
      --new-session \
      --cap-drop ALL \
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
      --ro-bind-try /etc/resolv.conf /etc/resolv.conf \
      --ro-bind-try /etc/hosts /etc/hosts \
      --ro-bind-try /etc/nsswitch.conf /etc/nsswitch.conf \
      --ro-bind-try /etc/ssl /etc/ssl \
      --ro-bind-try /etc/pki /etc/pki \
      "${ACGS_UV_SNAPSHOT_MOUNT[@]}" \
      --bind "$trusted_root" "$trusted_root" \
      --bind "$network_cache_root" "$network_cache_root" \
      --chdir "$trusted_root" \
      /usr/bin/env -i "${ACGS_PREFLIGHT_ENV[@]}" \
        /bin/bash --noprofile --norc -c "$ACGS_MOUNTED_ARTIFACT_PREFLIGHT_SCRIPT" _ \
        /usr/bin/env -i \
          PATH=/usr/bin:/bin \
          LANG=C.UTF-8 \
          LC_ALL=C.UTF-8 \
          TZ=UTC \
          HOME=/dev/null \
          TMPDIR=/tmp \
          TMP=/tmp \
          TEMP=/tmp \
          UV_CACHE_DIR="$network_cache_root" \
          UV_PYTHON_INSTALL_DIR="$network_python_root" \
          UV_PYTHON_BIN_DIR="$network_python_bin" \
          UV_PYTHON_CACHE_DIR="$network_python_cache" \
          UV_CREDENTIALS_DIR=/tmp/uv-credentials \
          UV_NO_CONFIG=1 \
          UV_NO_ENV_FILE=1 \
          UV_PYTHON_DOWNLOADS=never \
          "$UV_BIN" pip compile \
          --no-config \
          --default-index https://pypi.org/simple \
          --index-strategy first-index \
          --python-version 3.11 \
          --python-platform x86_64-manylinux_2_28 \
          --exclude-newer 2026-07-10T00:00:00Z \
          --generate-hashes \
          --only-binary :all: \
          --no-sources \
          --no-python-downloads \
          --custom-compile-command "$custom_compile_command" \
          "$input_relative" \
          --output-file "$output_relative"
  )
  (
    local -a ACGS_UV_SNAPSHOT_MOUNT
    local -a ACGS_PREFLIGHT_ENV
    open_uv_snapshot_data_fd
    close_noncontained_fds
    mapfile -d '' -t ACGS_UV_SNAPSHOT_MOUNT < <(contained_uv_snapshot_data_mount_args)
    mapfile -d '' -t ACGS_PREFLIGHT_ENV < <(mounted_artifact_preflight_env_args_uv)
    lower_descendant_file_size_limit
    exec "$BWRAP_BIN" \
      --die-with-parent \
      --unshare-user \
      --unshare-ipc \
      --unshare-pid \
      --new-session \
      --cap-drop ALL \
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
      --ro-bind-try /etc/resolv.conf /etc/resolv.conf \
      --ro-bind-try /etc/hosts /etc/hosts \
      --ro-bind-try /etc/nsswitch.conf /etc/nsswitch.conf \
      --ro-bind-try /etc/ssl /etc/ssl \
      --ro-bind-try /etc/pki /etc/pki \
      "${ACGS_UV_SNAPSHOT_MOUNT[@]}" \
      --bind "$trusted_root" "$trusted_root" \
      --bind "$network_cache_root" "$network_cache_root" \
      --chdir "$trusted_root" \
      /usr/bin/env -i "${ACGS_PREFLIGHT_ENV[@]}" \
        /bin/bash --noprofile --norc -c "$ACGS_MOUNTED_ARTIFACT_PREFLIGHT_SCRIPT" _ \
        /usr/bin/env -i \
          PATH=/usr/bin:/bin \
          LANG=C.UTF-8 \
          LC_ALL=C.UTF-8 \
          TZ=UTC \
          HOME=/dev/null \
          TMPDIR=/tmp \
          TMP=/tmp \
          TEMP=/tmp \
          UV_CACHE_DIR="$network_cache_root" \
          UV_PYTHON_INSTALL_DIR="$network_python_root" \
          UV_PYTHON_BIN_DIR="$network_python_bin" \
          UV_PYTHON_CACHE_DIR="$network_python_cache" \
          UV_CREDENTIALS_DIR=/tmp/uv-credentials \
          UV_NO_CONFIG=1 \
          UV_NO_ENV_FILE=1 \
          UV_PYTHON_DOWNLOADS=never \
          "$UV_BIN" pip sync \
          --no-config \
          --default-index https://pypi.org/simple \
          --index-strategy first-index \
          --python-version 3.11 \
          --python-platform x86_64-manylinux_2_28 \
          --exclude-newer 2026-07-10T00:00:00Z \
          --require-hashes \
          --only-binary :all: \
          --no-sources \
          --no-python-downloads \
          --target "$network_hydrate_root" \
          "$output_relative"
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
validate_and_publish_trusted_lock_inputs "$LOCK_RENDER_ROOT" "$TRUSTED_LOCK_INPUT_ROOT" "$EXPECTED"
LC_ALL=C TZ=UTC run_trusted_network_uv_compile "$TRUSTED_LOCK_INPUT_ROOT" \
  requirements/saas-beta/evidence-test.in \
  requirements/saas-beta/evidence-test.lock
LC_ALL=C TZ=UTC run_trusted_network_uv_compile "$TRUSTED_LOCK_INPUT_ROOT" \
  requirements/saas-beta/cp-test.in \
  requirements/saas-beta/cp-test.lock
LC_ALL=C TZ=UTC run_trusted_network_uv_compile "$TRUSTED_LOCK_INPUT_ROOT" \
  requirements/saas-beta/gz-test.in \
  requirements/saas-beta/gz-test.lock
UV_CACHE_DIR="$BOOTSTRAP_CACHE_ROOT/trusted-network-uv-cache"
export UV_CACHE_DIR
for relative in "${LOCK_FILES[@]}"; do
  cmp --silent "$EXPECTED/$relative" "$TRUSTED_LOCK_INPUT_ROOT/$relative" ||
    die "deterministic render/compile drift: $relative"
done
[[ -z "$(git -C "$WORKTREE" status --porcelain=v1 --untracked-files=all)" ]] ||
  die 'lock regeneration left product-tree drift'

phase B2
run_contained_python_install "$BOOTSTRAP_ROOT" "$UV_BIN" python install --no-config 3.11
mkdir -m 700 "$WORKTREE/.venv-evidence"
run_contained_bootstrap "$WORKTREE" "$UV_BIN" venv --no-config --offline --no-python-downloads \
  --python 3.11 "$WORKTREE/.venv-evidence"
mkdir -p "$NODE_EVIDENCE"
run_contained_bootstrap "$WORKTREE" "$UV_BIN" pip sync \
  --python "$WORKTREE/.venv-evidence/bin/python" --offline \
  --python-version 3.11 --python-platform x86_64-manylinux_2_28 \
  --no-python-downloads --require-hashes --only-binary :all: \
  "$WORKTREE/requirements/saas-beta/evidence-test.lock"
export UV_OFFLINE=1 UV_NO_INDEX=1 UV_NO_CACHE=1
export RUFF_NO_CACHE=true PYTHONDONTWRITEBYTECODE=1
EVIDENCE_PY="$WORKTREE/.venv-evidence/bin/python"
run_contained_bootstrap "$WORKTREE" "$EVIDENCE_PY" "$WORKTREE/scripts/evidence/verify_environment.py" \
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
run_contained_bootstrap "$WORKTREE" "$UV_BIN" venv --no-config --offline --no-python-downloads \
  --python 3.11 "$WORKTREE/packages/acgs-control-plane/.venv"
run_contained_bootstrap "$WORKTREE" "$UV_BIN" pip sync \
  --python "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" --offline \
  --python-version 3.11 --python-platform x86_64-manylinux_2_28 \
  --no-python-downloads --require-hashes --only-binary :all: \
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
  run_contained_bootstrap "$WORKTREE" "$UV_BIN" venv --no-config --offline --no-python-downloads \
    --python 3.11 "$WORKTREE/packages/gove-zone/.venv-beta"
  run_contained_bootstrap "$WORKTREE" "$UV_BIN" pip sync \
    --python "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" --offline \
    --python-version 3.11 --python-platform x86_64-manylinux_2_28 \
    --no-python-downloads --require-hashes --only-binary :all: \
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
run_contained_bootstrap "$WORKTREE" "$UV_BIN" pip install \
  --python "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" \
  --offline --no-index --no-cache --no-python-downloads --no-build-isolation --no-deps \
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
  run_contained_bootstrap "$WORKTREE" "$UV_BIN" pip install \
    --python "$WORKTREE/packages/gove-zone/.venv-beta/bin/python" \
    --offline --no-index --no-cache --no-python-downloads --no-build-isolation --no-deps \
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
  local append_errexit=0 append_rc=0
  shift 6
  local exact_cwd="${ACGS_LAST_RECORDED_CWD:-}"
  [[ -n "$exact_cwd" ]] || die 'trusted transcript exact cwd is missing'
  case $- in
    *e*)
      append_errexit=1
      set +e
      ;;
  esac
  /usr/bin/python3 -I -S - \
    "$TRUSTED_TRANSCRIPT" "$NODE_EVIDENCE/transcript.jsonl" "$NODE_ID" "$started" "$finished" \
    "$stdout_file" "$stderr_file" "$selector" "$cwd_scope" "$exact_cwd" "$@" <<'PY'
import datetime as _datetime
import hashlib
import json
import os
import pathlib
import stat
import sys

(
    target,
    compatibility_target,
    node_id,
    started,
    finished,
    stdout_path,
    stderr_path,
    selector,
    cwd_scope,
    exact_cwd,
    *argv,
) = sys.argv[1:]

def digest(path):
    candidate = pathlib.Path(path)
    if not candidate.is_file() or candidate.is_symlink():
        raise SystemExit("trusted transcript output path is not a regular file")
    return hashlib.sha256(candidate.read_bytes()).hexdigest()

def utc(value):
    try:
        parsed = _datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise SystemExit("trusted transcript timestamp is malformed") from None
    if parsed.tzinfo is not None:
        raise SystemExit("trusted transcript timestamp timezone is malformed")
    return value

def write_exact(fd, payload, label):
    remaining = memoryview(payload)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise SystemExit(f"{label} short write")
        remaining = remaining[written:]

if not pathlib.Path(exact_cwd).is_absolute():
    raise SystemExit("trusted transcript cwd is not absolute")
if (
    not argv
    or len(argv) > 256
    or any(
        not isinstance(argument, str)
        or not argument
        or len(argument) > 4096
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in argument)
        for argument in argv
    )
):
    raise SystemExit("trusted transcript argv is malformed")
record = {
    "argv": argv,
    "cwd": exact_cwd,
    "exit_code": 0,
    "stdout_sha256": digest(stdout_path),
    "stderr_sha256": digest(stderr_path),
    "started_at_utc": utc(started),
    "finished_at_utc": utc(finished),
    "selectors": [selector],
}
if cwd_scope != "__NONE__":
    record["cwd_scope"] = cwd_scope
target_path = pathlib.Path(target)
if not target_path.is_absolute():
    raise SystemExit("trusted transcript path must be absolute")
target_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
payload = (json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(target_path, flags, 0o600)
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise SystemExit("trusted transcript output must be regular")
    write_exact(fd, payload, "trusted transcript")
    os.fsync(fd)
finally:
    os.close(fd)
compatibility = dict(record)
compatibility.pop("cwd", None)
if compatibility["argv"] and compatibility["argv"][0] == "/home/martin/.local/bin/uv":
    compatibility["argv"] = ["uv", *compatibility["argv"][1:]]
compatibility_path = pathlib.Path(compatibility_target)
if compatibility_path.is_absolute():
    compatibility_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    compatibility_payload = (
        json.dumps(compatibility, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()
    compatibility_fd = os.open(compatibility_path, flags, 0o600)
    try:
        write_exact(compatibility_fd, compatibility_payload, "trusted transcript compatibility")
        os.fsync(compatibility_fd)
    finally:
        os.close(compatibility_fd)
PY
  append_rc=$?
  if (( append_errexit == 1 )); then
    set -e
  fi
  if (( append_rc != 0 )); then
    return "$append_rc"
  fi
  advance_transcript_records_after_append
}

emit_recorded_gate_failure_diagnostic() {
  local gate_ordinal="$1" selector="$2" gate_status="$3"
  if ! /usr/bin/python3 -I -S - "$ACGS_STATUS_FD" \
    "$gate_ordinal" "$selector" "$gate_status" <<'PY'
import hashlib
import json
import socket
import sys

SCHEMA = "acgs.recorded_gate.failure_status"
VERSION = 1
MAX_FRAME_BYTES = 4 * 1024 * 1024

status_fd_raw, gate_ordinal_raw, selector, gate_status_raw = sys.argv[1:]


class DiagnosticUnavailable(Exception):
    pass


def emit(payload):
    rendered = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    frame = rendered.encode("ascii")
    if len(frame) > MAX_FRAME_BYTES:
        raise DiagnosticUnavailable("status-frame-too-large")
    if not status_fd_raw.isdecimal():
        raise DiagnosticUnavailable("status-fd")
    status_socket = socket.socket(fileno=int(status_fd_raw))
    def send_status_body_once(sock, body, ancillary):
        sent = sock.sendmsg([body], ancillary)
        if sent <= 0:
            raise DiagnosticUnavailable("status-send")
        remaining = memoryview(body)[sent:]
        while remaining:
            sent = sock.send(remaining)
            if sent <= 0:
                raise DiagnosticUnavailable("status-send")
            remaining = remaining[sent:]
    try:
        status_socket.sendall(len(frame).to_bytes(4, "big"))
        send_status_body_once(status_socket, frame, [])
    finally:
        status_socket.detach()


try:
    if not gate_ordinal_raw.isdecimal():
        raise DiagnosticUnavailable("gate-ordinal")
    if not gate_status_raw.isdecimal() or not (1 <= int(gate_status_raw) <= 255):
        raise DiagnosticUnavailable("exit-code")
    payload = {
        "exit_code": int(gate_status_raw),
        "gate_ordinal": int(gate_ordinal_raw),
        "schema": SCHEMA,
        "selector_sha256": hashlib.sha256(selector.encode("utf-8")).hexdigest(),
        "version": VERSION,
    }
    emit(payload)
except DiagnosticUnavailable:
    raise SystemExit(2)
except Exception:
    raise SystemExit(2)
PY
  then
    return 2
  fi
}

recorded_gate_selector_sha256() {
  printf '%s' "$1" | sha256sum | awk '{print $1}'
}

run_recorded_gate() {
  local scope="$1" cwd="$2" basename="$3" selector="$4" cwd_scope="$5"
  shift 5
  local started finished stdout_file stderr_file gate_status
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
    emit_recorded_gate_failure_diagnostic "$TRANSCRIPT_RECORDS" "$selector" "$gate_status" || true
    printf 'RECORDED_GATE=FAIL ordinal=%s selector_sha256=%s exit=%s\n' \
      "$TRANSCRIPT_RECORDS" "$(recorded_gate_selector_sha256 "$selector")" "$gate_status" >&2
    return "$gate_status"
  fi
  ACGS_LAST_RECORDED_CWD="$cwd" \
  append_record "$started" "$finished" "$stdout_file" "$stderr_file" "$selector" \
    "$cwd_scope" "$@"
}

run_trusted_parent_postgres_gate() {
  local scope="$1" cwd="$2" basename="$3" selector="$4" cwd_scope="$5"
  shift 5
  local started finished stdout_file stderr_file gate_status tmpdir
  local runner_path runner_fd runner_path_stat runner_fd_stat runner_sha runner_size
  local trusted_runner_sha256='d504135dbecc9d376948514d49b3090c42ffecfab0a0339e107505fb8bbb50a1'
  [[ "$scope" == CP ]] || die 'trusted parent PostgreSQL gate is CP-only'
  [[ "$cwd" == "$WORKTREE/packages/acgs-control-plane" ]] ||
    die 'trusted parent PostgreSQL gate cwd must be the control-plane package'
  [[ "${1:-}" == ./scripts/run_postgres_gate.sh ]] ||
    die 'trusted parent PostgreSQL gate only runs the reviewed wrapper'
  [[ -x "$BWRAP_BIN" && ! -L "$BWRAP_BIN" ]] ||
    die 'trusted parent PostgreSQL gate requires bwrap'
  runner_path="$cwd/scripts/run_postgres_gate.sh"
  [[ -f "$runner_path" && ! -L "$runner_path" ]] ||
    die 'trusted parent PostgreSQL runner is unavailable'
  exec {runner_fd}<"$runner_path"
  runner_path_stat="$(stat -Lc '%d:%i:%u:%a:%h' -- "$runner_path")"
  runner_fd_stat="$(stat -Lc '%d:%i:%u:%a:%h' -- "/proc/$BASHPID/fd/$runner_fd")"
  [[ "$runner_path_stat" == "$runner_fd_stat" ]] ||
    die 'trusted parent PostgreSQL runner fd identity mismatch'
  [[ "${runner_path_stat##*:}" == 1 ]] ||
    die 'trusted parent PostgreSQL runner must be single-link'
  IFS=: read -r _ _ runner_owner runner_mode _ <<<"$runner_path_stat"
  [[ "$runner_owner" == "$(id -u)" ]] ||
    die 'trusted parent PostgreSQL runner owner mismatch'
  [[ $((runner_mode / 10 % 10 & 2)) -eq 0 && $((runner_mode % 10 & 2)) -eq 0 ]] ||
    die 'trusted parent PostgreSQL runner must not be group/world writable'
  runner_sha="$(sha256sum "/proc/$BASHPID/fd/$runner_fd" | awk '{print $1}')"
  [[ "$runner_sha" == "$trusted_runner_sha256" ]] ||
    die 'trusted parent PostgreSQL runner digest mismatch'
  runner_size="$(stat -Lc '%s' -- "/proc/$BASHPID/fd/$runner_fd")"
  tmpdir="${TMPDIR:-/tmp}"
  stdout_file="$NODE_EVIDENCE/$basename.stdout"
  stderr_file="$NODE_EVIDENCE/$basename.stderr"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  verify_uv_identity
  if (
    local -a ACGS_UV_SNAPSHOT_MOUNT
    local -a ACGS_PREFLIGHT_ENV
    open_uv_snapshot_data_fd
    open_regular_data_fd postgres-runner "$runner_fd" "$runner_path_stat" \
      "$trusted_runner_sha256" ACGS_POSTGRES_RUNNER_DATA_FD
    close_noncontained_fds
    mapfile -d '' -t ACGS_UV_SNAPSHOT_MOUNT < <(contained_uv_snapshot_data_mount_args)
    mapfile -d '' -t ACGS_PREFLIGHT_ENV < <(
      mounted_artifact_preflight_env_args_postgres "$runner_path" "$trusted_runner_sha256" "$runner_size"
    )
    validate_regular_data_fd postgres-runner "$ACGS_POSTGRES_RUNNER_DATA_FD" \
      "$runner_path_stat" "$trusted_runner_sha256"
    # Intentionally omit outer --disable-userns so the descriptor-validated,
    # SHA-pinned PostgreSQL runner can create its sealed inner user namespace.
    lower_descendant_file_size_limit
    exec "$BWRAP_BIN" \
      --die-with-parent \
      --unshare-user \
      --unshare-ipc \
      --unshare-pid \
      --new-session \
      --cap-drop ALL \
      --proc /proc \
      --dev /dev \
      --tmpfs /run \
      --dir /run/service \
      --dir /var \
      --symlink /run /var/run \
      --ro-bind /usr /usr \
      --ro-bind /bin /bin \
      --ro-bind-try /lib /lib \
      --ro-bind-try /lib64 /lib64 \
      --bind "$TMP_ROOT" "$TMP_ROOT" \
      --bind "$ACGS_POSTGRES_RECOVERY_ROOT" "$ACGS_POSTGRES_RECOVERY_ROOT" \
      --ro-bind "$WORKTREE" "$WORKTREE" \
      "${ACGS_UV_SNAPSHOT_MOUNT[@]}" \
      --perms 500 --ro-bind-data "$ACGS_POSTGRES_RUNNER_DATA_FD" "$runner_path" \
      --bind-try /var/run/docker.sock /run/docker.sock \
      --chdir "$cwd" \
      /usr/bin/env -i "${ACGS_PREFLIGHT_ENV[@]}" \
        /bin/bash --noprofile --norc -c "$ACGS_MOUNTED_ARTIFACT_PREFLIGHT_SCRIPT" _ \
        /bin/bash --noprofile --norc -c '
        set -Eeuo pipefail
        for fd_path in /proc/$$/fd/*; do
          fd="${fd_path##*/}"
          case "$fd" in
            0 | 1 | 2) ;;
            *) eval "exec $fd<&-" 2>/dev/null || true ;;
          esac
        done
        unset \
          ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_MKDIR \
          ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_MARKER_WRITE \
          ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_BRIDGE_FSYNC \
          ACGS_POSTGRES_SOCKET_BRIDGE_FAULT_AFTER_ROOT_FSYNC \
          ACGS_POSTGRES_SOCKET_BRIDGE_RENAME_EXCHANGE_AFTER_MKDIR \
          ACGS_POSTGRES_SOCKET_BRIDGE_EXCHANGE_INSIDE_MKDIR \
          ACGS_POSTGRES_SOCKET_BRIDGE_MOVE_OUTSIDE_ROOT_INSIDE_MKDIR \
          ACGS_POSTGRES_SOCKET_BRIDGE_MOVE_UNDER_BASELINE_CHILD_INSIDE_MKDIR \
          ACGS_POSTGRES_SOCKET_BRIDGE_PREPOPULATE_SUBSTITUTE_INSIDE_MKDIR
        recovery_root_binding="$(
          /usr/bin/python3 -I -S - "$4" "$5" <<'"'"'PY'"'"'
from __future__ import annotations

import os
import stat
import sys

root, expected_identity = sys.argv[1:3]
fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        raise SystemExit(70)
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise SystemExit(70)
    descriptor_path = os.path.realpath(f"/proc/self/fd/{fd}")
    if descriptor_path != os.path.realpath(root):
        raise SystemExit(70)
    observed_identity = f"{st.st_dev}:{st.st_ino}:{st.st_uid}:700"
    if observed_identity != expected_identity:
        raise SystemExit(70)
    mnt_id = ""
    with open(f"/proc/self/fdinfo/{fd}", encoding="utf-8") as fdinfo:
        for line in fdinfo:
            if line.startswith("mnt_id:"):
                mnt_id = line.split(":", 1)[1].strip()
                break
    if not mnt_id.isdigit():
        raise SystemExit(70)
    print(f"acgs-postgres-recovery-root/v2\t{observed_identity}\t{mnt_id}")
finally:
    os.close(fd)
PY
        )" || exit 70
        exec env -i \
          PATH=/usr/bin:/bin \
          HOME=/dev/null \
          TMPDIR="$1" \
          UV_BIN="$2" \
          UV_PYTHON_INSTALL_DIR="$3" \
          ACGS_POSTGRES_RECOVERY_ROOT="$4" \
          ACGS_POSTGRES_RECOVERY_ROOT_BINDING_V2="$recovery_root_binding" \
          ACGS_TEST_SEED=20260710 \
          PYTHONHASHSEED=0 \
          "$6" "${@:7}"
      ' _ "$tmpdir" "$UV_BIN" "$UV_PYTHON_INSTALL_DIR" \
      "$ACGS_POSTGRES_RECOVERY_ROOT" \
      "$ACGS_POSTGRES_RECOVERY_ROOT_DEVICE:$ACGS_POSTGRES_RECOVERY_ROOT_INODE:$ACGS_POSTGRES_RECOVERY_ROOT_UID:700" \
      "$@"
  ) >"$stdout_file" 2>"$stderr_file"; then
    gate_status=0
  else
    gate_status=$?
  fi
  exec {runner_fd}<&-
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "$gate_status" -ne 0 ]]; then
    emit_recorded_gate_failure_diagnostic "$TRANSCRIPT_RECORDS" "$selector" "$gate_status" || true
    printf 'RECORDED_GATE=FAIL ordinal=%s selector_sha256=%s exit=%s\n' \
      "$TRANSCRIPT_RECORDS" "$(recorded_gate_selector_sha256 "$selector")" "$gate_status" >&2
    return "$gate_status"
  fi
  ACGS_LAST_RECORDED_CWD="$cwd" \
  append_record "$started" "$finished" "$stdout_file" "$stderr_file" "$selector" \
    "$cwd_scope" "$@"
}

run_trusted_parent_p0_launcher_authority_gate() {
  local scope="$1" cwd="$2" basename="$3" selector="$4" cwd_scope="$5"
  shift 5
  local started finished stdout_file stderr_file gate_status
  local launcher_path launcher_fd launcher_path_stat launcher_fd_stat launcher_sha
  local trusted_launcher_sha256='bda70bc471f9399ddc4750ccb1b57011920a9cb9e79c67d5b79b020e9cec878b'
  local target_sha='1111111111111111111111111111111111111111'
  [[ "$scope" == P0 ]] || die 'trusted parent P0 launcher gate is P0-only'
  [[ "$cwd" == "$WORKTREE" ]] || die 'trusted parent P0 launcher gate cwd must be repository root'
  [[ "$selector" == root:P0-EVIDENCE-000-launcher-authority-harness ]] ||
    die 'trusted parent P0 launcher selector changed'
  [[ "$#" == 6 && "${1:-}" == /usr/bin/python3 && "${2:-}" == -I &&
    "${3:-}" == -S && "${4:-}" == - && "${5:-}" == scripts/evidence/prove_clean_sibling &&
    "${6:-}" == "$target_sha" ]] || die 'trusted parent P0 launcher argv changed'
  launcher_path="$WORKTREE/scripts/evidence/prove_clean_sibling"
  [[ -f "$launcher_path" && ! -L "$launcher_path" ]] ||
    die 'trusted parent P0 launcher is unavailable'
  exec {launcher_fd}<"$launcher_path"
  launcher_path_stat="$(stat -Lc '%d:%i:%u:%a:%h' -- "$launcher_path")"
  launcher_fd_stat="$(stat -Lc '%d:%i:%u:%a:%h' -- "/proc/$BASHPID/fd/$launcher_fd")"
  [[ "$launcher_path_stat" == "$launcher_fd_stat" ]] ||
    die 'trusted parent P0 launcher fd identity mismatch'
  [[ "${launcher_path_stat##*:}" == 1 ]] ||
    die 'trusted parent P0 launcher must be single-link'
  IFS=: read -r _ _ launcher_owner launcher_mode _ <<<"$launcher_path_stat"
  [[ "$launcher_owner" == "$(id -u)" ]] ||
    die 'trusted parent P0 launcher owner mismatch'
  [[ $((launcher_mode / 10 % 10 & 2)) -eq 0 && $((launcher_mode % 10 & 2)) -eq 0 ]] ||
    die 'trusted parent P0 launcher must not be group/world writable'
  launcher_sha="$(sha256sum "/proc/$BASHPID/fd/$launcher_fd" | awk '{print $1}')"
  [[ "$launcher_sha" == "$trusted_launcher_sha256" ]] ||
    die 'trusted parent P0 launcher digest mismatch'
  verify_authenticated_launch_context ||
    die 'trusted parent P0 launcher context is unauthenticated'
  stdout_file="$NODE_EVIDENCE/$basename.stdout"
  stderr_file="$NODE_EVIDENCE/$basename.stderr"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if (
    cd "$WORKTREE"
    verify_uv_identity
    env -i \
      PATH=/usr/bin:/bin \
      LANG=C.UTF-8 \
      LC_ALL=C.UTF-8 \
      TMPDIR="$TMP_ROOT" \
      HOME=/dev/null \
      XDG_CONFIG_HOME=/dev/null \
      DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
      XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
      "$@" <<'PY'
import hashlib
import json
import os
import resource
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_CASE_OUTPUT_BYTES = 8 * 1024 * 1024
REVIEWED_PARENT = "26d11c2c7a8da37937a7c50c642f18edc75c9345"
TARGET = "1111111111111111111111111111111111111111"
ATOMIC_FAULT_VALUES = (
    "intent:after-temp-create",
    "intent:partial-write",
    "intent:after-file-fsync",
    "intent:after-atomic-publish",
    "intent:after-dir-fsync",
    "ledger:after-temp-create",
    "ledger:partial-write",
    "ledger:after-file-fsync",
    "ledger:after-atomic-publish",
    "ledger:after-dir-fsync",
)
FORBIDDEN_TEXT = (
    "CLEAN_SIBLING=FAIL phase=B0 reason=",
    "CLEAN_SIBLING_TECHNICAL=PASS",
    "T commit is unavailable",
    "authenticated runtime bus unavailable",
    "authenticated systemd tooling unavailable",
    "null OID",
)
def fail(message: str) -> None:
    raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_executable(label: str, path_text: str) -> dict[str, object]:
    path = Path(path_text)
    resolved = path.resolve(strict=True)
    st = resolved.stat()
    mode = stat.S_IMODE(st.st_mode)
    if st.st_uid != 0:
        fail(f"host executable owner mismatch: {label}")
    if mode & 0o022:
        fail(f"host executable is group/world writable: {label}")
    if not os.access(resolved, os.X_OK):
        fail(f"host executable is not executable: {label}")
    return {
        "id": label,
        "mode": oct(mode),
        "sha256": sha256_file(resolved),
    }


def bounded_preexec() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024 * 1024, 8 * 1024 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_CPU, (30 * 60, 30 * 60))
    resource.setrlimit(resource.RLIMIT_AS, (8 * 1024 * 1024 * 1024, 8 * 1024 * 1024 * 1024))


def run_checked(command: list[str], *, env: dict[str, str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    input_bytes = input_text.encode("utf-8") if input_text is not None else None
    stdin_mode = subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        stdin=stdin_mode,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        preexec_fn=bounded_preexec,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        if input_bytes is not None:
            assert process.stdin is not None
            try:
                process.stdin.write(input_bytes)
                process.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                process.stdin.close()

        streams = {
            process.stdout.fileno(): ("stdout", process.stdout),
            process.stderr.fileno(): ("stderr", process.stderr),
        }
        chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
        sizes = {"stdout": 0, "stderr": 0}
        selector = selectors.DefaultSelector()
        for fd, (name, stream) in streams.items():
            os.set_blocking(fd, False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = 90 - (time.monotonic() - started)
            if remaining <= 0:
                process.kill()
                process.wait(timeout=5)
                fail("trusted launcher case timed out")
            for key, _events in selector.select(timeout=min(0.2, remaining)):
                name = key.data
                try:
                    data = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                sizes[name] += len(data)
                if sizes[name] > MAX_CASE_OUTPUT_BYTES:
                    process.kill()
                    process.wait(timeout=5)
                    fail("trusted launcher case output exceeded bounded capture")
                chunks[name].append(data)
        returncode = process.wait(timeout=5)
    finally:
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    return subprocess.CompletedProcess(
        command,
        returncode,
        b"".join(chunks["stdout"]).decode("utf-8", errors="replace"),
        b"".join(chunks["stderr"]).decode("utf-8", errors="replace"),
    )


def assert_positive_controls(root: Path) -> dict[str, object]:
    missing_preload = root / "missing-preload-do-not-create.so"
    loader_env = {"PATH": "/usr/bin:/bin", "LD_PRELOAD": str(missing_preload)}
    loader = run_checked(["/bin/true"], env=loader_env)
    if loader.returncode != 0 or str(missing_preload) not in loader.stderr:
        fail("LD_PRELOAD positive control did not prove dynamic-loader observation")
    function_marker = root / "imported-function-ran"
    function_env = {
        "PATH": "/usr/bin:/bin",
        "BASH_FUNC_realpath%%": (
            f"() {{ /usr/bin/touch {function_marker}; /usr/bin/realpath \"$@\"; }}"
        ),
    }
    function = run_checked(
        ["/bin/bash", "--noprofile", "--norc", "-s"],
        env=function_env,
        input_text="realpath /\n",
    )
    if function.returncode != 0 or not function_marker.is_file():
        fail("Bash imported-function positive control did not execute")
    git_marker = root / "git-positive-control-marker"
    hostile = root / "hostile.gitconfig"
    hostile.write_text(
        f"[core]\n\tfsmonitor = !touch {git_marker}\n\thooksPath = {root / 'hooks'}\n",
        encoding="utf-8",
    )
    hostile_home = root / "hostile-home"
    hostile_home.mkdir(mode=0o700)
    shutil.copy2(hostile, hostile_home / ".gitconfig")
    hostile_xdg = root / "hostile-xdg"
    (hostile_xdg / "git").mkdir(parents=True, mode=0o700)
    shutil.copy2(hostile, hostile_xdg / "git/config")

    def git_value(env: dict[str, str], args: list[str]) -> str:
        completed = run_checked(["/usr/bin/git", *args], env=env)
        if completed.returncode != 0:
            fail(f"Git positive control failed: {completed.stderr[:200]}")
        return completed.stdout.strip()

    expected = f"!touch {git_marker}"
    observed = {
        "global": git_value({"PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": str(hostile)}, ["config", "--global", "--get", "core.fsmonitor"]),
        "count": git_value(
            {
                "PATH": "/usr/bin:/bin",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.fsmonitor",
                "GIT_CONFIG_VALUE_0": expected,
            },
            ["config", "--get", "core.fsmonitor"],
        ),
        "home": git_value({"PATH": "/usr/bin:/bin", "HOME": str(hostile_home)}, ["config", "--global", "--get", "core.fsmonitor"]),
        "xdg": git_value(
            {"PATH": "/usr/bin:/bin", "HOME": str(root / "empty-home"), "XDG_CONFIG_HOME": str(hostile_xdg)},
            ["config", "--global", "--get", "core.fsmonitor"],
        ),
    }
    if any(value != expected for value in observed.values()):
        fail("Git positive control did not observe every hostile config source")
    if git_marker.exists():
        fail("Git positive control executed hostile config value")
    return {
        "git_config_sha256": sha256_file(hostile),
        "git_sources": sorted(observed),
        "loader_stderr_sha256": hashlib.sha256(loader.stderr.encode()).hexdigest(),
    }


def launcher_env(base_env: dict[str, str], injected: dict[str, str], caller: Path) -> dict[str, str]:
    keep = {
        key: value
        for key, value in base_env.items()
        if key
        in {
            "DBUS_SESSION_BUS_ADDRESS",
            "XDG_RUNTIME_DIR",
            "LANG",
            "LC_ALL",
            "PATH",
            "SYSTEMD_PAGER",
            "SYSTEMD_LESS",
        }
    }
    keep.setdefault("PATH", "/usr/bin:/bin")
    keep.setdefault("LANG", "C.UTF-8")
    keep.setdefault("LC_ALL", "C.UTF-8")
    keep.update(injected)
    keep.update({"P": REVIEWED_PARENT, "NODE_ID": "P0-EVIDENCE-000", "TMPDIR": str(caller)})
    for key in list(keep):
        if key.startswith("ACGS_CLEAN_SIBLING_"):
            keep.pop(key)
    return keep


def run_launcher_cases(launcher: Path, root: Path) -> list[dict[str, object]]:
    hostile = root / "hostile.gitconfig"
    git_marker = root / "git-injection-marker"
    hostile.write_text(
        f"[core]\n\tfsmonitor = !touch {git_marker}\n\thooksPath = {root / 'hooks'}\n",
        encoding="utf-8",
    )
    hostile_home = root / "hostile-home-case"
    hostile_home.mkdir(mode=0o700)
    shutil.copy2(hostile, hostile_home / ".gitconfig")
    hostile_xdg = root / "hostile-xdg-case"
    (hostile_xdg / "git").mkdir(parents=True, mode=0o700)
    shutil.copy2(hostile, hostile_xdg / "git/config")
    function_marker = root / "function-injection-marker"
    missing_preload = root / "missing-launcher-preload.so"
    cases = {
        "loader": {"LD_PRELOAD": str(missing_preload)},
        "function": {
            "BASH_FUNC_realpath%%": (
                f"() {{ /usr/bin/touch {function_marker}; /usr/bin/realpath \"$@\"; }}"
            )
        },
        "global": {"GIT_CONFIG_GLOBAL": str(hostile)},
        "count": {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": f"!touch {git_marker}",
        },
        "home": {"HOME": str(hostile_home)},
        "xdg": {"XDG_CONFIG_HOME": str(hostile_xdg)},
    }
    summaries = []
    for name, injected in cases.items():
        caller = root / f"caller-{name}"
        caller.mkdir(mode=0o700)
        sentinel = caller / "sentinel"
        sentinel.write_bytes(b"unchanged")
        completed = run_checked(
            [str(launcher), TARGET],
            env=launcher_env(os.environ, injected, caller),
        )
        combined = completed.stdout + completed.stderr
        if completed.returncode != 2:
            fail(f"{name} launcher case returned {completed.returncode}")
        if "CLEAN_SIBLING=FAIL phase=FINAL reason=child exited 2 " not in completed.stderr:
            fail(f"{name} launcher case did not use guardian final summary")
        for required in ("captured_sha256=", "captured_contains_pass=0"):
            if required not in completed.stderr:
                fail(f"{name} launcher case missing {required}")
        for forbidden in FORBIDDEN_TEXT:
            if forbidden in combined:
                fail(f"{name} launcher case leaked forbidden text")
        if sentinel.read_bytes() != b"unchanged":
            fail(f"{name} launcher case mutated sentinel")
        if sorted(path.name for path in caller.iterdir()) != ["sentinel"]:
            fail(f"{name} launcher case mutated caller directory")
        if git_marker.exists() or function_marker.exists() or missing_preload.exists():
            fail(f"{name} launcher case executed injected authority")
        summaries.append(
            {
                "case": name,
                "returncode": completed.returncode,
                "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
                "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
                "stderr_bytes": len(completed.stderr.encode()),
                "stdout_bytes": len(completed.stdout.encode()),
            }
        )
    return summaries


def run_forbidden_atomic_fault_cases(launcher: Path, root: Path) -> list[dict[str, object]]:
    summaries = []
    for value in ATOMIC_FAULT_VALUES:
        case_name = value.replace(":", "-")
        caller = root / f"caller-forbidden-atomic-{case_name}"
        caller.mkdir(mode=0o700)
        sentinel = caller / "sentinel"
        sentinel.write_bytes(b"unchanged")
        env = launcher_env(os.environ, {}, caller)
        env["ACGS_CLEAN_SIBLING_ATOMIC_FAULT"] = value
        completed = run_checked(
            [str(launcher), TARGET],
            env=env,
        )
        combined = completed.stdout + completed.stderr
        if completed.returncode != 2:
            fail(f"{value} forbidden atomic fault case returned {completed.returncode}")
        if "CLEAN_SIBLING=FAIL phase=FINAL reason=child exited 2 " not in completed.stderr:
            fail(f"{value} forbidden atomic fault case did not use guardian final summary")
        for required in ("captured_sha256=", "captured_contains_pass=0"):
            if required not in completed.stderr:
                fail(f"{value} forbidden atomic fault case missing {required}")
        for forbidden in FORBIDDEN_TEXT:
            if forbidden in combined:
                fail(f"{value} forbidden atomic fault case leaked forbidden text")
        if sentinel.read_bytes() != b"unchanged":
            fail(f"{value} forbidden atomic fault case mutated sentinel")
        if sorted(path.name for path in caller.iterdir()) != ["sentinel"]:
            fail(f"{value} forbidden atomic fault case mutated caller directory")
        summaries.append(
            {
                "case": value,
                "returncode": completed.returncode,
                "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
                "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
                "stderr_bytes": len(completed.stderr.encode()),
                "stdout_bytes": len(completed.stdout.encode()),
            }
        )
    return summaries


def main() -> None:
    global RUN_CAPTURE_DIR
    if sys.argv[1:] != ["scripts/evidence/prove_clean_sibling", TARGET]:
        fail("trusted harness argv changed")
    launcher = Path(sys.argv[1])
    canonical = launcher.resolve(strict=True)
    if canonical != (Path.cwd() / "scripts/evidence/prove_clean_sibling").resolve(strict=True):
        fail("launcher canonical path mismatch")
    root = Path(tempfile.mkdtemp(prefix="acgs-p0-launcher-authority.", dir=os.environ["TMPDIR"]))
    os.chmod(root, 0o700)
    RUN_CAPTURE_DIR = root / "captures"
    RUN_CAPTURE_DIR.mkdir(mode=0o700)
    payload = None
    cleanup_error = None
    try:
        controls = assert_positive_controls(root)
        cases = run_launcher_cases(canonical, root)
        forbidden_atomic_fault_cases = run_forbidden_atomic_fault_cases(canonical, root)
        executables = [
            validate_executable(label, path)
            for label, path in (
                ("python3", "/usr/bin/python3"),
                ("git", "/usr/bin/git"),
                ("bash", "/bin/bash"),
                ("true", "/bin/true"),
                ("busybox", "/usr/bin/busybox"),
            )
        ]
        payload = json.dumps(
            {
                "cases": cases,
                "executables": executables,
                "forbidden_atomic_fault_cases": forbidden_atomic_fault_cases,
                "launcher": {
                    "id": "scripts/evidence/prove_clean_sibling",
                    "sha256": sha256_file(canonical),
                },
                "positive_controls": controls,
                "schema": "acgs.p0.launcher_authority_harness.v1",
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    finally:
        try:
            shutil.rmtree(root)
        except Exception as exc:
            cleanup_error = exc
        if root.exists() and cleanup_error is None:
            cleanup_error = RuntimeError("trusted launcher harness root remains after cleanup")
    if cleanup_error is not None:
        fail("trusted launcher harness cleanup failed")
    print(payload)


main()
PY
  ) >"$stdout_file" 2>"$stderr_file"; then
    gate_status=0
  else
    gate_status=$?
  fi
  exec {launcher_fd}<&-
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "$gate_status" -ne 0 ]]; then
    emit_recorded_gate_failure_diagnostic "$TRANSCRIPT_RECORDS" "$selector" "$gate_status" || true
    printf 'RECORDED_GATE=FAIL ordinal=%s selector_sha256=%s exit=%s\n' \
      "$TRANSCRIPT_RECORDS" "$(recorded_gate_selector_sha256 "$selector")" "$gate_status" >&2
    return "$gate_status"
  fi
  ACGS_LAST_RECORDED_CWD="$cwd" \
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
  local started finished stdout_file stderr_file junit_file gate_status
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
    emit_recorded_gate_failure_diagnostic "$TRANSCRIPT_RECORDS" "$selector" "$gate_status" || true
    printf 'RECORDED_GATE=FAIL ordinal=%s selector_sha256=%s exit=%s\n' \
      "$TRANSCRIPT_RECORDS" "$(recorded_gate_selector_sha256 "$selector")" "$gate_status" >&2
    return "$gate_status"
  fi
  set +e
  validate_exact_pytest_junit "$junit_file" "$expected_tests" "$selector"
  gate_status=$?
  set -e
  if [[ "$gate_status" -ne 0 ]]; then
    emit_recorded_gate_failure_diagnostic "$TRANSCRIPT_RECORDS" "$selector" "$gate_status" || true
    printf 'RECORDED_GATE=FAIL ordinal=%s selector_sha256=%s exit=%s\n' \
      "$TRANSCRIPT_RECORDS" "$(recorded_gate_selector_sha256 "$selector")" "$gate_status" >&2
    return "$gate_status"
  fi
  ACGS_LAST_RECORDED_CWD="$cwd" \
  append_record "$started" "$finished" "$stdout_file" "$stderr_file" "$selector" \
    "$cwd_scope" "$@"
}

phase B5
node_cwd_scope() {
  local default_scope="$1"
  case "$NODE_ID" in
    P1-MIGRATION-001 | P1-SCOPE-002 | P1-LEDGER-003 | P1-TRUST-004 | \
    P2-TENANT-BOOTSTRAP-000 | P2-REGISTER-001 | P2-IDEMPOTENCY-002 | \
      P2-VERTICAL-GATE-003 | P3-POLICY-001 | P3-MUTATIONS-002 | \
      P3-APPROVAL-003)
      printf '%s' "$default_scope"
      ;;
    *) printf __NONE__ ;;
  esac
}

ACGS_LAST_RECORDED_CWD="$WORKTREE" \
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

run_contained_bootstrap "$WORKTREE" "$EVIDENCE_PY" \
  "$WORKTREE/scripts/evidence/capture_environment.py" \
  --code CP \
  --interpreter "$WORKTREE/packages/acgs-control-plane/.venv/bin/python" \
  --lock "$WORKTREE/requirements/saas-beta/cp-test.lock" \
  --require-editables 0.6 \
  --output "$NODE_EVIDENCE/environment-CP.json"
if [[ "$INCLUDE_GZ" == 1 ]]; then
  run_contained_bootstrap "$WORKTREE" "$EVIDENCE_PY" \
    "$WORKTREE/scripts/evidence/capture_environment.py" \
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
    tests/saas_beta/test_evidence_bootstrap.py::test_environment_identities_exactly_match_assignment \
    tests/saas_beta/test_evidence_bootstrap.py::test_missing_extra_or_retained_environment_rejected \
    tests/saas_beta/test_evidence_bootstrap.py::test_pep660_helpers_required_for_assigned_python_scopes)
  run_trusted_parent_p0_launcher_authority_gate P0 "$WORKTREE" p0-launcher-authority \
    'root:P0-EVIDENCE-000-launcher-authority-harness' __NONE__ \
    /usr/bin/python3 -I -S - scripts/evidence/prove_clean_sibling \
    1111111111111111111111111111111111111111
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
    tests/integration/test_migrations_postgres.py::test_failed_migration_no_later_state \
    tests/integration/test_migrations_postgres.py::test_revision_0010_refuses_historical_approval_votes_without_invented_bindings)
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
elif [[ "$NODE_ID" == P2-VERTICAL-GATE-003 ]]; then
  P2_VERTICAL_GATE_CP_GATE=(./scripts/run_postgres_gate.sh \
    tests/integration/test_vertical_gate_postgres.py::test_real_postgres_tenant_bootstrap_then_customer_agent_register \
    tests/integration/test_vertical_gate_postgres.py::test_real_postgres_vertical_negative_oracles_and_production_legacy_reachability)
  run_trusted_parent_postgres_gate CP \
    "$WORKTREE/packages/acgs-control-plane" p2-vertical-postgres \
    'packages/acgs-control-plane:P2-VERTICAL-GATE-003-postgres-vertical-gate' CP \
    "${P2_VERTICAL_GATE_CP_GATE[@]}"
  P2_VERTICAL_ROOT_GATE=(packages/acgs-control-plane/.venv/bin/python -m pytest -q \
    tests/saas_beta/test_cross_plane_contracts.py::test_tenant_bootstrap_receipt_contract \
    tests/saas_beta/test_cross_plane_contracts.py::test_vertical_gate_contract_locks_managed_routes_and_production_blockers)
  run_recorded_exact_pytest_gate P2 "$WORKTREE" p2-vertical-cross-plane \
    'root:P2-VERTICAL-GATE-003-cross-plane-contract' REPO_ROOT 2 \
    "${P2_VERTICAL_ROOT_GATE[@]}"
  P2_VERTICAL_GZ_GATE=("$UV_BIN" run --active --no-sync --python 3.11 --package gove-zone \
    python -m pytest \
    packages/gove-zone/tests/test_authz_enforcement.py::test_enforce_allows_registered_principal_through_dispatcher \
    packages/gove-zone/tests/test_authz_enforcement.py::test_enforce_denies_unregistered_actor_through_dispatcher \
    packages/gove-zone/tests/test_mcp_binding.py::test_unregistered_tool_cannot_run_and_is_not_audited \
    packages/gove-zone/tests/test_mcp_binding.py::test_runtime_registered_tool_is_gated_with_zero_binding_changes \
    --import-mode=importlib -q)
  run_recorded_exact_pytest_gate GZ "$WORKTREE" p2-vertical-runtime \
    'packages/gove-zone:P2-VERTICAL-GATE-003-runtime-registration-gate' REPO_ROOT 4 \
    "${P2_VERTICAL_GZ_GATE[@]}"
elif [[ "$NODE_ID" == P3-POLICY-001 ]]; then
  P3_POLICY_CP_GATE=(./scripts/run_postgres_gate.sh \
    tests/integration/test_managed_policy_lifecycle_postgres.py::test_pg_publish_immutable_version_without_head \
    tests/integration/test_managed_policy_lifecycle_postgres.py::test_pg_activate_advances_exactly_one_head \
    tests/integration/test_managed_policy_lifecycle_postgres.py::test_pg_concurrent_candidates_have_one_generation_winner \
    tests/integration/test_managed_policy_lifecycle_postgres.py::test_pg_publish_idempotent_replay_is_one_terminal_effect \
    tests/integration/test_managed_policy_lifecycle_postgres.py::test_pg_idempotency_conflict_has_zero_delta \
    tests/integration/test_managed_policy_lifecycle_postgres.py::test_pg_activation_revalidates_trust_and_rolls_back_before_effect)
  run_trusted_parent_postgres_gate CP \
    "$WORKTREE/packages/acgs-control-plane" p3-policy-postgres \
    'packages/acgs-control-plane:P3-POLICY-001-postgres-policy-gate' CP \
    "${P3_POLICY_CP_GATE[@]}"
  P3_POLICY_ROOT_GATE=(packages/acgs-control-plane/.venv/bin/python -m pytest -q \
    tests/saas_beta/test_cross_plane_contracts.py::test_policy_registry_contract_locks_managed_routes_negative_oracles_and_local_posture)
  run_recorded_exact_pytest_gate P3 "$WORKTREE" p3-policy-cross-plane \
    'root:P3-POLICY-001-cross-plane-contract' REPO_ROOT 1 \
    "${P3_POLICY_ROOT_GATE[@]}"
elif [[ "$NODE_ID" == P3-MUTATIONS-002 ]]; then
  P3_MUTATIONS_CP_GATE=(./scripts/run_postgres_gate.sh \
    tests/integration/test_mutation_inventory_postgres.py::test_pg_agent_register_commits_one_sql_atomic_managed_mutation \
    tests/integration/test_mutation_inventory_postgres.py::test_pg_route_app_drift_refuses_before_replacement_and_preserves_sql_counts \
    tests/integration/test_mutation_inventory_postgres.py::test_pg_service_binding_drift_preserves_sql_counts_and_legacy_blockers \
    tests/integration/test_mutation_inventory_postgres.py::test_pg_legacy_regex_precedence_drift_preserves_sql_counts_before_bootstrap)
  run_trusted_parent_postgres_gate CP \
    "$WORKTREE/packages/acgs-control-plane" p3-mutations-postgres \
    'packages/acgs-control-plane:P3-MUTATIONS-002-postgres-mutation-inventory-gate' CP \
    "${P3_MUTATIONS_CP_GATE[@]}"
  P3_MUTATIONS_ROOT_GATE=(packages/acgs-control-plane/.venv/bin/python -m pytest -q \
    tests/saas_beta/test_cross_plane_contracts.py::test_mutation_inventory_contract_locks_registry_and_actual_routing)
  run_recorded_exact_pytest_gate P3 "$WORKTREE" p3-mutations-cross-plane \
    'root:P3-MUTATIONS-002-cross-plane-contract' REPO_ROOT 1 \
    "${P3_MUTATIONS_ROOT_GATE[@]}"
elif [[ "$NODE_ID" == P3-APPROVAL-003 ]]; then
  P3_APPROVAL_CP_GATE=(./scripts/run_postgres_gate.sh \
    tests/integration/test_approval_resume_postgres.py::test_pg_escalate_creates_scoped_pending_without_agent_or_consumption \
    tests/integration/test_approval_resume_postgres.py::test_pg_self_and_wrong_role_approval_are_non_executable \
    tests/integration/test_approval_resume_postgres.py::test_pg_resume_before_required_vote_is_non_executable \
    tests/integration/test_approval_resume_postgres.py::test_pg_approved_resume_executes_once_and_replay_is_stable \
    tests/integration/test_approval_resume_postgres.py::test_pg_rejected_and_expired_requests_resume_zero_side_effects \
    tests/integration/test_approval_resume_postgres.py::test_pg_concurrent_vote_refusal_replay_records_one_evidence_set \
    tests/integration/test_approval_resume_postgres.py::test_pg_mixed_refusal_then_allow_same_vote_key_has_one_terminal_artifact \
    tests/integration/test_approval_resume_postgres.py::test_pg_stale_policy_trust_and_requester_resume_zero_side_effects \
    tests/integration/test_approval_resume_postgres.py::test_pg_tampered_sealed_payload_resume_zero_side_effects \
    tests/integration/test_approval_resume_postgres.py::test_pg_multiprocess_resume_race_authorizes_one_agent \
    tests/integration/test_approval_resume_postgres.py::test_pg_approval_composite_constraints_reject_cross_scope_rows)
  run_trusted_parent_postgres_gate CP \
    "$WORKTREE/packages/acgs-control-plane" p3-approval-postgres \
    'packages/acgs-control-plane:P3-APPROVAL-003-postgres-approval-gate' CP \
    "${P3_APPROVAL_CP_GATE[@]}"
  P3_APPROVAL_GZ_GATE=("$UV_BIN" run --active --no-sync --python 3.11 --package gove-zone \
    python -m pytest \
    packages/gove-zone/tests/test_mcp_gateway_conformance.py::test_escalate_approve_resume_single_use \
    packages/gove-zone/tests/test_mcp_gateway_conformance.py::test_cross_pending_reuse \
    packages/gove-zone/tests/test_receipt_consumption.py::test_resume_replay_blocked_with_ledger \
    packages/gove-zone/tests/test_receipt_consumption.py::test_concurrent_consumers_single_winner \
    --import-mode=importlib -q)
  run_recorded_exact_pytest_gate GZ "$WORKTREE" p3-approval-runtime \
    'packages/gove-zone:P3-APPROVAL-003-escalation-consumption-compatibility' REPO_ROOT 4 \
    "${P3_APPROVAL_GZ_GATE[@]}"
  P3_APPROVAL_ROOT_GATE=(packages/acgs-control-plane/.venv/bin/python -m pytest -q \
    tests/saas_beta/test_cross_plane_contracts.py::test_approval_contract_locks_vote_and_resume_assurance)
  run_recorded_exact_pytest_gate P3 "$WORKTREE" p3-approval-cross-plane \
    'root:P3-APPROVAL-003-cross-plane-contract' REPO_ROOT 1 \
    "${P3_APPROVAL_ROOT_GATE[@]}"
else
  die "unsupported clean-sibling node at product gate: $NODE_ID"
fi

phase B6
TRANSCRIPT_RECORDS="$(/usr/bin/python3 -I -S - "$TRUSTED_TRANSCRIPT" <<'PY'
import pathlib
import sys

print(len(pathlib.Path(sys.argv[1]).read_bytes().splitlines()))
PY
)"
[[ "$TRANSCRIPT_RECORDS" == "$EXPECTED_TRANSCRIPT_RECORDS" ]] ||
  die "reviewed transcript must contain exactly $EXPECTED_TRANSCRIPT_RECORDS records"
R="$(/usr/bin/python3 -I -S - \
  "$WORKTREE" "$P" "$T" "$NODE_ID" "$ASSIGNED_BOOTSTRAPS" \
  "$TRUSTED_TRANSCRIPT" "$TRUSTED_LEDGER_ROOT" "$TRUSTED_RUN_PATH" "$UV_BIN" <<'PY'
import csv
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import re
import secrets
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(sys.argv[1]).resolve(strict=True)
PARENT, TARGET, NODE_ID, ASSIGNMENT = sys.argv[2:6]
TRANSCRIPT = pathlib.Path(sys.argv[6]).resolve(strict=True)
LEDGER_ROOT = pathlib.Path(sys.argv[7]).resolve(strict=True)
RUN_PATH = pathlib.Path(sys.argv[8])
UV_BIN = pathlib.Path(sys.argv[9]).resolve(strict=True)
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
LOCK_ENTRY_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;\\]+)(?:\s*;[^\\]+)?\s*\\?$")
LOCK_HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s*\\)?$")
CODE_PATHS = {
    "EVID": (".venv-evidence/bin/python", "requirements/saas-beta/evidence-test.lock"),
    "CP": ("packages/acgs-control-plane/.venv/bin/python", "requirements/saas-beta/cp-test.lock"),
    "GZ": ("packages/gove-zone/.venv-beta/bin/python", "requirements/saas-beta/gz-test.lock"),
}
DIRECT_MODULES = {
    "EVID": ("rfc8785", "cryptography", "jsonschema", "pytest"),
    "CP": ("editables", "hatchling"),
    "GZ": ("editables", "hatchling"),
}

def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_lock(path: pathlib.Path) -> dict[str, dict[str, object]]:
    distributions: dict[str, dict[str, object]] = {}
    current = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = LOCK_ENTRY_RE.match(line)
        if match:
            name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
            if name in distributions:
                raise SystemExit(f"duplicate lock distribution: {name}")
            current = name
            distributions[name] = {"version": match.group(2), "artifact_hashes": []}
            continue
        hash_match = LOCK_HASH_RE.search(line)
        if hash_match and current is not None:
            distributions[current]["artifact_hashes"].append(hash_match.group(1))  # type: ignore[index]
            continue
    for name, item in distributions.items():
        hashes = item["artifact_hashes"]
        if not isinstance(hashes, list) or not hashes:
            raise SystemExit(f"lock entry lacks hashes: {name}")
    return distributions

def site_packages(runtime: pathlib.Path) -> pathlib.Path:
    candidates = sorted((runtime / "lib").glob("python3.11/site-packages"))
    if len(candidates) != 1:
        raise SystemExit(f"cannot find site-packages for {runtime}")
    return candidates[0].resolve(strict=True)

def dist_name(raw: str) -> str:
    return re.sub(r"[-_.]+", "-", raw).lower()

def installed(runtime: pathlib.Path) -> dict[str, dict[str, str]]:
    site = site_packages(runtime)
    result: dict[str, dict[str, str]] = {}
    for metadata in sorted(site.glob("*.dist-info/METADATA")):
        name = version = None
        for line in metadata.read_text(encoding="utf-8", errors="strict").splitlines():
            if line.startswith("Name: "):
                name = dist_name(line[6:].strip())
            elif line.startswith("Version: "):
                version = line[9:].strip()
            if name and version:
                break
        if not name or not version or name in result:
            raise SystemExit(f"malformed distribution metadata: {metadata}")
        result[name] = {"version": version, "location": str(site)}
    return result

def module_file(runtime: pathlib.Path, module: str) -> pathlib.Path:
    site = site_packages(runtime)
    package = site / module / "__init__.py"
    module_py = site / f"{module}.py"
    if package.is_file():
        return package.resolve(strict=True)
    if module_py.is_file():
        return module_py.resolve(strict=True)
    raise SystemExit(f"module file missing: {module}")

def manifest_version(path: pathlib.Path) -> str:
    manifest = tomllib.loads(path.read_text(encoding="utf-8"))
    project = manifest.get("project", {})
    if isinstance(project.get("version"), str):
        return project["version"]
    hatch = manifest.get("tool", {}).get("hatch", {}).get("version", {})
    rel_path = hatch.get("path")
    pattern = hatch.get("pattern")
    if not isinstance(rel_path, str) or not isinstance(pattern, str):
        raise SystemExit(f"cannot derive manifest version: {path}")
    text = (path.parent / rel_path).read_text(encoding="utf-8")
    match = re.search(pattern, text)
    if match is None:
        raise SystemExit(f"manifest version pattern missed: {path}")
    return match.group("version")

def python_identity(code: str) -> dict[str, object]:
    interp_rel, lock_rel = CODE_PATHS[code]
    interpreter = ROOT / interp_rel
    runtime = interpreter.parents[1].resolve(strict=True)
    lock = (ROOT / lock_rel).resolve(strict=True)
    pyvenv = runtime / "pyvenv.cfg"
    locked = parse_lock(lock)
    dists = installed(runtime)
    pyvenv_text = pyvenv.read_text(encoding="utf-8", errors="strict")
    version_match = re.search(r"version_info\s*=\s*([0-9]+\.[0-9]+\.[0-9]+)", pyvenv_text)
    python_version = version_match.group(1) if version_match else "3.11.0"
    marker_record = {
        "schema_version": "acgs-bootstrap-record/v1",
        "node_id": NODE_ID,
        "code": code,
        "captured_at_utc": utc_now(),
        "runtime_root": str(runtime),
        "interpreter": str(interpreter),
        "interpreter_realpath": str(interpreter.resolve(strict=True)),
        "python_version": python_version,
        "python_implementation": "cpython",
        "runtime_ctime_ns": str(runtime.stat().st_ctime_ns),
        "pyvenv_cfg_sha256": sha(pyvenv),
        "lock_sha256": sha(lock),
        "nonce": secrets.token_hex(32),
    }
    identity: dict[str, object] = {
        "schema_version": "acgs-environment-identity/v1",
        "code": code,
        "node_id": NODE_ID,
        "captured_at_utc": marker_record["captured_at_utc"],
        "interpreter": str(interpreter),
        "interpreter_realpath": str(interpreter.resolve(strict=True)),
        "module_root": str(runtime),
        "python_version": python_version,
        "python_implementation": "cpython",
        "lock": {"path": lock_rel, "sha256": sha(lock), "distributions": locked},
        "installed_distributions": dists,
        "bootstrap_record": marker_record,
        "output_path": str(LEDGER_ROOT / f"environment-{code}.json"),
    }
    if code == "EVID":
        modules = {}
        for module in DIRECT_MODULES[code]:
            distribution = "cryptography" if module == "cryptography" else module
            if distribution not in dists:
                raise SystemExit(f"EVID missing distribution: {distribution}")
            modules[module] = {
                "distribution": distribution,
                "version": dists[distribution]["version"],
                "path": str(module_file(runtime, module)),
            }
        identity["uv"] = {"version": "0.11.19", "executable": str(UV_BIN)}
        identity["modules"] = modules
    else:
        required_editables = {"gove-zone"} if code == "GZ" else {"gove-zone", "acgs-control-plane"}
        expected = set(locked) | required_editables
        if not expected.issubset(set(dists)):
            raise SystemExit(f"{code} installed distribution set missing expected entries")
        editable_py = module_file(runtime, "editables").relative_to(runtime)
        hatchling_py = module_file(runtime, "hatchling").relative_to(runtime)
        identity["pep517_backend"] = {
            "backend": "hatchling.build",
            "distribution": "hatchling",
            "version": locked["hatchling"]["version"],
            "module_path": str(hatchling_py),
            "artifact_hashes": locked["hatchling"]["artifact_hashes"],
        }
        identity["pep660_editable_build"] = {
            "distribution": "editables",
            "version": "0.6",
            "module": "editables",
            "module_path": str(editable_py),
            "lock_sha256": sha(lock),
            "artifact_hashes": locked["editables"]["artifact_hashes"],
        }
        for name in required_editables:
            manifest = ROOT / ("packages/gove-zone/pyproject.toml" if name == "gove-zone" else "packages/acgs-control-plane/pyproject.toml")
            if dists[name]["version"] != manifest_version(manifest):
                raise SystemExit(f"{code} editable distribution version mismatch: {name}")
    (LEDGER_ROOT / f"environment-{code}.json").write_text(
        json.dumps(identity, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    return identity

commands = [
    json.loads(line)
    for line in TRANSCRIPT.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
if not commands:
    raise SystemExit("trusted transcript is empty")
for command in commands:
    if set(command) not in (
        {"argv", "cwd", "exit_code", "stdout_sha256", "stderr_sha256", "started_at_utc", "finished_at_utc", "selectors"},
        {"argv", "cwd", "cwd_scope", "exit_code", "stdout_sha256", "stderr_sha256", "started_at_utc", "finished_at_utc", "selectors"},
    ):
        raise SystemExit("trusted transcript command shape mismatch")
    if command["exit_code"] != 0 or not pathlib.Path(command["cwd"]).is_absolute():
        raise SystemExit("trusted transcript command execution metadata mismatch")
    if not all(SHA_RE.fullmatch(command[name]) for name in ("stdout_sha256", "stderr_sha256")):
        raise SystemExit("trusted transcript digest mismatch")
    if not all(UTC_RE.fullmatch(command[name]) for name in ("started_at_utc", "finished_at_utc")):
        raise SystemExit("trusted transcript timestamp mismatch")

tokens = ASSIGNMENT.split("+")
environment_identities = {code: python_identity(code) for code in tokens if code in CODE_PATHS}
pep660_envs = {}
for code in tokens:
    if code in {"CP", "GZ"}:
        helper = environment_identities[code]["pep660_editable_build"]
        pep660_envs[code] = {
            "module_path": helper["module_path"],
            "product_lock_sha256": helper["lock_sha256"],
            "artifact_hashes": helper["artifact_hashes"],
        }
identity_bundle = {
    "schema_version": "acgs-environment-identities/v1",
    "node_id": NODE_ID,
    "assignment": ASSIGNMENT,
    "environment_identities": environment_identities,
    "pep660_editable_build": {
        "distribution": "editables",
        "version": "0.6",
        "module": "editables",
        "environments": pep660_envs,
    },
    "ed25519_implementation": {
        "distribution": "cryptography",
        "version": environment_identities["EVID"]["installed_distributions"]["cryptography"]["version"],
        "module": "cryptography.hazmat.primitives.asymmetric.ed25519",
        "evidence_test_lock_sha256": environment_identities["EVID"]["lock"]["sha256"],
        "artifact_hashes": environment_identities["EVID"]["lock"]["distributions"]["cryptography"]["artifact_hashes"],
    },
}
identity_path = LEDGER_ROOT / "environment-identities.json"
identity_path.write_text(
    json.dumps(identity_bundle, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
    encoding="utf-8",
)
tree_sha = subprocess.run(
    ["git", "-C", str(ROOT), "rev-parse", f"{TARGET}^{{tree}}"],
    text=True,
    stdout=subprocess.PIPE,
    check=True,
).stdout.strip()
selectors = []
for command in commands:
    for selector in command["selectors"]:
        if selector not in selectors:
            selectors.append(selector)
process_by_node = {
    "P2-IDEMPOTENCY-002": ["single-process-evidence-and-package-gates", "postgres-100-request-multiprocess-agent-registration-idempotency"],
    "P2-VERTICAL-GATE-003": ["single-process-evidence-and-package-gates", "postgres-vertical-bootstrap-register"],
    "P3-POLICY-001": ["single-process-evidence-and-package-gates", "postgres-pg6-policy-registry-lifecycle"],
    "P3-MUTATIONS-002": ["single-process-evidence-and-package-gates", "postgres-pg6-mutation-inventory-drift"],
    "P3-APPROVAL-003": ["single-process-evidence-and-package-gates", "postgres-pg9-approval-resume-multiprocess"],
}
run = {
    "schema_version": "acgs-run-evidence/v1",
    "node_version": 1,
    "node_id": NODE_ID,
    "parent_commit_sha": PARENT,
    "product_commit_sha": TARGET,
    "git_tree_sha": tree_sha,
    "assignment": ASSIGNMENT,
    "environment_identities": environment_identities,
    "pep660_editable_build": identity_bundle["pep660_editable_build"],
    "ed25519_implementation": identity_bundle["ed25519_implementation"],
    "commands": commands,
    "selectors": selectors,
    "determinism": {
        "seed": 20260710,
        "python_hash_seed": "0",
        "process_schedule": process_by_node.get(NODE_ID, ["single-process"]),
    },
    "clock": {"source": "system-utc", "skew_ms": 0},
    "platform": {
        "os": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "container": {
            "kind": "linux-cgroup",
            "identity": sha(pathlib.Path("/proc/1/cgroup")) if pathlib.Path("/proc/1/cgroup").is_file() else "not-detected",
        },
    },
    "artifacts": [
        {"path": str(identity_path), "sha256": sha(identity_path)},
        {"path": str(TRANSCRIPT), "sha256": sha(TRANSCRIPT)},
    ],
    "skipped": [],
    "external": [],
    "timestamps": {
        "generated_at_utc": utc_now(),
        "transcript_started_at_utc": commands[0]["started_at_utc"],
        "transcript_finished_at_utc": commands[-1]["finished_at_utc"],
    },
}
payload = json.dumps(run, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
RUN_PATH.write_text(payload, encoding="utf-8")
canonical = json.dumps(run, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
print(hashlib.sha256(canonical).hexdigest())
PY
)"
[[ "$R" =~ ^[0-9a-f]{64}$ ]] || die 'JCS run hash is malformed'
RUN_JSON_PATH="$TRUSTED_RUN_PATH"
exec {RUN_JSON_FD}<"$RUN_JSON_PATH"
RUN_JSON_FD_IDENTITY="$(stat -Lc '%d:%i:%u:%a' -- "/proc/$$/fd/$RUN_JSON_FD")"
RUN_JSON_FD_SIZE="$(stat -Lc '%s' -- "/proc/$$/fd/$RUN_JSON_FD")"
RUN_JSON_FD_SHA256="$(sha256sum "/proc/$$/fd/$RUN_JSON_FD" | awk '{print $1}')"
[[ "$RUN_JSON_FD_SHA256" =~ ^[0-9a-f]{64}$ ]] || die 'run evidence descriptor hash is malformed'
PROOF_COMPLETE=1
readonly RUN_JSON_FD RUN_JSON_FD_IDENTITY RUN_JSON_FD_SIZE RUN_JSON_FD_SHA256 RUN_JSON_PATH \
  PROOF_COMPLETE TRANSCRIPT_RECORDS R
trap '' INT TERM
cleanup_status=0
op_status=0
detach_status=0
quota_detach_failed=0
quota_cleanup_unsafe=0
if record_worktree_gitfile_pre_detach_witness; then
  op_status=0
else
  op_status=$?
fi
if [[ "$op_status" == 0 ]]; then
  if close_worktree_gitfile_after_witness; then
    op_status=0
  else
    op_status=$?
  fi
fi
if [[ "$op_status" != 0 && "$cleanup_status" == 0 ]]; then
  cleanup_status=$op_status
fi
if clean_sibling_retain_recovery_contracts; then
  op_status=0
else
  op_status=$?
fi
if [[ "$op_status" != 0 && "$cleanup_status" == 0 ]]; then
  cleanup_status=$op_status
fi
if detach_quota_root; then
  detach_status=0
else
  detach_status=$?
fi
if [[ "$detach_status" != 0 ]]; then
  if [[ "$cleanup_status" == 0 ]]; then
    cleanup_status=$detach_status
  fi
  quota_detach_failed=1
fi
if [[ "$quota_detach_failed" == 0 ]]; then
  if quota_bound_artifacts_removed; then
    op_status=0
  else
    op_status=$?
  fi
  if [[ "$op_status" != 0 && "$cleanup_status" == 0 ]]; then
    cleanup_status=$op_status
  fi
  if [[ "$op_status" != 0 && -z "${ACGS_QUOTA_RECOVERY_BUNDLE_NAME:-}" ]]; then
    quota_cleanup_unsafe=1
  fi
fi
if clean_sibling_cleanup 0 "$quota_detach_failed" "$quota_cleanup_unsafe"; then
  op_status=0
else
  op_status=$?
fi
if [[ "$op_status" != 0 && "$cleanup_status" == 0 ]]; then
  cleanup_status=$op_status
fi
if [[ "$op_status" == 0 && "$cleanup_status" == 0 ]]; then
  if quota_gc_committed_parent_recovery_bundle; then
    op_status=0
  else
    op_status=$?
  fi
fi
if [[ "$op_status" != 0 && "$cleanup_status" == 0 ]]; then
  cleanup_status=$op_status
fi
if [[ "$cleanup_status" == 0 ]]; then
  current_parent_entries="$(clean_sibling_snapshot_direct_entries \
    "$TMP_PARENT_FD" "$TMP_PARENT_STAT_BEFORE" "$TMP_PARENT" 2>/dev/null || true)"
  if [[ -z "${TMP_PARENT_ENTRIES_BEFORE:-}" ]] ||
    [[ "$current_parent_entries" != "$TMP_PARENT_ENTRIES_BEFORE" ]]; then
    printf 'caller TMPDIR direct entries changed across proof after recovery GC\n' >&2
    cleanup_status=2
  fi
fi
ACGS_CLEANUP_TRAP_ARMED=0
trap - EXIT
if [[ "$cleanup_status" != 0 ]]; then
  if [[ "$ACGS_OUTPUT_GUARDIAN" == 1 ]]; then
    printf 'CLEAN_SIBLING=FAIL phase=FINAL reason=cleanup-status-%s\n' \
      "$cleanup_status" >&2
    exit 2
  fi
  finalize_clean_sibling_output 0 "cleanup-status-$cleanup_status"
  exit $?
fi
emit_exact_clean_sibling_pass
