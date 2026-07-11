#!/usr/bin/env bash
# Run an acgi-ai verification command with the repo's exact frontend toolchain.
#
# Default command:
#   pnpm -F acgi-ai run test:all
#
# This gate fails closed unless the reviewed Linux/x86_64 fnm, Node, Corepack,
# and pnpm payloads are available. It copies all executable package-manager
# code into a fresh private runtime before executing the requested command.

set -euo pipefail

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
[[ "$SCRIPT_DIR" != "${BASH_SOURCE[0]}" ]] || SCRIPT_DIR="."
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
ACGI_DIR="$ROOT_DIR/acgi-ai"

REQUIRED_NODE_VERSION="24.18.0"
REQUIRED_COREPACK_VERSION="0.35.0"
REQUIRED_FNM_SHA256="2b8810b610654de6914a17e3235d3948fbd5c7d4712815ac45724c3f06e8966f"
REQUIRED_NODE_SHA256="41a74efb34cbde5c7632cdac0cf8bd1a14d0b8d73dc1e82755014d9a9ce70f5c"
REQUIRED_COREPACK_SHA256="3655bc798f300951f2070fee411b337d626b0c3ae80c2d24c46ccac4595d4bf9"
REQUIRED_PNPM_DISPATCHER_SHA256="7c2a67995976b5b592b611d8b236e3b0633bd654fb49aedd96c6eb7ce04c9cbb"
REQUIRED_COREPACK_TREE_SHA256="6dc22292849f9e176da87530b3c6e7e871b6d153853905472323a30c68e3ef83"
REQUIRED_PNPM_TREE_SHA256="f5024c43f73511fd4405a2af8e5284037c7ce9d740ccbc21b48c82a4372a5e1b"
REQUIRED_PNPM_SELECTOR='pnpm@9.15.4+sha512.b2dc20e2fc72b3e18848459b37359a32064663e5627a51e4c74b2c29dd8e8e0491483c3abb40789cfd578bf362fb6ba8261b05f0387d76792ed6e23ea3b1b6a0'

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ "$(/usr/bin/uname -s)" == Linux && "$(/usr/bin/uname -m)" == x86_64 ]] ||
  fail "the reviewed acgi-ai gate supports Linux/x86_64 only"

# Reject code-injection controls before resolving or executing fnm/Node. The
# final command also receives these variables unset as defense in depth.
for injection_var in \
  NODE_OPTIONS NODE_PATH NODE_REPL_EXTERNAL_MODULE \
  NODE_COMPILE_CACHE NODE_COMPILE_CACHE_PORTABLE; do
  [[ ! -v "$injection_var" ]] ||
    fail "${injection_var} must stay unset; Node injection controls are forbidden"
done

if ! command -v fnm >/dev/null 2>&1; then
  fail "fnm is required for exact Node ${REQUIRED_NODE_VERSION} identity"
fi
FNM_BIN="$(command -v fnm)"
# No caller-controlled directory remains in PATH after fnm has been located.
export PATH="/usr/bin:/bin"
CURRENT_UID="$(/usr/bin/id -u)"

validate_owned_executable() {
  local path="$1" label="$2" canonical mode
  [[ "$path" == /* && -f "$path" && ! -L "$path" && -x "$path" ]] ||
    fail "${label} must be an absolute, regular, non-symlink executable: ${path}"
  canonical="$(/usr/bin/realpath -e -- "$path")"
  [[ "$canonical" == "$path" ]] || fail "${label} must already be canonical: ${path}"
  [[ "$(/usr/bin/stat -c '%u' -- "$path")" == "$CURRENT_UID" ]] ||
    fail "${label} must be owned by the invoking user: ${path}"
  mode="$(/usr/bin/stat -c '%a' -- "$path")"
  (( (8#$mode & 022) == 0 )) || fail "${label} must not be group- or world-writable"
}

validate_sha256() {
  local path="$1" expected="$2" label="$3" actual
  actual="$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || fail "${label} digest is not the reviewed digest"
}

tree_sha256() {
  /usr/bin/python3 -I - "$1" <<'PY'
from pathlib import Path
import hashlib
import sys

root = Path(sys.argv[1])
if not root.is_dir() or root.is_symlink():
    raise SystemExit(2)
digest = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root).as_posix().encode()
    if path.is_symlink():
        kind, payload = b"L", str(path.readlink()).encode()
    elif path.is_file():
        kind = b"F"
        payload = hashlib.sha256(path.read_bytes()).hexdigest().encode()
    elif path.is_dir():
        kind, payload = b"D", b""
    else:
        raise SystemExit(2)
    digest.update(relative + b"\0" + kind + b"\0" + payload + b"\0")
print(digest.hexdigest())
PY
}

validate_tree_sha256() {
  local path="$1" expected="$2" label="$3" actual
  [[ -d "$path" && ! -L "$path" ]] || fail "${label} must be a non-symlink directory"
  actual="$(tree_sha256 "$path")"
  [[ "$actual" == "$expected" ]] || fail "${label} tree digest is not reviewed"
}

# Resolve the immutable fnm installation without executing fnm. This is the
# fail-closed equivalent of `fnm exec --using ...`: a fake PATH fnm cannot run
# before its digest, the derived Node binary, and the full Corepack tree pass.
FNM_BIN="$(/usr/bin/realpath -e -- "$FNM_BIN")"
validate_owned_executable "$FNM_BIN" "fnm"
validate_sha256 "$FNM_BIN" "$REQUIRED_FNM_SHA256" "fnm"
FNM_ROOT="${FNM_BIN%/*}"
NODE_PREFIX="${FNM_ROOT}/node-versions/v${REQUIRED_NODE_VERSION}/installation"
NODE_BIN_DIR="${NODE_PREFIX}/bin"
NODE_BIN="${NODE_BIN_DIR}/node"
SOURCE_COREPACK_ROOT="${NODE_PREFIX}/lib/node_modules/corepack"
SOURCE_COREPACK_ENTRY="${SOURCE_COREPACK_ROOT}/dist/corepack.js"
SOURCE_PNPM_DISPATCHER="${SOURCE_COREPACK_ROOT}/dist/pnpm.js"
SOURCE_COREPACK_SHIM="${NODE_BIN_DIR}/corepack"

validate_owned_executable "$NODE_BIN" "Node ${REQUIRED_NODE_VERSION}"
validate_sha256 "$NODE_BIN" "$REQUIRED_NODE_SHA256" "Node ${REQUIRED_NODE_VERSION}"
[[ -L "$SOURCE_COREPACK_SHIM" ]] || fail "canonical Corepack shim is missing"
[[ "$(/usr/bin/realpath -e -- "$SOURCE_COREPACK_SHIM")" == "$SOURCE_COREPACK_ENTRY" ]] ||
  fail "canonical Corepack shim does not resolve to the reviewed dispatcher"
validate_tree_sha256 \
  "$SOURCE_COREPACK_ROOT" "$REQUIRED_COREPACK_TREE_SHA256" "source Corepack"
validate_owned_executable "$SOURCE_COREPACK_ENTRY" "Corepack dispatcher"
validate_owned_executable "$SOURCE_PNPM_DISPATCHER" "Corepack pnpm dispatcher"
validate_sha256 \
  "$SOURCE_COREPACK_ENTRY" "$REQUIRED_COREPACK_SHA256" "Corepack dispatcher"
validate_sha256 \
  "$SOURCE_PNPM_DISPATCHER" \
  "$REQUIRED_PNPM_DISPATCHER_SHA256" \
  "Corepack pnpm dispatcher"

NODE_VERSION="$(/usr/bin/env \
  -u NODE_OPTIONS -u NODE_PATH -u NODE_REPL_EXTERNAL_MODULE \
  -u NODE_COMPILE_CACHE -u NODE_COMPILE_CACHE_PORTABLE \
  "$NODE_BIN" -p 'process.versions.node')"
[[ "$NODE_VERSION" == "$REQUIRED_NODE_VERSION" ]] ||
  fail "expected Node ${REQUIRED_NODE_VERSION}, got ${NODE_VERSION}"

NODE_VERSION_FILE="$(/usr/bin/tr -d '[:space:]' < "$ACGI_DIR/.node-version")"
[[ "$NODE_VERSION_FILE" == "$REQUIRED_NODE_VERSION" ]] ||
  fail "acgi-ai/.node-version must be exactly ${REQUIRED_NODE_VERSION}"

read_package_manager() {
  /usr/bin/python3 -I - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    package = json.load(handle)
print(package.get("packageManager", ""))
PY
}

ROOT_PNPM_SELECTOR="$(read_package_manager "$ROOT_DIR/package.json")"
ACGI_PNPM_SELECTOR="$(read_package_manager "$ACGI_DIR/package.json")"
[[ "$ROOT_PNPM_SELECTOR" == "$REQUIRED_PNPM_SELECTOR" ]] ||
  fail "root packageManager must be the reviewed integrity-qualified selector"
[[ "$ACGI_PNPM_SELECTOR" == "$REQUIRED_PNPM_SELECTOR" ]] ||
  fail "acgi-ai packageManager must match the reviewed integrity-qualified selector"
EXPECTED_PNPM="${ROOT_PNPM_SELECTOR#pnpm@}"
EXPECTED_PNPM="${EXPECTED_PNPM%%+sha512.*}"
[[ -n "$EXPECTED_PNPM" && "$EXPECTED_PNPM" != "$ROOT_PNPM_SELECTOR" ]] ||
  fail "could not derive pnpm version from the reviewed selector"

cd "$ROOT_DIR"
[[ ! -v COREPACK_INTEGRITY_KEYS ]] ||
  fail "COREPACK_INTEGRITY_KEYS must stay unset; integrity bypasses are forbidden"
unset COREPACK_ROOT
export COREPACK_DEFAULT_TO_LATEST=0
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
export COREPACK_ENABLE_PROJECT_SPEC=1
export COREPACK_ENABLE_STRICT=1
export COREPACK_ENV_FILE=0

LAUNCHER_PARENT="${TMPDIR:-/tmp}"
[[ "$LAUNCHER_PARENT" == /* && -d "$LAUNCHER_PARENT" && ! -L "$LAUNCHER_PARENT" ]] ||
  fail "TMPDIR must be an absolute, non-symlink directory"
LAUNCHER_PARENT_CANONICAL="$(/usr/bin/realpath -e -- "$LAUNCHER_PARENT")"
[[ "${LAUNCHER_PARENT%/}" == "$LAUNCHER_PARENT_CANONICAL" ]] ||
  fail "TMPDIR must already be canonical"
PARENT_OWNER="$(/usr/bin/stat -c '%u' -- "$LAUNCHER_PARENT")"
PARENT_MODE="$(/usr/bin/stat -c '%a' -- "$LAUNCHER_PARENT")"
if [[ "$PARENT_OWNER" == "$CURRENT_UID" && "$PARENT_MODE" == 700 ]]; then
  :
elif [[ "$LAUNCHER_PARENT_CANONICAL" == /tmp && "$PARENT_OWNER" == 0 && \
  "$PARENT_MODE" == 1777 ]]; then
  :
else
  fail "TMPDIR must be caller-owned mode 0700 or root-owned sticky /tmp mode 1777"
fi

RUN_DIR=""
CHILD_PID=""
# shellcheck disable=SC2329 # invoked through EXIT/signal traps
cleanup_runtime() {
  if [[ -n "$RUN_DIR" && -d "$RUN_DIR" && ! -L "$RUN_DIR" ]]; then
    /usr/bin/rm -rf -- "$RUN_DIR"
  fi
  RUN_DIR=""
}
# shellcheck disable=SC2329 # invoked through signal traps
on_signal() {
  local signal="$1"
  trap - HUP INT TERM
  if [[ -n "$CHILD_PID" ]]; then
    /bin/kill -s "$signal" -- "-$CHILD_PID" 2>/dev/null || true
    wait "$CHILD_PID" 2>/dev/null || true
  fi
  CHILD_PID=""
  cleanup_runtime
  trap - EXIT
  /bin/kill -s "$signal" "$$"
}
trap cleanup_runtime EXIT
trap 'on_signal HUP' HUP
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM

umask 077
RUN_DIR="$(/usr/bin/mktemp -d "${LAUNCHER_PARENT_CANONICAL}/acgs-node24-gate.XXXXXXXX")"
[[ -d "$RUN_DIR" && ! -L "$RUN_DIR" ]] || fail "failed to create private runtime"
[[ "$(/usr/bin/stat -c '%u:%a' -- "$RUN_DIR")" == "${CURRENT_UID}:700" ]] ||
  fail "private runtime must be caller-owned mode 0700"

PRIVATE_COREPACK_ROOT="${RUN_DIR}/corepack"
/usr/bin/cp -a -- "$SOURCE_COREPACK_ROOT" "$PRIVATE_COREPACK_ROOT"
validate_tree_sha256 \
  "$PRIVATE_COREPACK_ROOT" "$REQUIRED_COREPACK_TREE_SHA256" "private Corepack"
PRIVATE_COREPACK_ENTRY="${PRIVATE_COREPACK_ROOT}/dist/corepack.js"
PRIVATE_PNPM_DISPATCHER="${PRIVATE_COREPACK_ROOT}/dist/pnpm.js"
validate_sha256 \
  "$PRIVATE_COREPACK_ENTRY" "$REQUIRED_COREPACK_SHA256" "private Corepack dispatcher"
validate_sha256 \
  "$PRIVATE_PNPM_DISPATCHER" \
  "$REQUIRED_PNPM_DISPATCHER_SHA256" \
  "private Corepack pnpm dispatcher"

PRIVATE_COREPACK_HOME="${RUN_DIR}/corepack-home"
/usr/bin/mkdir -m 700 "$PRIVATE_COREPACK_HOME"

validate_private_corepack() {
  validate_tree_sha256 \
    "$PRIVATE_COREPACK_ROOT" "$REQUIRED_COREPACK_TREE_SHA256" "private Corepack"
}
run_corepack() {
  validate_private_corepack
  /usr/bin/env \
    -u COREPACK_ROOT -u NODE_OPTIONS -u NODE_PATH -u NODE_REPL_EXTERNAL_MODULE \
    -u NODE_COMPILE_CACHE -u NODE_COMPILE_CACHE_PORTABLE \
    COREPACK_HOME="$PRIVATE_COREPACK_HOME" \
    PATH="${NODE_BIN_DIR}:/usr/bin:/bin" \
    "$NODE_BIN" "$PRIVATE_COREPACK_ENTRY" "$@"
}

COREPACK_VERSION="$(run_corepack --version)"
[[ "$COREPACK_VERSION" == "$REQUIRED_COREPACK_VERSION" ]] ||
  fail "expected Corepack ${REQUIRED_COREPACK_VERSION}, got ${COREPACK_VERSION}"

HOST_PNPM_ROOT="${HOME:?HOME must be set}/.cache/node/corepack/v1/pnpm/${EXPECTED_PNPM}"
PRIVATE_PNPM_PARENT="${PRIVATE_COREPACK_HOME}/v1/pnpm"
PRIVATE_PNPM_ROOT="${PRIVATE_PNPM_PARENT}/${EXPECTED_PNPM}"
/usr/bin/mkdir -m 700 "${PRIVATE_COREPACK_HOME}/v1"
/usr/bin/mkdir -m 700 "$PRIVATE_PNPM_PARENT"
if [[ -e "$HOST_PNPM_ROOT" || -L "$HOST_PNPM_ROOT" ]]; then
  [[ -d "$HOST_PNPM_ROOT" && ! -L "$HOST_PNPM_ROOT" ]] ||
    fail "persistent pnpm source must be a non-symlink directory"
  [[ "$(/usr/bin/realpath -e -- "$HOST_PNPM_ROOT")" == "$HOST_PNPM_ROOT" ]] ||
    fail "persistent pnpm source must already be canonical"
  validate_tree_sha256 "$HOST_PNPM_ROOT" "$REQUIRED_PNPM_TREE_SHA256" "source pnpm"
  /usr/bin/cp -a -- "$HOST_PNPM_ROOT" "$PRIVATE_PNPM_ROOT"
else
  # Corepack's exact-version download must reproduce the reviewed f502 tree.
  # The manifests separately bind that version to the required SHA-512 selector.
  run_corepack prepare "pnpm@${EXPECTED_PNPM}" --activate
fi
validate_tree_sha256 "$PRIVATE_PNPM_ROOT" "$REQUIRED_PNPM_TREE_SHA256" "private pnpm"

LAUNCHER_DIR="${RUN_DIR}/bin"
/usr/bin/mkdir -m 700 "$LAUNCHER_DIR"
run_corepack enable --install-directory "$LAUNCHER_DIR" pnpm
PNPM_LAUNCHER="${LAUNCHER_DIR}/pnpm"
/usr/bin/rm -f -- "${LAUNCHER_DIR}/pnpx"
EXPECTED_LAUNCHER_TARGET="$(/usr/bin/realpath \
  --relative-to="$LAUNCHER_DIR" -- "$PRIVATE_PNPM_DISPATCHER")"

validate_runtime() {
  local entries launcher_sha
  [[ -d "$RUN_DIR" && ! -L "$RUN_DIR" ]] || fail "private runtime disappeared"
  [[ "$(/usr/bin/stat -c '%u:%a' -- "$RUN_DIR")" == "${CURRENT_UID}:700" ]] ||
    fail "private runtime ownership or mode changed"
  [[ -d "$LAUNCHER_DIR" && ! -L "$LAUNCHER_DIR" ]] || fail "launcher directory changed"
  [[ "$(/usr/bin/stat -c '%u:%a' -- "$LAUNCHER_DIR")" == "${CURRENT_UID}:700" ]] ||
    fail "launcher directory ownership or mode changed"
  shopt -s nullglob dotglob
  entries=("$LAUNCHER_DIR"/*)
  shopt -u nullglob dotglob
  [[ "${#entries[@]}" -eq 1 && "${entries[0]}" == "$PNPM_LAUNCHER" ]] ||
    fail "launcher directory contains an unexpected entry"
  [[ -L "$PNPM_LAUNCHER" ]] || fail "private pnpm launcher is not a symlink"
  [[ "$(/usr/bin/readlink -- "$PNPM_LAUNCHER")" == "$EXPECTED_LAUNCHER_TARGET" ]] ||
    fail "private pnpm launcher lexical target changed"
  [[ "$(/usr/bin/realpath -e -- "$PNPM_LAUNCHER")" == "$PRIVATE_PNPM_DISPATCHER" ]] ||
    fail "private pnpm launcher escaped its dispatcher"
  launcher_sha="$(/usr/bin/sha256sum -- "$PNPM_LAUNCHER" | /usr/bin/awk '{print $1}')"
  [[ "$launcher_sha" == "$REQUIRED_PNPM_DISPATCHER_SHA256" ]] ||
    fail "private pnpm launcher dispatcher changed"
  validate_sha256 "$NODE_BIN" "$REQUIRED_NODE_SHA256" "Node ${REQUIRED_NODE_VERSION}"
  validate_private_corepack
  validate_tree_sha256 "$PRIVATE_PNPM_ROOT" "$REQUIRED_PNPM_TREE_SHA256" "private pnpm"
}

CONTROLLED_PATH="${LAUNCHER_DIR}:${NODE_BIN_DIR}:/usr/bin:/bin"
# This is the hardened equivalent of `corepack pnpm -v`: both the full private
# Corepack tree and the full private pnpm payload are revalidated first.
validate_runtime
PNPM_VERSION="$(/usr/bin/env \
  -u COREPACK_ROOT -u NODE_OPTIONS -u NODE_PATH -u NODE_REPL_EXTERNAL_MODULE \
  -u NODE_COMPILE_CACHE -u NODE_COMPILE_CACHE_PORTABLE \
  COREPACK_HOME="$PRIVATE_COREPACK_HOME" PATH="$CONTROLLED_PATH" \
  "$PNPM_LAUNCHER" -v)"
[[ "$PNPM_VERSION" == "$EXPECTED_PNPM" ]] ||
  fail "expected pnpm ${EXPECTED_PNPM}, got ${PNPM_VERSION}"

echo "acgi-ai Node 24 gate: node=v${NODE_VERSION}, corepack=${COREPACK_VERSION}, pnpm=${PNPM_VERSION}"

if [[ "$#" -eq 0 ]]; then
  set -- pnpm -F acgi-ai run test:all
fi
validate_runtime

ARGV0_BASENAME="${1##*/}"
case "$ARGV0_BASENAME" in
  pnpm)
    shift
    FINAL_COMMAND=(
      /usr/bin/env
      -u COREPACK_ROOT -u NODE_OPTIONS -u NODE_PATH -u NODE_REPL_EXTERNAL_MODULE
      -u NODE_COMPILE_CACHE -u NODE_COMPILE_CACHE_PORTABLE
      COREPACK_HOME="$PRIVATE_COREPACK_HOME" PATH="$CONTROLLED_PATH"
      "$PNPM_LAUNCHER" "$@"
    )
    ;;
  corepack)
    shift
    FINAL_COMMAND=(
      /usr/bin/env
      -u COREPACK_ROOT -u NODE_OPTIONS -u NODE_PATH -u NODE_REPL_EXTERNAL_MODULE
      -u NODE_COMPILE_CACHE -u NODE_COMPILE_CACHE_PORTABLE
      COREPACK_HOME="$PRIVATE_COREPACK_HOME" PATH="${NODE_BIN_DIR}:/usr/bin:/bin"
      "$NODE_BIN" "$PRIVATE_COREPACK_ENTRY" "$@"
    )
    ;;
  *)
    FINAL_COMMAND=(
      /usr/bin/env
      -u COREPACK_ROOT -u NODE_OPTIONS -u NODE_PATH -u NODE_REPL_EXTERNAL_MODULE
      -u NODE_COMPILE_CACHE -u NODE_COMPILE_CACHE_PORTABLE
      COREPACK_HOME="$PRIVATE_COREPACK_HOME" PATH="$CONTROLLED_PATH"
      "$@"
    )
    ;;
esac

# The child owns a new session/process group. Signal handlers forward to the
# negative PGID, wait for the entire command leader, clean private code, and
# re-raise the original signal on this wrapper.
set +e
/usr/bin/setsid --wait "${FINAL_COMMAND[@]}" &
CHILD_PID=$!
wait "$CHILD_PID"
COMMAND_STATUS=$?
CHILD_PID=""
set -e
exit "$COMMAND_STATUS"
