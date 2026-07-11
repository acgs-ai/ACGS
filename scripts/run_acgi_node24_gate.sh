#!/usr/bin/env bash
# Run an acgi-ai verification command with the repo's exact frontend toolchain.
#
# Default command:
#   pnpm -F acgi-ai run test:all
#
# The script intentionally uses the existing local version manager when
# available instead of accepting the caller's shell-default Node. That turns the
# Node and pnpm requirements from warning-prone conventions into a reproducible
# local gate before deploy handoff.

set -euo pipefail

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
[[ "$SCRIPT_DIR" != "${BASH_SOURCE[0]}" ]] || SCRIPT_DIR="."
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
ACGI_DIR="$ROOT_DIR/acgi-ai"
REQUIRED_NODE_VERSION="24.18.0"
REQUIRED_COREPACK_VERSION="0.35.0"
REQUIRED_NODE_SHA256="41a74efb34cbde5c7632cdac0cf8bd1a14d0b8d73dc1e82755014d9a9ce70f5c"
REQUIRED_COREPACK_SHA256="3655bc798f300951f2070fee411b337d626b0c3ae80c2d24c46ccac4595d4bf9"
REQUIRED_PNPM_DISPATCHER_SHA256="7c2a67995976b5b592b611d8b236e3b0633bd654fb49aedd96c6eb7ce04c9cbb"
REQUIRED_PNPM_SELECTOR='pnpm@9.15.4+sha512.b2dc20e2fc72b3e18848459b37359a32064663e5627a51e4c74b2c29dd8e8e0491483c3abb40789cfd578bf362fb6ba8261b05f0387d76792ed6e23ea3b1b6a0'

if ! command -v fnm >/dev/null 2>&1; then
  echo "ERROR: fnm is required to run the exact Node ${REQUIRED_NODE_VERSION} acgi-ai gate on this host." >&2
  echo "Install/use fnm with Node ${REQUIRED_NODE_VERSION}; do not substitute a floating Node 24 release." >&2
  exit 1
fi
FNM_BIN="$(command -v fnm)"
# No caller-controlled directory remains in PATH after fnm has been resolved.
# The private pnpm launcher and exact Node directory are added only after they
# have passed their identity and digest checks below.
export PATH="/usr/bin:/bin"

NODE_VERSION_FILE="$(tr -d '[:space:]' < "$ACGI_DIR/.node-version")"
if [[ "$NODE_VERSION_FILE" != "$REQUIRED_NODE_VERSION" ]]; then
  echo "ERROR: acgi-ai/.node-version must be exactly ${REQUIRED_NODE_VERSION}; got ${NODE_VERSION_FILE}." >&2
  exit 1
fi

read_package_manager() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    package = json.load(handle)
print(package.get("packageManager", ""))
PY
}

ROOT_PNPM_SELECTOR="$(read_package_manager "$ROOT_DIR/package.json")"
ACGI_PNPM_SELECTOR="$(read_package_manager "$ACGI_DIR/package.json")"
if [[ "$ROOT_PNPM_SELECTOR" != "$REQUIRED_PNPM_SELECTOR" ]]; then
  echo "ERROR: root packageManager must be the reviewed integrity-qualified selector." >&2
  exit 1
fi
if [[ "$ACGI_PNPM_SELECTOR" != "$REQUIRED_PNPM_SELECTOR" ]]; then
  echo "ERROR: acgi-ai packageManager must match the reviewed integrity-qualified selector." >&2
  exit 1
fi

# Derive the executable version from the already-validated selector so the
# version check cannot drift from its integrity-qualified source of truth.
EXPECTED_PNPM="${ROOT_PNPM_SELECTOR#pnpm@}"
EXPECTED_PNPM="${EXPECTED_PNPM%%+sha512.*}"
if [[ -z "$EXPECTED_PNPM" || "$EXPECTED_PNPM" == "$ROOT_PNPM_SELECTOR" ]]; then
  echo "ERROR: could not derive pnpm version from the reviewed packageManager selector." >&2
  exit 1
fi

# Corepack resolves the nearest package.json from the current working directory.
# Normalize before any identity lookup so a caller cannot select another
# package-manager manifest by invoking this wrapper from elsewhere.
cd "$ROOT_DIR"

if [[ -v COREPACK_INTEGRITY_KEYS ]]; then
  echo "ERROR: COREPACK_INTEGRITY_KEYS must stay unset; integrity bypasses are forbidden." >&2
  exit 1
fi
unset COREPACK_ROOT
export COREPACK_HOME="${XDG_CACHE_HOME:-${HOME}/.cache}/acgs/corepack-node-${REQUIRED_NODE_VERSION}"
export COREPACK_DEFAULT_TO_LATEST=0
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
export COREPACK_ENABLE_PROJECT_SPEC=1
export COREPACK_ENABLE_STRICT=1
export COREPACK_ENV_FILE=0

CURRENT_UID="$(id -u)"

validate_owned_executable() {
  local path="$1"
  local label="$2"
  local canonical mode

  [[ "$path" == /* && -f "$path" && ! -L "$path" && -x "$path" ]] || {
    echo "ERROR: ${label} must be an absolute, regular, non-symlink executable: ${path}." >&2
    exit 1
  }
  canonical="$(realpath -e -- "$path")"
  [[ "$canonical" == "$path" ]] || {
    echo "ERROR: ${label} must already be canonical: ${path}." >&2
    exit 1
  }
  [[ "$(stat -c '%u' -- "$path")" == "$CURRENT_UID" ]] || {
    echo "ERROR: ${label} must be owned by the invoking user: ${path}." >&2
    exit 1
  }
  mode="$(stat -c '%a' -- "$path")"
  if (( (8#$mode & 022) != 0 )); then
    echo "ERROR: ${label} must not be group- or world-writable: ${path}." >&2
    exit 1
  fi
}

validate_sha256() {
  local path="$1"
  local expected="$2"
  local label="$3"
  local actual

  actual="$(sha256sum -- "$path" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || {
    echo "ERROR: ${label} digest is not the reviewed digest." >&2
    exit 1
  }
}

FNM_BIN="$(realpath -e -- "$FNM_BIN")"
validate_owned_executable "$FNM_BIN" "fnm"

# Resolve the selected Node executable through fnm once (the hardened form of
# `fnm exec --using ...`), then bind every
# Corepack and pnpm invocation to that canonical executable.  Keeping the
# selected installation path out of the caller's PATH prevents an ambient pnpm
# from reappearing inside a nested `pnpm run` lifecycle.
NODE_BIN="$({ "$FNM_BIN" exec --using "$REQUIRED_NODE_VERSION" -- node -p 'process.execPath'; } 2>/dev/null)"
NODE_BIN="$(realpath -e -- "$NODE_BIN")"
validate_owned_executable "$NODE_BIN" "Node ${REQUIRED_NODE_VERSION}"
validate_sha256 "$NODE_BIN" "$REQUIRED_NODE_SHA256" "Node ${REQUIRED_NODE_VERSION}"
NODE_BIN_DIR="${NODE_BIN%/*}"
NODE_PREFIX="${NODE_BIN_DIR%/bin}"

COREPACK_SHIM="${NODE_BIN_DIR}/corepack"
COREPACK_ENTRY="${NODE_PREFIX}/lib/node_modules/corepack/dist/corepack.js"
COREPACK_PNPM_ENTRY="${NODE_PREFIX}/lib/node_modules/corepack/dist/pnpm.js"
[[ -L "$COREPACK_SHIM" ]] || {
  echo "ERROR: canonical Node ${REQUIRED_NODE_VERSION} Corepack shim is missing." >&2
  exit 1
}
[[ "$(realpath -e -- "$COREPACK_SHIM")" == "$COREPACK_ENTRY" ]] || {
  echo "ERROR: canonical Corepack shim does not resolve to the reviewed dispatcher." >&2
  exit 1
}
validate_owned_executable "$COREPACK_ENTRY" "Corepack dispatcher"
validate_owned_executable "$COREPACK_PNPM_ENTRY" "Corepack pnpm dispatcher"
validate_sha256 "$COREPACK_ENTRY" "$REQUIRED_COREPACK_SHA256" "Corepack dispatcher"
validate_sha256 \
  "$COREPACK_PNPM_ENTRY" \
  "$REQUIRED_PNPM_DISPATCHER_SHA256" \
  "Corepack pnpm dispatcher"

run_corepack() {
  env -u COREPACK_ROOT \
    PATH="${NODE_BIN_DIR}:/usr/bin:/bin" \
    "$NODE_BIN" "$COREPACK_ENTRY" "$@"
}

NODE_VERSION="$("$NODE_BIN" -p "process.versions.node")"
if [[ "$NODE_VERSION" != "$REQUIRED_NODE_VERSION" ]]; then
  echo "ERROR: expected Node ${REQUIRED_NODE_VERSION}, got v${NODE_VERSION}." >&2
  exit 1
fi

COREPACK_VERSION="$(run_corepack --version)"
if [[ "$COREPACK_VERSION" != "$REQUIRED_COREPACK_VERSION" ]]; then
  echo "ERROR: expected bundled Corepack ${REQUIRED_COREPACK_VERSION}, got ${COREPACK_VERSION}." >&2
  exit 1
fi

# Create a private, ephemeral Corepack launcher rather than using either the
# host's pnpm or `corepack enable` against the Node installation.  Corepack's
# generated relative symlink is accepted only when its lexical and resolved
# targets both bind to this Node 24 installation's exact pnpm dispatcher.
LAUNCHER_DIR=""
cleanup_launcher() {
  if [[ -n "$LAUNCHER_DIR" && -d "$LAUNCHER_DIR" && ! -L "$LAUNCHER_DIR" ]]; then
    rm -rf -- "$LAUNCHER_DIR"
  fi
  LAUNCHER_DIR=""
}
on_signal() {
  local signal="$1"
  trap - HUP INT TERM
  cleanup_launcher
  kill -s "$signal" "$$"
}
trap cleanup_launcher EXIT
trap 'on_signal HUP' HUP
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM

LAUNCHER_PARENT="${TMPDIR:-/tmp}"
[[ -d "$LAUNCHER_PARENT" ]] || {
  echo "ERROR: launcher parent does not exist: ${LAUNCHER_PARENT}." >&2
  exit 1
}
umask 077
LAUNCHER_DIR="$(mktemp -d "${LAUNCHER_PARENT%/}/acgs-node24-gate.XXXXXXXX")"
[[ -d "$LAUNCHER_DIR" && ! -L "$LAUNCHER_DIR" ]] || {
  echo "ERROR: failed to create a private launcher directory." >&2
  exit 1
}
[[ "$(stat -c '%u:%a' -- "$LAUNCHER_DIR")" == "${CURRENT_UID}:700" ]] || {
  echo "ERROR: private launcher directory must be caller-owned mode 0700." >&2
  exit 1
}

run_corepack enable --install-directory "$LAUNCHER_DIR" pnpm
PNPM_LAUNCHER="${LAUNCHER_DIR}/pnpm"
# `corepack enable ... pnpm` also emits pnpx. It is not part of this gate's
# command surface, so remove it before sealing and validating the directory.
rm -f -- "${LAUNCHER_DIR}/pnpx"

EXPECTED_LAUNCHER_TARGET="$(realpath --relative-to="$LAUNCHER_DIR" -- "$COREPACK_PNPM_ENTRY")"
[[ -L "$PNPM_LAUNCHER" ]] || {
  echo "ERROR: Corepack did not create the expected private pnpm launcher." >&2
  exit 1
}
[[ "$(readlink -- "$PNPM_LAUNCHER")" == "$EXPECTED_LAUNCHER_TARGET" ]] || {
  echo "ERROR: private pnpm launcher has an unexpected lexical target." >&2
  exit 1
}
[[ "$(realpath -e -- "$PNPM_LAUNCHER")" == "$COREPACK_PNPM_ENTRY" ]] || {
  echo "ERROR: private pnpm launcher escaped the canonical Corepack dispatcher." >&2
  exit 1
}
[[ "$(stat -c '%u:%a' -- "$LAUNCHER_DIR")" == "${CURRENT_UID}:700" ]] || {
  echo "ERROR: private launcher directory ownership or mode changed." >&2
  exit 1
}
[[ "$(stat -c '%u' -- "$PNPM_LAUNCHER")" == "$CURRENT_UID" ]] || {
  echo "ERROR: private pnpm launcher must be caller-owned." >&2
  exit 1
}

validate_pnpm_launcher() {
  local entries launcher_sha
  shopt -s nullglob dotglob
  entries=("$LAUNCHER_DIR"/*)
  shopt -u nullglob dotglob
  [[ "${#entries[@]}" -eq 1 && "${entries[0]}" == "$PNPM_LAUNCHER" ]] || {
    echo "ERROR: private launcher directory contains an unexpected entry." >&2
    exit 1
  }
  [[ -d "$LAUNCHER_DIR" && ! -L "$LAUNCHER_DIR" ]] || exit 1
  [[ "$(stat -c '%u:%a' -- "$LAUNCHER_DIR")" == "${CURRENT_UID}:700" ]] || exit 1
  [[ -L "$PNPM_LAUNCHER" ]] || exit 1
  [[ "$(readlink -- "$PNPM_LAUNCHER")" == "$EXPECTED_LAUNCHER_TARGET" ]] || exit 1
  [[ "$(realpath -e -- "$PNPM_LAUNCHER")" == "$COREPACK_PNPM_ENTRY" ]] || exit 1
  [[ -f "$COREPACK_PNPM_ENTRY" && ! -L "$COREPACK_PNPM_ENTRY" ]] || exit 1
  launcher_sha="$(sha256sum -- "$PNPM_LAUNCHER" | awk '{print $1}')"
  [[ "$launcher_sha" == "$REQUIRED_PNPM_DISPATCHER_SHA256" ]] || {
    echo "ERROR: private pnpm launcher dispatcher changed after creation." >&2
    exit 1
  }
  validate_sha256 "$NODE_BIN" "$REQUIRED_NODE_SHA256" "Node ${REQUIRED_NODE_VERSION}"
}

CONTROLLED_PATH="${LAUNCHER_DIR}:${NODE_BIN_DIR}:/usr/bin:/bin"
# This private-dispatcher check is the hardened equivalent of `corepack pnpm -v`:
# it consumes the same reviewed packageManager selector without exposing an
# ambient pnpm to nested lifecycle commands.
validate_pnpm_launcher
PNPM_VERSION="$(env -u COREPACK_ROOT PATH="$CONTROLLED_PATH" "$PNPM_LAUNCHER" -v)"
if [[ "$PNPM_VERSION" != "$EXPECTED_PNPM" ]]; then
  echo "ERROR: expected pnpm ${EXPECTED_PNPM}, got ${PNPM_VERSION}." >&2
  exit 1
fi

echo "acgi-ai Node 24 gate: node=v${NODE_VERSION}, corepack=${COREPACK_VERSION}, pnpm=${PNPM_VERSION}"

if [[ "$#" -eq 0 ]]; then
  set -- pnpm -F acgi-ai run test:all
fi

validate_pnpm_launcher
if [[ "$1" == "pnpm" ]]; then
  shift
  env -u COREPACK_ROOT PATH="$CONTROLLED_PATH" "$PNPM_LAUNCHER" "$@"
elif [[ "$1" == "corepack" ]]; then
  shift
  run_corepack "$@"
else
  env -u COREPACK_ROOT PATH="$CONTROLLED_PATH" "$@"
fi
