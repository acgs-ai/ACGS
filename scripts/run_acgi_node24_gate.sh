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

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACGI_DIR="$ROOT_DIR/acgi-ai"
REQUIRED_NODE_VERSION="24.18.0"
REQUIRED_COREPACK_VERSION="0.35.0"
REQUIRED_PNPM_SELECTOR='pnpm@9.15.4+sha512.b2dc20e2fc72b3e18848459b37359a32064663e5627a51e4c74b2c29dd8e8e0491483c3abb40789cfd578bf362fb6ba8261b05f0387d76792ed6e23ea3b1b6a0'

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

if ! command -v fnm >/dev/null 2>&1; then
  echo "ERROR: fnm is required to run the exact Node ${REQUIRED_NODE_VERSION} acgi-ai gate on this host." >&2
  echo "Install/use fnm with Node ${REQUIRED_NODE_VERSION}; do not substitute a floating Node 24 release." >&2
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
export COREPACK_HOME="${XDG_CACHE_HOME:-${HOME}/.cache}/acgs/corepack-node-${REQUIRED_NODE_VERSION}"
export COREPACK_DEFAULT_TO_LATEST=0
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
export COREPACK_ENABLE_PROJECT_SPEC=1
export COREPACK_ENABLE_STRICT=1
export COREPACK_ENV_FILE=0

NODE_VERSION="$(fnm exec --using "$REQUIRED_NODE_VERSION" -- node -p "process.versions.node")"
if [[ "$NODE_VERSION" != "$REQUIRED_NODE_VERSION" ]]; then
  echo "ERROR: expected Node ${REQUIRED_NODE_VERSION}, got v${NODE_VERSION}." >&2
  exit 1
fi

COREPACK_VERSION="$(fnm exec --using "$REQUIRED_NODE_VERSION" -- corepack --version)"
if [[ "$COREPACK_VERSION" != "$REQUIRED_COREPACK_VERSION" ]]; then
  echo "ERROR: expected bundled Corepack ${REQUIRED_COREPACK_VERSION}, got ${COREPACK_VERSION}." >&2
  exit 1
fi

# `corepack pnpm` consumes the full integrity-qualified packageManager selector
# from the repository manifest. A bare pnpm executable would prove only the
# version string, not the downloaded package-manager artifact.
PNPM_VERSION="$(fnm exec --using "$REQUIRED_NODE_VERSION" -- corepack pnpm -v)"
if [[ "$PNPM_VERSION" != "$EXPECTED_PNPM" ]]; then
  echo "ERROR: expected pnpm ${EXPECTED_PNPM}, got ${PNPM_VERSION}." >&2
  exit 1
fi

echo "acgi-ai Node 24 gate: node=v${NODE_VERSION}, corepack=${COREPACK_VERSION}, pnpm=${PNPM_VERSION}"

if [[ "$#" -eq 0 ]]; then
  set -- corepack pnpm -F acgi-ai run test:all
elif [[ "$1" == "pnpm" ]]; then
  set -- corepack "$@"
fi

exec fnm exec --using "$REQUIRED_NODE_VERSION" -- "$@"
