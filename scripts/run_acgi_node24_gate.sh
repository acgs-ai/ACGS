#!/usr/bin/env bash
# Run an acgi-ai verification command with the repo's exact Node 24 toolchain.
#
# Default command:
#   pnpm -F acgi-ai run test:all
#
# The script intentionally uses the existing local version manager when
# available instead of accepting the caller's shell-default Node. That turns the
# Node 24 requirement from a warning-prone convention into a reproducible local
# gate before deploy handoff.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACGI_DIR="$ROOT_DIR/acgi-ai"
REQUIRED_NODE_MAJOR="$(tr -d '[:space:]' < "$ACGI_DIR/.node-version")"

if ! command -v fnm >/dev/null 2>&1; then
  echo "ERROR: fnm is required to run the exact Node ${REQUIRED_NODE_MAJOR} acgi-ai gate on this host." >&2
  echo "Install/use fnm or run the equivalent command in a Node ${REQUIRED_NODE_MAJOR}.x environment." >&2
  exit 1
fi

eval "$(fnm env --use-on-cd)"
cd "$ACGI_DIR"
fnm use "$REQUIRED_NODE_MAJOR"

NODE_VERSION="$(node -p "process.versions.node")"
NODE_MAJOR="${NODE_VERSION%%.*}"
if [[ "$NODE_MAJOR" != "$REQUIRED_NODE_MAJOR" ]]; then
  echo "ERROR: expected Node ${REQUIRED_NODE_MAJOR}.x, got v${NODE_VERSION}." >&2
  exit 1
fi

PNPM_VERSION="$(pnpm -v)"
EXPECTED_PNPM="$(node -e "const pkg = require('./package.json'); console.log(pkg.packageManager.split('@').at(-1))")"
if [[ "$PNPM_VERSION" != "$EXPECTED_PNPM" ]]; then
  echo "ERROR: expected pnpm ${EXPECTED_PNPM}, got ${PNPM_VERSION}." >&2
  exit 1
fi

cd "$ROOT_DIR"
echo "acgi-ai Node 24 gate: node=v${NODE_VERSION}, pnpm=${PNPM_VERSION}"

if [[ "$#" -eq 0 ]]; then
  set -- pnpm -F acgi-ai run test:all
fi

exec "$@"
