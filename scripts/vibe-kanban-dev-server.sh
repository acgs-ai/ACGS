#!/usr/bin/env bash
# Vibe Kanban dev-server hook for the govern-zone frontend console.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

if [[ ! -f AGENTS.md || ! -f MONOREPO.md || ! -d acgi-ai ]]; then
  echo "ERROR: refusing to run outside the govern-zone repository root: $repo_root" >&2
  exit 2
fi

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: node is required for acgi-ai dev server." >&2
  exit 1
fi

node_major="$(node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || echo 0)"
if (( node_major < 24 )); then
  echo "ERROR: acgi-ai/package.json requires Node >=24 <25; current: $(node --version)." >&2
  echo "Use Node 24 before starting this Vibe dev server." >&2
  exit 1
fi

if ! command -v pnpm >/dev/null 2>&1; then
  echo "ERROR: pnpm is required for acgi-ai dev server." >&2
  exit 1
fi

port="${PORT:-5173}"
echo "Starting govern-zone console dev server for Vibe Kanban."
echo "Vibe preview URL: http://127.0.0.1:${port}"
exec pnpm -F acgi-ai dev -- --host 127.0.0.1 --port "$port" --strictPort
