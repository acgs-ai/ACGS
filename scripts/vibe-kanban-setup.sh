#!/usr/bin/env bash
# Preflight/setup hook for Vibe Kanban govern-zone workspaces.
# Default mode is intentionally non-mutating. Set VK_GOVERN_ZONE_INSTALL=1
# to allow dependency installation in a freshly-created Vibe worktree.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

if [[ ! -f AGENTS.md || ! -f MONOREPO.md || ! -d packages ]]; then
  echo "ERROR: refusing to run outside the govern-zone repository root: $repo_root" >&2
  exit 2
fi

show_version() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "MISSING $cmd"
    return 1
  fi

  case "$cmd" in
    node|npm|pnpm|uv|python)
      printf '%s ' "$cmd"
      "$cmd" --version 2>/dev/null || true
      ;;
    git)
      git --version
      ;;
    codex)
      codex --version 2>/dev/null || codex -V 2>/dev/null || echo "codex present"
      ;;
    claude)
      claude --version 2>/dev/null || echo "claude present"
      ;;
    *)
      "$cmd" --version 2>/dev/null || echo "$cmd present"
      ;;
  esac
}

missing=0
for cmd in git node npm pnpm uv python; do
  if ! show_version "$cmd"; then
    missing=$((missing + 1))
  fi
done

for optional in codex claude; do
  if ! show_version "$optional"; then
    echo "WARNING: $optional is not available; Vibe agent runs using that executor will fail until it is installed/authenticated." >&2
  fi
done

if (( missing > 0 )); then
  echo "ERROR: missing $missing required core tool(s). Install them before starting governed Vibe workspaces." >&2
  exit 1
fi

echo
echo "== git workspace =="
git status --short --branch | sed -n '1,40p'

echo
echo "== Vibe setup mode =="
if [[ "${VK_GOVERN_ZONE_INSTALL:-0}" != "1" ]]; then
  echo "Preflight-only: dependency installation skipped."
  echo "Set VK_GOVERN_ZONE_INSTALL=1 to run pnpm/uv frozen installs in this worktree."
  exit 0
fi

if [[ -f pnpm-lock.yaml ]]; then
  echo "Running pnpm install --frozen-lockfile"
  pnpm install --frozen-lockfile
else
  echo "Skipping pnpm install: no root pnpm-lock.yaml"
fi

if [[ -f uv.lock ]]; then
  echo "Running uv sync --all-extras --frozen"
  uv sync --all-extras --frozen
else
  echo "Skipping uv sync: no root uv.lock"
fi

echo "Vibe govern-zone setup complete."
