#!/usr/bin/env bash
# Idempotent cleanup hook for Vibe Kanban govern-zone workspaces.
# Removes transient caches only by default. It deliberately preserves
# node_modules, .venv, nested git repos, and source/build outputs unless the
# explicit aggressive mode is requested.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

if [[ ! -f AGENTS.md || ! -f MONOREPO.md || ! -d packages ]]; then
  echo "ERROR: refusing to run outside the govern-zone repository root: $repo_root" >&2
  exit 2
fi

remove_paths=()
while IFS= read -r path; do
  remove_paths+=("$path")
done < <(
  find . \
    \( -path './.git' -o -path './node_modules' -o -path './.venv' -o -path './packages/acgs-lite/.git' -o -path './packages/Acgs-Swarm/.git' \) -prune \
    -o \( -type d \( -name '__pycache__' -o -name '.pytest_cache' -o -name '.ruff_cache' -o -name '.mypy_cache' -o -name '.turbo' -o -name 'htmlcov' \) -print \) \
    -o \( -type f \( -name '.coverage' -o -name '.coverage.*' \) -print \)
)

if (( ${#remove_paths[@]} == 0 )); then
  echo "No transient caches found."
else
  printf 'Removing %d transient cache path(s):\n' "${#remove_paths[@]}"
  printf '  %s\n' "${remove_paths[@]}"
  rm -rf -- "${remove_paths[@]}"
fi

if [[ "${VK_GOVERN_ZONE_AGGRESSIVE_CLEAN:-0}" == "1" ]]; then
  echo
  echo "Aggressive clean enabled: removing known non-source build outputs."
  aggressive_paths=(
    "acgi-ai/dist"
    "acgi-ai/build"
    "packages/gove-zone/dist"
    "packages/gove-zone/build"
    "packages/agent-bus-analyzer/dist"
    "packages/agent-bus-analyzer/build"
    "acgs_governance_eval_mvp/dist"
    "acgs_governance_eval_mvp/build"
    "acgs-cft-governance-pack/dist"
    "acgs-cft-governance-pack/build"
  )
  for path in "${aggressive_paths[@]}"; do
    if [[ -e "$path" ]]; then
      echo "  rm -rf $path"
      rm -rf -- "$path"
    fi
  done
else
  echo "Aggressive clean skipped. Set VK_GOVERN_ZONE_AGGRESSIVE_CLEAN=1 to remove known build outputs."
fi

echo "Vibe govern-zone cleanup complete."
