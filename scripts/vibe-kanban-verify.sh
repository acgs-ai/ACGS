#!/usr/bin/env bash
# Bounded verification helper for Vibe Kanban govern-zone workspaces.
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

if [[ ! -f AGENTS.md || ! -f MONOREPO.md || ! -d packages ]]; then
  echo "ERROR: refusing to run outside the govern-zone repository root: $repo_root" >&2
  exit 2
fi

node_major() {
  node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || echo 0
}

run_quick() {
  echo "== quick: constitutional hash drift =="
  python scripts/verify_constitutional_hashes.py --ignore-missing-prefix packages/clinicalguard/

  echo "== quick: shell syntax =="
  bash -n scripts/vibe-kanban-setup.sh
  bash -n scripts/vibe-kanban-cleanup.sh
  bash -n scripts/vibe-kanban-dev-server.sh
  bash -n scripts/vibe-kanban-verify.sh

  echo "== quick: Vibe profile JSON =="
  python -m json.tool docs/vibe-kanban-profiles.example.json >/dev/null
}

run_conductor() {
  echo "== conductor =="
  if [[ ! -d acgs_conductor_integration_starter ]]; then
    echo "SKIP: acgs_conductor_integration_starter/ is not present in this checkout."
    return 0
  fi
  (cd acgs_conductor_integration_starter && python -m pytest tests --import-mode=importlib)
}

run_frontend() {
  echo "== frontend =="
  if ! command -v node >/dev/null 2>&1; then
    echo "ERROR: node is required for frontend verification." >&2
    return 1
  fi
  local major
  major="$(node_major)"
  if (( major < 24 )); then
    echo "ERROR: acgi-ai/package.json requires Node >=24 <25; current: $(node --version)." >&2
    return 1
  fi
  pnpm -F acgi-ai lint
  pnpm -F acgi-ai build
}

run_full() {
  echo "== full: make verify =="
  make verify
}

scope="${VK_GOVERN_ZONE_VERIFY_SCOPE:-quick}"
case "$scope" in
  quick)
    run_quick
    ;;
  conductor)
    run_conductor
    ;;
  frontend)
    run_frontend
    ;;
  full)
    run_full
    ;;
  all)
    run_quick
    run_conductor
    run_frontend
    run_full
    ;;
  *)
    echo "ERROR: unknown VK_GOVERN_ZONE_VERIFY_SCOPE=$scope" >&2
    echo "Expected one of: quick, conductor, frontend, full, all" >&2
    exit 2
    ;;
esac

echo "Vibe govern-zone verification complete for scope: $scope"
