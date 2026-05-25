#!/usr/bin/env bash
set -euo pipefail

# ACGI TTHW runner.
# Default mode is the clean-runner contract: install dependencies, launch the
# mock dev server, and prove the marketing and console HTTP shells respond
# within ACGI_TTHW_BUDGET_SECONDS. This is an HTTP shell foundation; headless
# browser proof remains external until the Phase 2 Playwright gate lands.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUDGET_SECONDS="${ACGI_TTHW_BUDGET_SECONDS:-300}"
PORT="${ACGI_TTHW_PORT:-5187}"
INSTALL=1
STRICT_NODE=1
HTTP_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-install)
      INSTALL=0
      shift
      ;;
    --allow-node-drift)
      STRICT_NODE=0
      shift
      ;;
    --http-only)
      HTTP_ONLY=1
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

START_SECONDS="$(date +%s)"
LOG_FILE="$(mktemp -t acgi-tthw-vite.XXXXXX.log)"
SERVER_PID=""

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -f "$LOG_FILE"
}
trap cleanup EXIT

elapsed() {
  local now
  now="$(date +%s)"
  echo $((now - START_SECONDS))
}

check_budget() {
  local used
  used="$(elapsed)"
  if (( used > BUDGET_SECONDS )); then
    echo "ACGI TTHW exceeded budget: ${used}s > ${BUDGET_SECONDS}s" >&2
    echo "vite log: $LOG_FILE" >&2
    sed -n '1,160p' "$LOG_FILE" >&2 || true
    exit 1
  fi
}

node_major="$(node -p "process.versions.node.split('.')[0]")"
if [[ "$node_major" != "24" ]]; then
  if (( STRICT_NODE )); then
    echo "ACGI TTHW requires Node 24; current node=$(node -v). Use --allow-node-drift only for local non-CI smoke." >&2
    exit 1
  fi
  echo "warning: ACGI TTHW local smoke running with node=$(node -v); CI/deploy contract is Node 24." >&2
fi

cd "$APP_DIR"

if (( INSTALL )); then
  pnpm install --frozen-lockfile --ignore-workspace
fi

export VITE_BYPASS_SESSION=true
export VITE_USE_MOCKS=true
export CHOKIDAR_USEPOLLING="${CHOKIDAR_USEPOLLING:-1}"
pnpm run dev:mock --host 127.0.0.1 --port "$PORT" --strictPort >"$LOG_FILE" 2>&1 &
SERVER_PID="$!"

fetch_status() {
  node -e "fetch(process.argv[1], { redirect: 'manual' }).then((r) => { console.log(r.status); process.exit(r.ok || (r.status >= 300 && r.status < 400) ? 0 : 1) }).catch((error) => { console.error(error.message); process.exit(1) })" "$1"
}

fetch_text() {
  node -e "fetch(process.argv[1]).then(async (r) => { if (!r.ok) throw new Error('HTTP ' + r.status); process.stdout.write(await r.text()) }).catch((error) => { console.error(error.message); process.exit(1) })" "$1"
}

until fetch_status "http://127.0.0.1:${PORT}/" >/dev/null 2>&1; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "vite dev server exited before readiness" >&2
    sed -n '1,160p' "$LOG_FILE" >&2 || true
    exit 1
  fi
  check_budget
  sleep 1
done

for route in / /console; do
  body="$(fetch_text "http://127.0.0.1:${PORT}${route}")"
  if [[ "$body" != *'<div id="root">'* ]]; then
    echo "route ${route} did not return the Vite root shell" >&2
    exit 1
  fi
  if [[ "$body" == *'Internal server error'* ]]; then
    echo "route ${route} returned an internal server error shell" >&2
    exit 1
  fi
  echo "ACGI TTHW route ok: ${route}"
done

used="$(elapsed)"
check_budget

if (( HTTP_ONLY )); then
  echo "ACGI TTHW HTTP shell foundation passed in ${used}s; headless browser proof remains external."
else
  echo "ACGI TTHW clean-runner HTTP shell foundation passed in ${used}s / ${BUDGET_SECONDS}s."
  echo "headless browser proof remains external until Phase 2 Playwright first-render coverage lands."
fi
