#!/usr/bin/env bash
# deploy-drift-check.sh — read-only probe: does production serve what we expect?
# Detects the known ACGS failure modes without touching any deploy credentials:
#   1. served != built   (live asset fingerprint vs local acgi-ai/dist build)
#   2. silent site change (live fingerprint vs recorded baseline)
#   3. SPA-fallback misconfig (missing static asset answered 200 text/html)
#   4. console.acgs.ai DNS absence
#
# Usage:
#   deploy-drift-check.sh              # probe + compare
#   deploy-drift-check.sh --baseline   # additionally record current live state as baseline
set -uo pipefail

SITE="https://acgs.ai"
CONSOLE_HOST="console.acgs.ai"
DIST="${ACGS_DIST:-/home/martin/Documents/ACGS/acgi-ai/dist/index.html}"
BASELINE_DIR="/home/martin/Documents/ACGS/.omc/state"
BASELINE="$BASELINE_DIR/deploy-drift-baseline.txt"
RECORD=0
[ "${1:-}" = "--baseline" ] && RECORD=1

fail=0
note() { printf '%s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; fail=1; }
ok()   { printf 'ok    %s\n' "$*"; }

# --- 1. live fingerprint ------------------------------------------------------
LIVE_HTML=$(curl -sf --max-time 15 "$SITE/" || true)
if [ -z "$LIVE_HTML" ]; then
  warn "$SITE/ unreachable or empty body (empty-body edge 404 is the Workers-shadow signature)"
else
  LIVE_FP=$(printf '%s' "$LIVE_HTML" | grep -oE '/assets/[A-Za-z0-9._-]+\.(js|css)' | sort -u)
  ok "$SITE/ reachable; live assets:"
  printf '%s\n' "$LIVE_FP" | sed 's/^/        /'

  # --- vs local dist (only meaningful if dist is a fresh master build) --------
  if [ -f "$DIST" ]; then
    DIST_FP=$(grep -oE '/assets/[A-Za-z0-9._-]+\.(js|css)' "$DIST" | sort -u)
    DIST_AGE=$(( ( $(date +%s) - $(stat -c %Y "$DIST") ) / 3600 ))
    if [ "$LIVE_FP" = "$DIST_FP" ]; then
      ok "live matches local dist (dist built ${DIST_AGE}h ago)"
    else
      warn "live != local dist (dist built ${DIST_AGE}h ago). If dist is a fresh origin/master build, production has DRIFTED; if dist is stale, rebuild first: cd acgi-ai && pnpm build"
    fi
  else
    note "note  no local dist at $DIST — skip built-vs-served comparison (build with: cd acgi-ai && pnpm build)"
  fi

  # --- vs recorded baseline ----------------------------------------------------
  if [ -f "$BASELINE" ]; then
    if [ "$LIVE_FP" = "$(cat "$BASELINE")" ]; then
      ok "live matches recorded baseline ($BASELINE)"
    else
      warn "live CHANGED since baseline — expected after an intentional deploy (re-run with --baseline); otherwise investigate"
    fi
  else
    note "note  no baseline recorded yet — run with --baseline to pin current live state"
  fi
  if [ "$RECORD" = 1 ]; then
    mkdir -p "$BASELINE_DIR"
    printf '%s\n' "$LIVE_FP" > "$BASELINE"
    ok "baseline recorded → $BASELINE"
  fi
fi

# --- 3. SPA-fallback misconfig: a missing asset must NOT come back as 200 html -
PROBE=$(curl -s -o /dev/null -w '%{http_code} %{content_type}' --max-time 15 "$SITE/assets/__drift_probe_missing__.js" || echo "000")
case "$PROBE" in
  200\ text/html*) warn "missing asset served as 200 text/html — SPA fallback swallowing static 404s (breaks agent-discovery scanners)" ;;
  404*)            ok "missing asset correctly 404s ($PROBE)" ;;
  *)               note "note  missing-asset probe returned: $PROBE" ;;
esac

# --- 4. console DNS -----------------------------------------------------------
if timeout 5 getent hosts "$CONSOLE_HOST" >/dev/null 2>&1; then
  C=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "https://$CONSOLE_HOST/" || echo "000")
  ok "$CONSOLE_HOST resolves; / -> HTTP $C"
else
  warn "$CONSOLE_HOST has no DNS record (known gap — console deploy is separate from marketing)"
fi

exit "$fail"
