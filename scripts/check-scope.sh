#!/usr/bin/env bash
# scripts/check-scope.sh — H006 scope fence + H007 network/secret/deploy denylist.
# Runs before tournament acceptance and before any internal --no-ff merge.
# Usage:
#   ./scripts/check-scope.sh --base <ref> [--worktree <path>]
# Exits 0 if clean, 1 if violations found, 2 on internal error.
set -euo pipefail

BASE="improve/eval-mvp-hardening"
WORKTREE="$(pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --base) BASE="$2"; shift 2 ;;
    --worktree) WORKTREE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

cd "$WORKTREE"

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "ERR: not a git repo: $WORKTREE" >&2
  exit 2
fi

if ! git rev-parse --verify "$BASE" >/dev/null 2>&1; then
  echo "ERR: base ref not found: $BASE" >&2
  exit 2
fi

CHANGED=$(git diff --name-only "$BASE" 2>/dev/null || true)
if [[ -z "$CHANGED" ]]; then
  echo "OK: no changes vs $BASE"
  exit 0
fi

VIOLATIONS=()

# H006 — scope fence. Allowed paths only.
while IFS= read -r p; do
  [[ -z "$p" ]] && continue
  case "$p" in
    tests/*|governance/*|docs/*) ;;
    .omc/self-improve/topics/eval-mvp-hardening/state/*) ;;
    .omc/self-improve/topics/eval-mvp-hardening/plans/*) ;;
    .omc/self-improve/topics/eval-mvp-hardening/tracking/*) ;;
    *) VIOLATIONS+=("H006 scope: $p") ;;
  esac
done <<< "$CHANGED"

# H007 — denylist on added lines, scoped to source paths only.
ADDED=$(git diff -U0 "$BASE" -- 'tests/**' 'governance/**' 'docs/**' 2>/dev/null \
  | grep -E '^\+[^+]' | sed 's/^.//' || true)

NET_RE='(\bimport[[:space:]]+requests\b|\bimport[[:space:]]+httpx\b|\bimport[[:space:]]+aiohttp\b|\bfrom[[:space:]]+urllib\.request\b|\burlopen\(|\bsocket\.(connect|create_connection)\(|\brequests\.(get|post|put|delete|patch|request|head|options)\(|\bhttpx\.(get|post|put|delete|patch|Client|AsyncClient)\(|\baiohttp\.ClientSession\(|\bsubprocess\.[a-zA-Z_]+\(.*[\x27\x22](curl|wget|nc|netcat)\b)'
DEPLOY_RE='(gh[[:space:]]+pr[[:space:]]+create|git[[:space:]]+push|kubectl|wrangler[[:space:]]|flyctl|vercel[[:space:]]+deploy|docker[[:space:]]+push|aws[[:space:]]+s3[[:space:]]+cp|gcloud[[:space:]]+app[[:space:]]+deploy)'
SECRET_RE='(SECRET_KEY|API_KEY|PRIVATE_KEY|AWS_ACCESS_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|HF_TOKEN|SLACK_TOKEN|STRIPE_SECRET|DATABASE_URL[[:space:]]*=[[:space:]]*[\x27\x22][^\x27\x22]*://[^\x27\x22]*:[^\x27\x22]*@)'

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if echo "$line" | grep -qE "$NET_RE"; then
    VIOLATIONS+=("H007 network: ${line:0:200}")
  fi
  if echo "$line" | grep -qE "$DEPLOY_RE"; then
    VIOLATIONS+=("H007 deploy: ${line:0:200}")
  fi
  if echo "$line" | grep -qE "$SECRET_RE"; then
    VIOLATIONS+=("H007 secret-name: ${line:0:200}")
  fi
done <<< "$ADDED"

if [[ ${#VIOLATIONS[@]} -gt 0 ]]; then
  printf 'SCOPE/HARNESS VIOLATIONS (vs %s):\n' "$BASE" >&2
  printf '  %s\n' "${VIOLATIONS[@]}" >&2
  exit 1
fi

CHANGED_COUNT=$(echo "$CHANGED" | wc -l | tr -d ' ')
echo "OK: scope+denylist check passed ($CHANGED_COUNT changed file(s) vs $BASE)"
exit 0
