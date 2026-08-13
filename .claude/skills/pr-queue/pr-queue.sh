#!/usr/bin/env bash
# pr-queue.sh — read-only merge-readiness sweep of open PRs.
# Reports CI rollup, mergeability, review state per PR, plus the
# verify-pass marker status for the current worktree (the marker that
# gates `gh pr merge` via blocked-op-escalation-guard.mjs).
#
# Usage: pr-queue.sh [--repo owner/name] [--base master]
# Never writes, merges, or comments. Safe to run any time.
set -euo pipefail

REPO="dislovelhl/ACGS"
BASE="master"
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --base) BASE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

gh pr list --repo "$REPO" --base "$BASE" --state open --limit 50 \
  --json number,title,headRefName,isDraft,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup,updatedAt \
  | python3 -c '
import json, sys
from datetime import datetime, timezone

prs = json.load(sys.stdin)
if not prs:
    print("No open PRs.")
    sys.exit(0)

def ci(rollup):
    if not rollup:
        return "no checks"
    ok = bad = pend = 0
    for c in rollup:
        s = (c.get("conclusion") or c.get("state") or "").upper()
        if s in ("SUCCESS", "NEUTRAL", "SKIPPED"):
            ok += 1
        elif s in ("FAILURE", "ERROR", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED"):
            bad += 1
        else:
            pend += 1
    parts = []
    if ok:   parts.append(f"{ok} pass")
    if bad:  parts.append(f"{bad} FAIL")
    if pend: parts.append(f"{pend} pending")
    return ", ".join(parts)

def age(iso):
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    d = (datetime.now(timezone.utc) - dt).days
    return f"{d}d" if d else "<1d"

rows = []
for p in sorted(prs, key=lambda p: p["number"]):
    verdict_bits = []
    cis = ci(p["statusCheckRollup"])
    if p["isDraft"]:
        verdict_bits.append("DRAFT")
    if "FAIL" in cis:
        verdict_bits.append("CI-RED")
    elif "pending" in cis:
        verdict_bits.append("CI-PENDING")
    elif cis == "no checks":
        # No CI evidence at all is NOT green — never call such a PR ready.
        verdict_bits.append("NO-CHECKS")
    if p["mergeable"] == "CONFLICTING":
        verdict_bits.append("CONFLICTS")
    if (p.get("reviewDecision") or "") == "CHANGES_REQUESTED":
        verdict_bits.append("CHANGES-REQ")
    verdict = " ".join(verdict_bits) if verdict_bits else "READY-FOR-HUMAN-MERGE"
    num = p["number"]
    rows.append((f"#{num}", p["headRefName"][:40], cis,
                 p["mergeStateStatus"], age(p["updatedAt"]), verdict,
                 p["title"][:60]))

w = [max(len(r[i]) for r in rows + [("PR","BRANCH","CI","STATE","AGE","VERDICT","TITLE")]) for i in range(7)]
hdr = ("PR","BRANCH","CI","STATE","AGE","VERDICT","TITLE")
for r in [hdr] + rows:
    print("  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)))
'

# --- verify-pass marker for the current worktree (merge gate input) ----------
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  GITDIR="$(git rev-parse --absolute-git-dir)"
  MARKER="$GITDIR/verify-pass.json"
  HEAD_SHA="$(git rev-parse HEAD)"
  echo
  if [ -f "$MARKER" ]; then
    M_SHA=$(python3 -c "import json;print(json.load(open('$MARKER'))['sha'])" 2>/dev/null || echo "?")
    if [ "$M_SHA" = "$HEAD_SHA" ]; then
      echo "verify-marker: FRESH for HEAD ${HEAD_SHA:0:12} — gh pr merge permitted on this branch."
    else
      echo "verify-marker: STALE (marker ${M_SHA:0:12} != HEAD ${HEAD_SHA:0:12}) — re-run record-verify-pass.sh before merging."
    fi
  else
    echo "verify-marker: NONE for this worktree — run ~/.claude/scripts/record-verify-pass.sh to enable merge."
  fi
fi
