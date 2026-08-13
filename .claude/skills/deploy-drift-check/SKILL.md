---
name: deploy-drift-check
description: Use when verifying that live acgs.ai matches what was merged/built, after a deploy, when a merged change "isn't showing up" in production, or when suspecting served-vs-deployed drift, empty-body edge 404s, or console.acgs.ai being down.
---

# Deploy Drift Check — served vs built (read-only)

Probes production without any deploy credentials. Merging to master does NOT deploy here (Workers Assets serve the apex; Pages CI is a shadow) — this script is how you notice.

## Run

```bash
bash .claude/skills/deploy-drift-check/deploy-drift-check.sh              # probe + compare
bash .claude/skills/deploy-drift-check/deploy-drift-check.sh --baseline   # also pin current live state
```

Exit 0 = no warnings; exit 1 = at least one WARN line.

## Interpreting WARNs

- `live != local dist` — only meaningful if `acgi-ai/dist` is a **fresh origin/master build** (check the reported dist age). Rebuild first if stale.
- `live CHANGED since baseline` — expected right after an intentional deploy; re-pin with `--baseline`. Unexpected otherwise.
- `missing asset served as 200 text/html` — SPA fallback misconfig; breaks scanners and agent discovery.
- Actual deploys stay human-gated: `wrangler deploy --name acgs-governance-proxy --assets dist` (never run this from an agent).
