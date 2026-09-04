# Site copy deck — external follow-ups (record only)

Date: 2026-09-01
Status: no action taken this pass. Tracks work outside `docs/SITE-COPY-DECK-0.md`.

## Off-origin trust leaks (external edits)

| Item | Location | Problem | Owner action |
|---|---|---|---|
| Zenodo title | https://doi.org/10.5281/zenodo.16416793 | "Production-Ready" + >1,250 RPS + P99 3.2 ms + 99.99% uptime + 847 tests | Relabel or add disclaimer on Zenodo record (external service) |
| governance-mcp README | https://github.com/dislovelhl/governance-mcp | 6,471 RPS; 18,582 tests; 18 frameworks (unverified this session — fetch timed out) | Remove or link public harness + hardware + raw JSON before any acgs.ai republish |

## Nested-repo README fixes (separate PRs)

| Item | Repo | Problem |
|---|---|---|
| Stale gove-zone publish claim | https://github.com/acgs-ai/acgs-lite/blob/main/README.md | Published README still says gove-zone "not yet published to PyPI" (PyPI has 1.0.0rc2 since 2026-08-23) |
| Dead docs links | https://github.com/acgs-ai/acgs-lite/blob/main/README.md | Badges and docs table link to https://acgs.ai/docs/* (404) |
| Commercial licenses footer | https://github.com/acgs-ai/acgs-lite/blob/main/README.md | Links commercial licenses to acgs.ai (no commercial page on origin) |
| Broken website sentence | https://github.com/acgs-ai/gove-zone/blob/main/README.md | README: "The project website is." (truncated) |
| Private-repo wording | https://github.com/acgs-ai/gove-zone/blob/main/README.md | README: "while this repository remains private" (repo is public) |

## Deck §8 assets still needed

| Asset | Status |
|---|---|
| `/evidence` HTML page on acgs.ai | needs creation |
| `status.json` (component pins for Status page) | needs creation |
| Public docs site at `/docs` | needs creation |
| Public benchmark harness + hardware + raw JSON | needs creation |
| `framework-inventory.json` (five domains, certified: no) | needs creation; seed from governance-framework.txt |
| C6 download counts | re-fetch from pypistats/pepy at publish time (PyPI JSON does not expose counts) |

## Embed-slices (completed this pass)

| Item | Location | SHA |
|---|---|---|
| Five-tool stub demo | `/home/martin/Documents/gove-zone` branch `feat/embed-l2c-slices` | `e74e32ddf1e6685118d279d8bb2727760f251f6e` (parent `31e989ca`) |
| Recipe skeleton | `EMBED-SLICES-0.md` | same commit |
| Demo command | `uv run python examples/l2c-embed-slices/demo.py` | exit 0 verified |

Not pushed. Not merged.

## Hook fix (Cursor compatibility)

Applied to `~/.claude/hooks/acgs-worktree-hook-dispatch.py` (outside this repo). Not origin copy. Do not typeset.

- Event name aliases (`preToolUse` → `PreToolUse`)
- Tool name aliases (`Shell` → `Bash`)
- cwd / CLAUDE_PROJECT_DIR fallbacks for Cursor

Separate commit/PR if this should live in a shared hooks repo.
