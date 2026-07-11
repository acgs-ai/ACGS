# Releasing gove-zone

Agents prepare; humans publish. The publish path is unreachable without a
human-pushed tag AND a human environment approval.

## One-time setup (HUMAN, before first release)

1. PyPI → project `gove-zone` → add a **Trusted Publisher**:
   owner `dislovelhl`, repo `ACGS`, workflow `release-gove-zone.yml`,
   environment `pypi`. (For the very first upload use PyPI's
   "pending publisher" flow — no API token is ever stored in GitHub.)
2. GitHub → Settings → Environments → `pypi` → required reviewers: repo owner.
3. The retired workflow `release.yml` (tag `v*`, environment `production`) was
   the previous, never-used publish lane — if a pending Trusted Publisher or a
   `production` environment was ever registered for it on PyPI/GitHub, delete
   those entries so `release-gove-zone.yml` + `pypi` is the ONLY publish path.

## Per-release checklist

1. Branch. Set `__version__` in `src/gove_zone/__init__.py` (sole source).
2. Move `[Unreleased]` CHANGELOG entries under the new version + date.
   If the API surface changed intentionally, regenerate
   `tests/fixtures/public_api.txt` (header has the command) in the same PR.
3. `bash scripts/release_check.sh` → `release_check: OK`.
4. PR → CI green (including `dist-check`) → merge to master.
5. **HUMAN:** tag the merge commit and push the tag:
   `git tag gove-zone-v<version> && git push origin gove-zone-v<version>`
6. `release-gove-zone.yml` runs: build → release_check → provenance
   attestation → waits on `pypi` environment approval → **HUMAN approves** →
   Trusted-Publishing upload.
7. Post-publish verify (HUMAN or agent, read-only):
   `python -m venv /tmp/v && /tmp/v/bin/pip install gove-zone==<version> && /tmp/v/bin/gove-zone smoke --audit /tmp/a.jsonl`
   → exit 0. Attach output to the release notes.

## Final 1.0.0 only

**HUMAN (in the same release PR):** classifier `4 - Beta` →
`5 - Production/Stable`, and update `test_development_status_is_beta` to pin
the new classifier. Do not flip earlier — claim-safety rule.
