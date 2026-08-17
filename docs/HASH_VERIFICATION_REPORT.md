# Constitutional-Hash Verification Report

> Phase-3 direct verification. No hashes were changed to produce this report.

## What the mechanism is

The repository pins an inventory of files that carry a
`# Constitutional Hash:` marker in `docs/constitutional-hashes.lock`. A CI job
(`.github/workflows/constitutional-hash.yml`) and the local script
`scripts/verify_constitutional_hashes.py` recompute the inventory and fail on
drift.

## Command output

### Marker scan of the parent tree (submodules not initialized)

```
$ grep -rInE "^# Constitutional Hash:" .  # excluding node_modules/.venv/.git
0
```
Zero exact markers exist in the parent-tracked tree.

### Lock-file inventory

```
$ python3 -c "import json; d=json.load(open('docs/constitutional-hashes.lock'))['hashes']; \
    print('entries', len(d)); print('unique hash values', len(set(d.values())))"
entries 221
unique hash values 1
```
All 221 entries share the single value `608508a9bd224290`, and every path is
under a submodule (`packages/acgs-lite/…`, `packages/Acgs-Swarm/…`,
`packages/clinicalguard/…`, `packages/ACGS-agency-agents/…`).

### Verifier on a submodule-free clone

```
$ python3 scripts/verify_constitutional_hashes.py ; echo $?
FAIL — constitutional-hash drift detected:
  REMOVED (221):
    - packages/acgs-lite/docs/contributing-frameworks.md  (608508a9bd224290)
    - …
    - packages/clinicalguard/tests/test_validate_clinical.py  (608508a9bd224290)
1
```
Exit code **1 (FAIL)**.

## Analysis

- **Markers are per-file, but the hash is global.** 221 pinned files, exactly
  **one** hash value across all of them. This is therefore effectively a
  *single global constitutional hash* (`608508a9bd224290`) stamped identically
  into every governed file, inventoried per-path — not 221 distinct per-file
  content digests. The lock's own `_comment` describes it as a "pinned
  inventory of markers," consistent with this reading.
- **The invariant is entirely submodule-resident.** No parent-tracked file
  carries a marker. Every pinned path lives inside a git submodule. On a clone
  that does not (or cannot) initialize submodules, the verifier reports all 221
  as `REMOVED` and exits non-zero.

## Number summary

| Measure | Value |
|---|---|
| Files that *mention* "Constitutional Hash" (docs/hooks/refs) | 32 |
| Exact `# Constitutional Hash:` markers in parent tree | 0 |
| Marker entries pinned in the lock | 221 |
| Unique hash values across those entries | 1 (`608508a9bd224290`) |
| Entries residing inside submodules | 221 / 221 |
| Verifier exit on submodule-free clone | 1 (FAIL) |

## Pass/fail conclusion

- **With submodules initialized (CI path):** the gate is expected to PASS — CI
  checks out submodules before running the verifier. Not re-runnable here
  without submodule access.
- **On a bare public clone (no submodule init):** the gate **FAILS closed**
  (exit 1). This is correct fail-closed behavior, but it is a documentation and
  reproducibility hazard unless a reviewer is told that submodule
  initialization is a precondition for this specific check. See
  `docs/REPRODUCIBILITY.md`.

## Reviewer clarification

The constitutional hash verification requires the complete source tree,
including required submodule contents. The core governance kernel remains
independently reproducible without optional research references — the
`gove-zone` invariant demos and test suite run on a bare clone with no
submodules (see `docs/REPRODUCIBILITY.md`). A bare-clone FAIL of
`verify_constitutional_hashes.py` reflects absent submodule content, not a
kernel defect or a hash change.

## Recommendation (no hashes changed)

Document — do not alter — the invariant:
1. State in `docs/REPRODUCIBILITY.md` that `verify_constitutional_hashes.py`
   requires initialized submodules and fails closed without them.
2. Consider a verifier flag (e.g. `--allow-missing-submodules`) that reports
   "submodules absent — check skipped" rather than a hard drift FAIL, so a
   reviewer without submodule access is not shown a misleading red. **This is a
   suggestion for the maintainers; it is a behavior change and was not made
   here.**
3. If the intent is genuinely "one constitutional hash for the whole
   constitution," say so explicitly in `docs/SECURITY_MODEL.md` so reviewers do
   not over-read 221 entries as 221 independent integrity proofs.
