# Versioning (Phase 2)

## Source of truth

Each package versions **independently** (`pyproject.toml:6-9` policy). There is
no single repo-wide version, and the root workspace is intentionally unversioned.

| Scope | Version source of truth | Value | Notes |
|---|---|---|---|
| **Flagship kernel** | `packages/gove-zone/src/gove_zone/__init__.py` `__version__` (hatch dynamic via `pyproject.toml`) | `1.0.0rc1` (classifier: Beta) | Surfaced by `README.md` badge. Prefers installed metadata; source fallback = `1.0.0rc1`. |
| Root workspace (Python) | `pyproject.toml:14` | `0.0.0` | Non-published virtual workspace — documented (`pyproject.toml:3-5`). |
| Root workspace (JS) | `package.json:3` | `0.0.0`, `private` | Not published — documented. |
| Frontend/console | `acgi-ai/package.json` | `0.0.0`, `private` | Unpublished app; conventional. |
| Published sibling | `packages/acgs-lite` (PyPI) | `v2.10.1` | `requires-python >= 3.10` (intentionally below the 3.11 workspace floor). |
| Proofpack verifier | `packages/acgs-proofpack-verifier/pyproject.toml` | `0.1.0a1` | Independent line. |
| Control plane / bus-analyzer / research-engine / eval-MVP / CFT pack | respective `pyproject.toml` | `0.1.0` | Independent, internally consistent lines. |

**Flagship kernel version = `gove-zone 1.0.0rc1` (Beta).** The root `0.0.0`
sentinels are permanent non-published markers, not a product version.

## Artifact version vs package version

Two version levels exist and must not be conflated:

| Level | What it names | Value | Where it is declared |
|---|---|---|---|
| **ACGS artifact / platform** | The whole repository as an early-stage platform | **`0.1.0` (early / alpha platform)** | No single published root version — the root workspace is a `0.0.0` non-published sentinel by policy. `0.1.0` is the documented maturity line most first-party non-kernel packages share (control-plane, bus-analyzer, research-engine, eval-MVP, CFT pack). |
| **`gove-zone` kernel package** | The flagship enforcement kernel package only | **`1.0.0rc1` (Beta classifier)** | `packages/gove-zone/.../__init__.py` `__version__`; surfaced by the README badge. |

`gove-zone 1.0.0rc1` is the **kernel package** version. It is **not** a claim
that the entire ACGS artifact is at a 1.0 release candidate — the platform as a
whole is early-stage (`0.1.0`). Reviewer surfaces that quote `1.0.0rc1` are
describing the `gove-zone` kernel specifically; the platform maturity is `0.1.0`.
Do not downgrade the `gove-zone` package version to match the artifact line, and
do not promote the artifact line to match the kernel — they are intentionally
different levels.

## Rule set

1. `gove-zone`'s `__version__` is the single source of truth for the kernel; the
   README badge and docs must match it.
2. Root and frontend `0.0.0` are permanent non-published sentinels — leave them.
3. Each other package versions independently; do not synchronize them to the
   kernel line.
4. `acgs-lite` published floor `>= 3.10` and the 3.11 workspace floor are
   **intentionally different** — do not "fix" the divergence.
5. No contradictory versions on reviewer-visible surfaces.
6. `gove-zone 1.0.0rc1` is a **package** version, not the artifact version. The
   ACGS platform maturity line is `0.1.0`. Never present the kernel RC as the
   whole-artifact version.

## Known drift at baseline (reconcile before tag)

This is already self-documented as an open blocker in
`docs/gove-zone-pypi-readiness.md:80-81` and `docs/reconstruction/01-internal-audit.md:64`.

### Drift 1 — gove-zone `1.0.0rc1`/Beta vs stale `0.1.0.dev0` / `0.1.0a1` / Alpha

Canonical surfaces (README, CONTRIBUTING, FAQ, SECURITY_MODEL,
DECISION_RECEIPT_SPEC, HUMAN_GUIDE) say `1.0.0rc1`/Beta. Still-stale surfaces:

- `0.1.0.dev0` / "Alpha": `COMPARISON.md:10,24,77`; `docs/EU_AI_ACT_MAPPING.md:89`;
  `docs/blog/*` (7 files); `docs/launch/STAGE3-landing-thesis.md:4,141`;
  `docs/productization/07-investor-brief.md:10`; `docs/launch/evidence/SUMMARY.md:4`.
- `0.1.0a1`: `docs/performance-report.md:3`; `docs/adr/0009-*.md:33`;
  `ROADMAP-ENFORCEMENT-SUBSTRATE.md:17`; `docs/reconstruction/01-internal-audit.md:64,140`;
  `docs/reconstruction/04-platform-blueprint.md:55,160`.

**Highest-visibility offenders for launch:** `COMPARISON.md`, `docs/blog/*`,
`docs/launch/*`. These are reviewer-facing and should be swept to `1.0.0rc1`/Beta
(or the drafts relocated to `docs/internal/` per Phase 4).

### Drift 2 — acgs-lite `v2.10.1` vs `v2.10.0`

`MONOREPO.md:53` / `CLAUDE.md:11` say **v2.10.1** (correct — matches the recent
`docs-version-pin-fix` PR #349). Stale `v2.10.0` references remain in
`docs/reconstruction/01-internal-audit.md:29`,
`docs/reconstruction/04-platform-blueprint.md:87`,
`docs/reconstruction/00-EXECUTIVE-SUMMARY.md:30`. These `docs/reconstruction/*`
files are Phase-4 relocation candidates, so fixing them and relocating them
resolve together.

### Stray version a `grep` will surface

`docs/archive/acgs-enterprise-ai-manager/frontend/package.json` = `1.0.0` — an
**archived** frontend removed from the pnpm workspace. Harmless but is the only
stray `1.0.0`; it disappears if the archived app is removed (Phase 7).

## Sweep executed on public surfaces

Reconciled to `1.0.0rc1`/beta (matching verified `gove-zone --version` output and
the Beta classifier), with all "not certified" disclaimers left verbatim:
`COMPARISON.md`, `docs/EU_AI_ACT_MAPPING.md`, `docs/adr/0009`,
`docs/performance-report.md`, `ROADMAP-ENFORCEMENT-SUBSTRATE.md`, and the
`ci-deployment-gate` / `launch-demo` / `undeniable-demo` example READMEs. The
acgs-lite `v2.10.0` → `v2.10.1` drift in `docs/reconstruction/*` was also fixed.

**Intentionally left stale:** honest point-in-time provenance (README asciinema
cast "recorded against `0.1.0.dev0`", `plan-level-governance.md` changelog entry)
and internal `docs/strategy/*` / `docs/reconstruction/*` strings that are dated
verified-command transcripts or *meta descriptions of the skew itself* — editing
them would corrupt an honest historical record. These live in internal-classified
docs, not on reviewer-facing product surfaces.
