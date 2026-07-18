# `gove-zone` — PyPI release readiness

**Scope:** only the Python distribution in `packages/gove-zone/`.
This is not a release report for the ACGS monorepo or `acgs-lite`.

**Last reviewed:** 2026-07-17 against the then-current `master`.
Refresh this document on the exact commit proposed for release.

This is an evidence-oriented checklist, not proof that PyPI publication,
GitHub environment protection, a Trusted Publisher, or a production deployment
exists. External state must be verified immediately before release.

## Verdict

**Do not publish the current source merely by pushing a tag.** The package is
release-candidate-shaped, but release authority, changelog completeness,
workflow enforcement, private-repository constraints, and the public source
link posture are not yet evidenced as complete.

| Area | Current repository evidence | Readiness |
|---|---|---|
| Source version | `src/gove_zone/__init__.py` reports `1.0.0rc1` | Candidate only |
| Version model | Hatch dynamic version; source literal is canonical | Ready |
| Maturity metadata | `Development Status :: 4 - Beta` | Coherent with RC; not production proof |
| Python floor | `>=3.11`; classifiers include 3.11 and 3.12 | Ready |
| Build | Hatchling builds wheel and sdist | Ready for re-verification |
| Runtime dependencies | Zero hard dependencies; optional extras are declared | Ready for re-verification |
| Distribution gate | `scripts/release_check.sh` builds, checks metadata, inspects the wheel, installs it in a clean venv, and runs smoke | Useful but incomplete |
| Release workflow | Tag/version guard, build, GitHub provenance job, `pypi` environment, Trusted-Publishing upload | Present; enforcement and private-repo compatibility unverified |
| Changelog | `1.0.0rc1` entry predates later package changes; the inventory remains incomplete | **Blocker: reconcile** |
| Current README status | Root and package READMEs are aligned in this docs change; broader current-doc inventory remains | Partial |
| Public API contract | Snapshot test exists; later public-surface changes require inventory and explicit SemVer classification | **Blocker: reconcile** |
| Public source links | Repository is private while metadata exposes Repository and Issues URLs | **Product/release decision required** |
| PyPI project and publication state | Not independently verified during this review | **Human verification required** |
| Stable `1.0.0` | No independent operational-maturity sign-off is evidenced | Not ready |

## Current canonical metadata

| Field | Value | Source |
|---|---|---|
| Distribution | `gove-zone` | `pyproject.toml` |
| Import package | `gove_zone` | wheel target / source tree |
| Current source version | `1.0.0rc1` | `src/gove_zone/__init__.py` |
| Version extraction | Dynamic Hatch version | `[tool.hatch.version]` |
| Python | `>=3.11` | `project.requires-python` |
| Classifier | Beta | `project.classifiers` |
| Wheel packages | `gove_zone`, `mcp_gateway` | Hatch wheel target |
| Console scripts | `gove-zone`, `gove-zone-api`, `acgs` | `project.scripts` |
| License | Apache-2.0 | package metadata and shipped license |
| Publish workflow | `release-gove-zone.yml` | `.github/workflows/` |
| Tag pattern | `gove-zone-v*` | release workflow |

The current source version is not the same as a verified GitHub Release or a
verified PyPI distribution. State each separately in public material.

## Release blockers

### 1. Reconcile the candidate history

The `1.0.0rc1` preparation and changelog entry predate later merged package
changes, including public API additions. Before tagging:

- inventory package changes since the RC preparation commit;
- decide whether the next candidate remains `1.0.0rc1` or becomes a higher
  candidate version;
- populate `[Unreleased]` or rebuild the candidate entry accurately;
- reconcile `CHANGELOG.md`, `docs/API_STABILITY.md`, the public API fixture,
  console-script coverage, and both shipped wheel packages; and
- run the full package and documentation gates on the exact candidate SHA.

### 2. Synchronize current user-facing status

The source and metadata say `1.0.0rc1` / Beta. Before this review, the root
and package READMEs and multiple current docs still said `0.1.0a1` / Alpha.
This documentation change aligns the two READMEs; complete the remaining
current-doc inventory without rewriting historical evidence. Add a consistency
test that derives the version, Python floor, classifier, and entry points from
canonical metadata and rejects stale current-document values.

### 3. Prove the external publication controls

The workflow file cannot prove its GitHub or PyPI settings. A release manager
must verify and record:

- the repository plan and visibility support the intended `pypi` required
  reviewer rule;
- the rule is active, cannot be bypassed, and follows the intended self-review
  policy;
- a `gove-zone-v*` tag ruleset restricts tag creation, update, and deletion;
- the PyPI Trusted Publisher matches the exact owner, repository, workflow, and
  environment; and
- no retired publisher, stored upload token, or competing workflow remains.

Required-reviewer availability is plan- and visibility-dependent. The
repository is private at the time of this review, so this must be treated as a
blocking capability check, not assumed from YAML.

### 4. Harden the tag-to-artifact chain

The current workflow verifies tag text against package version, but it does not
enforce that the tagged commit is the approved `master` candidate or rerun the
full required test suite. Until those controls are automated, require a human
pre-tag record proving ancestry, exact-SHA CI success, version consistency, and
artifact review.

The provenance job also runs before environment approval and on manual dry
runs. Therefore a GitHub attestation is not, by itself, evidence that a release
was approved or published. Confirm that the chosen attestation mechanism is
supported for the repository visibility and plan, and distinguish GitHub build
provenance from PyPI's publish attestation.

### 5. Resolve public distribution links

A public PyPI page with private Repository and Issues URLs gives adopters dead
links and prevents independent source review. Before public distribution,
choose one coherent posture:

1. make the source repository public;
2. publish from a protected public release or mirror repository; or
3. remove inaccessible Repository and Issues metadata until a public source is
   available.

Do not describe the package as publicly auditable while its source and issue
tracker are inaccessible to the public.

## Preflight commands

Run on a clean checkout of the exact approved candidate commit:

```bash
cd packages/gove-zone
bash scripts/release_check.sh
uv run --extra dev python -m pytest \
  tests/test_release_metadata.py tests/test_public_api.py -q
cd ../..
uv run --package gove-zone python -m pytest \
  packages/gove-zone/tests --import-mode=importlib -q
uv run python -m pytest tests/docs --import-mode=importlib -q
make lint-docs
git diff --check
```

Also inspect the built artifacts rather than trusting command exit codes alone:

- exactly one wheel and one sdist for the intended version;
- metadata version, Python floor, classifier, license, README, and Project URLs;
- both intended wheel packages and required package data;
- all declared console entry points;
- no tests, local paths, secrets, or stale build products; and
- clean-venv smoke from the exact wheel that will be published.

## External checks immediately before publication

- Confirm the PyPI project exists or that the pending publisher is still valid
  and the name remains available; a pending publisher does not reserve a name.
- Confirm the intended version is not already present on PyPI.
- Confirm the protected environment and tag rules through current GitHub
  settings or API evidence.
- Confirm the release tag will point to the exact approved `master` commit.
- Confirm package Homepage, Documentation, Repository, and Issues links resolve
  for the intended audience.
- Confirm the publish action will use Trusted Publishing and no long-lived
  upload credential.

## Post-publish acceptance

A release is complete only after the steps in
[`packages/gove-zone/docs/RELEASING.md`](../packages/gove-zone/docs/RELEASING.md)
pass against PyPI: clean install from the public index, exact version assertion,
smoke proof, artifact digest comparison, publish/build-attestation review,
Project-URL checks, and a GitHub Release tied to the same immutable tag.

If a published version is defective, do not overwrite it. Preserve evidence,
yank when appropriate, and publish a higher corrected version.

## Stable-release boundary

`1.0.0` may define a stable API without proving operational production
maturity. Keep the Beta classifier until independent evidence justifies
Production/Stable. Certification, regulatory approval, production deployment,
and third-party assurance remain separate claims governed by `docs/CLAIMS.md`.
