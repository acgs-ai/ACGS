# Releasing `gove-zone`

This runbook covers only the `packages/gove-zone` Python distribution. It does
not release the whole ACGS monorepo or any nested package.

Release preparation may be automated. Publication authority remains human and
must be evidenced outside the repository. The checked-in workflow proves its
code path; it does **not** prove that GitHub environment protection, tag
rulesets, or the PyPI Trusted Publisher are configured and effective.

All shell blocks below assume Bash on Linux/macOS with `git`, `uv`, `gh`,
Python 3, and standard POSIX utilities available. On Windows, use WSL; do not
paste the Unix virtual-environment paths into PowerShell unchanged.

## Release contract

| Item | Canonical value |
|---|---|
| Distribution | `gove-zone` |
| Primary import package | `gove_zone` |
| Wheel packages | `gove_zone`, `mcp_gateway` |
| Console scripts | `gove-zone`, `gove-zone-api`, `acgs` |
| Version source | Quoted `__version__` literal in `src/gove_zone/__init__.py` |
| Build metadata | Dynamic Hatch version in `pyproject.toml` |
| Tag | `gove-zone-v<PEP-440-version>` |
| Workflow | `.github/workflows/release-gove-zone.yml` |
| PyPI environment | `pypi` |
| Publication mechanism | PyPI Trusted Publishing (OIDC); no stored upload token |
| Default branch | `master` |

Versions and tags are immutable release identifiers. Never move or reuse a tag
or overwrite a published version.

## One-time enforced prerequisites

Complete and record these checks before the first release. Treat any unverified
item as a release blocker.

1. **Confirm repository visibility, GitHub plan, and environment protection.**
   In GitHub Settings → Environments, create `pypi` and verify that a required
   reviewer rule is both available and actually enforced for this private
   repository. Prefer a reviewer other than the tag initiator and enable
   prevention of self-review when the operating model supports two-person
   control. Record all environment and ruleset bypass actors plus the effective
   deployment-protection bypass settings. If required-reviewer protection is
   unavailable on the current plan, do not describe the lane as human-approved
   and do not publish through it.
2. **Protect release tags.** Configure a repository ruleset for
   `gove-zone-v*` that restricts creation, update, and deletion to authorized
   release managers. The workflow can check a tag pattern; it cannot prove that
   a person, rather than a token or app, created the tag.
3. **Register the Trusted Publisher.** In PyPI, configure project `gove-zone`
   with owner `dislovelhl`, repository `ACGS`, workflow
   `release-gove-zone.yml`, and environment `pypi`. For a first upload, use
   PyPI's pending-publisher flow. A pending publisher does not reserve the
   project name, so reconfirm name availability and pending-publisher validity
   immediately before release. If the project now exists, verify that the
   intended owner controls it.
4. **Retire competing publish paths.** Remove any PyPI publisher, GitHub
   environment, secret, or ruleset tied to the retired `release.yml` /
   `production` lane. `release-gove-zone.yml` + `pypi` must be the only active
   publication path.
5. **Prove the protection, not just the configuration.** The current
   `workflow_dispatch` path builds and checks artifacts and skips the `pypi`
   publish job, but it also writes persistent GitHub build attestations. It is
   not a pure dry run and cannot exercise the protected-environment approval
   gate. Do not use it as approval evidence. Verify settings through current UI
   or API evidence and perform a separate non-production protected-environment
   exercise, or harden the workflow with a safe approval-test path first.
   Record the date, reviewer, repository plan, required-reviewer and self-review
   settings, every bypass actor, deployment-protection bypass settings, and the
   resulting deployment history.
6. **Decide public source-link posture.** The repository is private at the time
   of this review, while package metadata exposes Repository and Issues URLs.
   Before a public PyPI release, make the repository public, provide a public
   mirror, or remove inaccessible public metadata links.

GitHub documents plan and visibility limits for required reviewers in
[Managing environments for deployment](https://docs.github.com/actions/deployment/targeting-different-environments/using-environments-for-deployment).
PyPI documents the pending-publisher behavior in
[Creating a PyPI project with a Trusted Publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

## Prepare the release PR

Start from the latest `master`. Keep release preparation in one reviewable PR.

1. Set the quoted `__version__` literal in
   `src/gove_zone/__init__.py`. Do not add a static `[project].version`.
2. Update the exact-version assertion in
   `tests/test_release_metadata.py`. If maturity changes, update its classifier
   assertion separately and explain the evidence for that change.
3. Move relevant `[Unreleased]` entries in `CHANGELOG.md` under the new version.
   Add the release date only when the candidate is actually cut. Inventory all
   package changes since the previous release-preparation commit; an empty
   `[Unreleased]` section is not acceptable when runtime or public API changed.
4. Synchronize the current-source version and maturity wording in the root
   `README.md`, package `README.md`, release-readiness report, and other current
   user-facing docs. Historical evidence must retain its original version and
   be labelled as point-in-time evidence rather than silently rewritten.
5. If the public API changed intentionally, regenerate
   `tests/fixtures/public_api.txt` using the checked-in regeneration procedure,
   inspect the diff, and describe the SemVer impact. Do not hand-append symbols.
6. Review the complete distribution surface: both wheel packages
   (`gove_zone`, `mcp_gateway`), all three console scripts (`gove-zone`,
   `gove-zone-api`, `acgs`), package data, optional extras, Python floor,
   README rendering, license, and Project URLs. Explicitly classify any surface
   that is experimental and excluded from the 1.0 stability promise.
7. Run the release and documentation gates:

   ```bash
   cd packages/gove-zone
   bash scripts/release_check.sh
   cd ../..
   uv run --package gove-zone --extra dev python -m pytest \
     packages/gove-zone/tests/test_release_metadata.py \
     packages/gove-zone/tests/test_public_api.py \
     --import-mode=importlib -q
   uv run python -m pytest tests/docs --import-mode=importlib -q
   make lint-docs
   git fetch --prune origin \
     '+refs/heads/master:refs/remotes/origin/master'
   git diff --check refs/remotes/origin/master...HEAD
   ```

8. Require green PR CI, including `dist-check`, and record the exact commit SHA
   that passed. Because the current tag workflow does not independently enforce
   ancestry from `master` or replay the full test suite, the release manager
   must verify both conditions before tagging.

## Pre-tag approval

Before creating a tag, a human release manager must confirm:

- the candidate commit is the merged `master` commit intended for release;
- the version literal, metadata test, changelog heading, README status, and tag
  all match exactly;
- the full required CI suite passed on that exact commit;
- the PyPI Trusted Publisher and effective `pypi` approval protection were
  rechecked;
- the public-source and Project-URL decision is resolved; and
- no release-blocking security, API-stability, or packaging issue remains.

Until the workflow enforces branch ancestry and full required checks itself,
attach this approval evidence to the release PR or release record.

## Tag and publish

After the release PR is merged:

```bash
set -euo pipefail
git fetch --prune --tags origin \
  '+refs/heads/master:refs/remotes/origin/master'
merge_sha="<approved-master-merge-sha>"
remote_master="$(git rev-parse refs/remotes/origin/master)"
local_head="$(git rev-parse HEAD)"

if [ "$remote_master" != "$merge_sha" ]; then
  echo "refusing release: approved SHA is not the current origin/master" >&2
  exit 1
fi
if [ "$local_head" != "$merge_sha" ] || [ -n "$(git status --porcelain)" ]; then
  echo "refusing release: checkout is not the clean approved SHA" >&2
  exit 1
fi

git show --check --oneline "$merge_sha"

version="$(uv run --locked --package gove-zone python -c \
  'import gove_zone; print(gove_zone.__version__)')"
test -n "$version"
git tag -a "gove-zone-v${version}" "$merge_sha" \
  -m "gove-zone ${version}"
git show --no-patch --decorate "gove-zone-v${version}"
git push origin "gove-zone-v${version}"
```

Use a signed tag when the release-manager signing setup is established. The tag
ruleset must prevent later mutation either way.

The `release-gove-zone` workflow should then:

1. confirm the tag version matches package metadata;
2. build the wheel and sdist and run the distribution gate;
3. generate provenance for the approved release artifacts;
4. wait at the protected `pypi` environment; and
5. publish through PyPI Trusted Publishing only after approval.

Before approving the `pypi` deployment, download the exact tag-triggered run's
`dist` artifact and record its identity and digests:

```bash
set -euo pipefail
run_id="<tag-triggered-workflow-run-id>"
merge_sha="<approved-master-merge-sha>"
version="<approved-version>"
tag="gove-zone-v${version}"
review_dir="$(mktemp -d)"
trap 'rm -rf "$review_dir"' EXIT

run_api="repos/dislovelhl/ACGS/actions/runs/${run_id}"
test "$(gh api "$run_api" --jq .event)" = "push"
test "$(gh api "$run_api" --jq .head_sha)" = "$merge_sha"
test "$(gh api "$run_api" --jq .head_branch)" = "$tag"
test "$(gh api "$run_api" --jq .path)" = \
  ".github/workflows/release-gove-zone.yml"
gh run download "$run_id" --repo dislovelhl/ACGS \
  --name dist --dir "$review_dir/dist"
test "$(find "$review_dir/dist" -maxdepth 1 -type f -name '*.whl' | wc -l)" -eq 1
test "$(find "$review_dir/dist" -maxdepth 1 -type f -name '*.tar.gz' | wc -l)" -eq 1
test "$(find "$review_dir/dist" -maxdepth 1 -type f | wc -l)" -eq 2
find "$review_dir/dist" -maxdepth 1 -type f -print | sort
python3 - "$review_dir/dist" <<'PY'
from hashlib import sha256
from pathlib import Path
import sys

for path in sorted(Path(sys.argv[1]).iterdir()):
    if path.is_file():
        print(f"{sha256(path.read_bytes()).hexdigest()}  {path.name}")
PY
```

Require exactly the intended wheel and sdist. Verify their filenames, embedded
version and metadata, checks, and recorded digests before approval. Reject the
deployment if any value differs. The current workflow does not emit an
immutable pre-approval digest manifest or job summary, so this manual record is
a gap to automate. It also generates attestations before environment approval;
a pre-approval attestation is build provenance, not proof that publication was
authorized or completed.

## Post-publish verification

Verify from PyPI, not from the source tree or a package-manager cache:

```bash
set -euo pipefail
version="<published-version>"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
python3 -m venv "$tmp/venv"
"$tmp/venv/bin/python" -m pip install --isolated --no-cache-dir \
  --index-url https://pypi.org/simple "gove-zone==${version}"
installed_version="$("$tmp/venv/bin/python" -c \
  'from importlib.metadata import version; print(version("gove-zone"))')"
test "$installed_version" = "$version"
"$tmp/venv/bin/gove-zone" smoke --audit "$tmp/audit.jsonl"
"$tmp/venv/bin/python" -m pip show gove-zone
```

Then:

1. confirm the imported version equals the approved version;
2. inspect the PyPI page, README rendering, Python requirement, classifiers,
   license, and every Project URL;
3. download the published wheel and sdist, record their SHA-256 digests, and
   compare them with the workflow artifacts;
4. query PyPI's Integrity API for each published filename and verify its PEP
   740 publish attestation identifies the intended Trusted Publisher;
5. when the repository plan supports attestations for this private repository,
   verify both published files against the exact signer workflow, tag ref, and
   source commit as shown below;
   and
6. create the GitHub Release from the same immutable tag with the matching
   changelog, commit SHA, artifact digests, and smoke-verification result.

```bash
set -euo pipefail
version="<published-version>"
merge_sha="<approved-master-merge-sha>"
published_dir="<directory-containing-downloaded-wheel-and-sdist>"

for file in "$published_dir"/*.whl "$published_dir"/*.tar.gz; do
  gh attestation verify "$file" \
    --repo dislovelhl/ACGS \
    --signer-workflow \
      dislovelhl/ACGS/.github/workflows/release-gove-zone.yml \
    --source-ref "refs/tags/gove-zone-v${version}" \
    --source-digest "$merge_sha"
done
```

PyPI publish attestations and GitHub build attestations are different evidence.
See PyPI's [Integrity API](https://docs.pypi.org/api/integrity/) and GitHub's
[artifact-attestation guidance](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds).
The exact verification flags are documented in the
[`gh attestation verify` manual](https://cli.github.com/manual/gh_attestation_verify).
For private repositories, GitHub artifact attestations require a supported
GitHub Enterprise Cloud plan; verify that capability before relying on the
workflow's attestation job.

## Failure, rollback, and yanking

- **Before approval or upload:** reject or cancel the deployment. Fix forward in
  a reviewed PR. If a tag was exposed, do not force-move it; use a new version
  and tag when source changes are required.
- **Transient workflow failure with unchanged approved source:** rerun only
  after confirming no artifact was uploaded and the exact commit, version, and
  artifact digests remain unchanged.
- **After upload:** PyPI versions are immutable. Never overwrite or reuse the
  version. Preserve the evidence, yank the affected release with a reason when
  appropriate, publish a higher corrected version, and update the GitHub
  Release and security/adoption communications.
- **Publisher or supply-chain incident:** reject pending deployments, disable or
  remove the Trusted Publisher, protect tags, preserve logs and attestations,
  rotate any affected credentials, and follow the security-response process.

See PyPI's [yanking guidance](https://docs.pypi.org/project-management/yanking/)
before yanking a release.

## Final `1.0.0`

SemVer stability and operational production maturity are separate decisions.
Do **not** automatically change the classifier from Beta to
Production/Stable merely because the version becomes `1.0.0`.

For the final release PR:

- replace the RC-specific version test with an exact `1.0.0` assertion;
- decide the classifier from independent maturity evidence and update its test
  only when that evidence supports the change;
- reconcile the API-stability contract, public API fixture, distribution
  surface, changelog, and all current status references; and
- record the human security, release, and operational sign-offs required by the
  claim ledger.
