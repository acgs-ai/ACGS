# Releasing `gove-zone`

This runbook covers only the `packages/gove-zone` Python distribution. It does
not release the whole ACGS monorepo or any nested package.

Release preparation may be automated. Publication authority remains human and
must be evidenced outside the repository. The checked-in workflow proves its
code path; it does **not** prove that GitHub environment protection, tag
rulesets, or the PyPI Trusted Publisher are configured and effective.

## Release contract

| Item | Canonical value |
|---|---|
| Distribution | `gove-zone` |
| Import package | `gove_zone` |
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
   control. If required-reviewer protection is unavailable on the current plan,
   do not describe the lane as human-approved and do not publish through it.
2. **Protect release tags.** Configure a repository ruleset for
   `gove-zone-v*` that restricts creation, update, and deletion to authorized
   release managers. The workflow can check a tag pattern; it cannot prove that
   a person, rather than a token or app, created the tag.
3. **Register the Trusted Publisher.** In PyPI, configure project `gove-zone`
   with owner `dislovelhl`, repository `ACGS`, workflow
   `release-gove-zone.yml`, and environment `pypi`. For a first upload, use
   PyPI's pending-publisher flow. A pending publisher does not reserve the
   project name, so reconfirm project ownership immediately before release.
4. **Retire competing publish paths.** Remove any PyPI publisher, GitHub
   environment, secret, or ruleset tied to the retired `release.yml` /
   `production` lane. `release-gove-zone.yml` + `pypi` must be the only active
   publication path.
5. **Prove the protection, not just the configuration.** Run
   `workflow_dispatch` on `master` and confirm it builds and checks artifacts
   without publishing. Then perform a non-production environment-approval
   exercise or inspect deployment history to verify the reviewer gate cannot be
   bypassed. Record the date, reviewer, repository plan, and settings evidence.
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
   git diff --check
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
git fetch origin master --tags
merge_sha="<approved-master-merge-sha>"
git merge-base --is-ancestor "$merge_sha" origin/master

version="$(cd packages/gove-zone && uvx hatch version)"
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

At approval time, verify the tag, commit SHA, artifact names, version, checks,
and digests again. Reject the deployment if any value differs. Note that the
current workflow generates attestations before the environment approval; treat
this as a hardening gap and do not interpret a pre-approval attestation as proof
that publication was authorized or completed.

## Post-publish verification

Verify from PyPI, not from the source tree or a package-manager cache:

```bash
version="<published-version>"
tmp="$(mktemp -d)"
python3 -m venv "$tmp/venv"
"$tmp/venv/bin/python" -m pip install --isolated --no-cache-dir \
  --index-url https://pypi.org/simple "gove-zone==${version}"
"$tmp/venv/bin/python" -c \
  'from importlib.metadata import version; print(version("gove-zone"))'
"$tmp/venv/bin/gove-zone" smoke --audit "$tmp/audit.jsonl"
"$tmp/venv/bin/python" -m pip show gove-zone
```

Then:

1. confirm the imported version equals the approved version;
2. inspect the PyPI page, README rendering, Python requirement, classifiers,
   license, and every Project URL;
3. download the published wheel and sdist, record their SHA-256 digests, and
   compare them with the workflow artifacts;
4. verify the artifact attestation from the tagged commit where that
   attestation is externally consumable; and
5. create the GitHub Release from the same immutable tag with the matching
   changelog, commit SHA, artifact digests, and smoke-verification result.

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
