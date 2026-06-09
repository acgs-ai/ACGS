# `gove-zone` — PyPI publish-readiness report

**Scope:** the `gove-zone` *kernel* package at `packages/gove-zone/`. This is the
**unpublished** governed-runtime core.

> **Not to be confused with `acgs-lite`.** `packages/acgs-lite/` is a *separate*
> package that is **already published to PyPI** (v2.10.0, `requires-python
> >=3.10`). This report does **not** touch `acgs-lite`. Everything below is about
> `gove-zone` only.

**Status:** audit/report. Producing this file changes no packaging behavior.
**Publishing is a human-gated release action — this report does not publish.**

Generated against `packages/gove-zone/pyproject.toml` at `version = "0.1.0.dev0"`.

---

## Verdict

Both original packaging **blockers are now resolved and verified against the
built wheel** (2026-06-06). What remains before publish is the version bump, a
PyPI name check, the apex-404 landing page, and the human-gated upload.

| # | Item | State | Severity |
|---|---|---|---|
| 1 | `LICENSE` file ships in the sdist/wheel | ✅ **resolved** — ships as `dist-info/licenses/LICENSE` | was Blocker |
| 2 | `[project.urls]` (Homepage / Repository / Issues) | ✅ **resolved** — 4 `Project-URL` in METADATA | was Blocker |
| 3 | Version is `0.1.0.dev0` | ⚠️ dev marker | Must bump to publish |
| 4 | Package name `gove-zone` available on PyPI | ❓ unverified | Verify before upload |
| 5 | `README.md` long description | ✅ present (452 lines, claim-safe) | OK |
| 6 | Build backend (`hatchling`) + wheel target | ✅ `packages = ["src/gove_zone"]` | OK |
| 7 | Zero hard runtime deps; extras for `schema`/`crypto` | ✅ `dependencies = []` | OK |
| 8 | Classifiers + `requires-python = ">=3.11"` | ✅ Alpha, 3.11/3.12 | OK |
| 9 | Console scripts (`gove-zone`, `gove-zone-api`) | ✅ present | OK |
| 10 | `twine check` / metadata render | ✅ **PASSED** (wheel + sdist, 2026-06-06) | OK |

---

## Blockers (now resolved — prep applied 2026-06-06)

### 1. ~~No `LICENSE` file~~ ✅ RESOLVED

Both `pyproject.toml` files declared `license = { text = "Apache-2.0" }` but no
`LICENSE` file shipped. **Fixed** by copying the org's canonical Apache-2.0 text
(from the already-published `packages/acgs-lite/LICENSE`, body verified as
unmodified Apache-2.0) to:

- `LICENSE` (repo root — covers the monorepo)
- `packages/gove-zone/LICENSE` (so the wheel ships it)

**Evidence (built wheel, not assumed):**

```
$ unzip -l dist/gove_zone-0.1.0.dev0-py3-none-any.whl | grep -i licen
    12057  ...  gove_zone-0.1.0.dev0.dist-info/licenses/LICENSE
$ unzip -p dist/...whl '*.dist-info/METADATA' | grep -i '^License'
License: Apache-2.0
License-File: LICENSE
```

Hatchling auto-included the package-dir `LICENSE` — no `license-files` key was
needed. (Version bump aside, this is publish-ready.)

### 2. ~~No `[project.urls]`~~ ✅ RESOLVED

The PyPI page would have had **no Homepage / Repository / Issues links**.
**Fixed** by adding this block to `packages/gove-zone/pyproject.toml` (directly
after `[project.scripts]`):

```toml
[project.urls]
Homepage = "https://acgs.ai"
Documentation = "https://acgs.ai/docs"
Repository = "https://github.com/dislovelhl/ACGS"
Issues = "https://github.com/dislovelhl/ACGS/issues"
```

**Evidence (built wheel METADATA):**

```
$ unzip -p dist/...whl '*.dist-info/METADATA' | grep -i '^Project-URL'
Project-URL: Homepage, https://acgs.ai
Project-URL: Documentation, https://acgs.ai/docs
Project-URL: Repository, https://github.com/dislovelhl/ACGS
Project-URL: Issues, https://github.com/dislovelhl/ACGS/issues
```

> **Canonical domain verified (2026-06-06):** `acgs.ai` is registered (Cloudflare)
> and `https://acgs.ai/docs` serves the live docs site
> (`<title>ACGS — Constitutional AI Governance</title>`, HTTP 200).
> **Caveat — apex 404:** `https://acgs.ai` (and `https://www.acgs.ai`) currently
> return **HTTP 404**; only `/docs` serves a page. Before publishing, either
> deploy a landing page at the apex so `Homepage` resolves, or temporarily point
> `Homepage` at `https://acgs.ai/docs` (the only path that currently returns 200).
> Do not ship a `Homepage` that 404s on the PyPI page.

---

## Pre-flight items (before the upload command)

3. **Bump the version.** `0.1.0.dev0` is a dev release marker. For a first
   public release choose an explicit version — e.g. `0.1.0a1` (alpha
   pre-release) is the most honest given the project's own "alpha / not
   production-certified" stance. Keep the `Development Status :: 3 - Alpha`
   classifier consistent with it.

4. **Confirm the name is free.** Check that `gove-zone` (and the import name
   `gove_zone`) is available / owned on PyPI before the first upload. If taken,
   decide on a namespaced name.

5. **Build + metadata check** (run from `packages/gove-zone/`):

   ```bash
   uv build                 # produces sdist + wheel in dist/
   uvx twine check dist/*   # validates long-description renders + metadata
   ```

   `twine check` must pass before upload. Confirm the wheel actually contains
   `src/gove_zone/**` and (after fix #1) the `LICENSE`.

6. **Smoke the built artifact**, not just the source tree — install the wheel
   into a clean venv and run `gove-zone smoke` to prove the console script and
   packaged module work post-install.

7. **Decide publish mechanics** (human-gated): PyPI Trusted Publishing (OIDC
   via GitHub Actions) is preferred over a long-lived API token. Either way,
   the actual `twine upload` / release is performed by a human, not an agent.

---

## What is already good

- README long description is substantial and **claim-safe** — it already carries
  the alpha / "not production-certified, not compliance-certified" boundary, so
  the PyPI page will not overclaim.
- No hard runtime dependencies; `pydantic` and `cryptography` are correctly
  optional extras (`schema`, `crypto`). Lean install surface.
- Build backend, wheel package target, console scripts, keywords, and
  classifiers are all present and coherent.

## Suggested order of work

1. ✅ ~~Add `LICENSE`~~ (blocker #1) — done, verified in wheel.
2. ✅ ~~Add `[project.urls]`~~ (blocker #2) — done, verified in METADATA.
3. ⬜ Bump version to `0.1.0a1` (item #3) — **next; left as a release decision.**
4. ⬜ Verify name availability (item #4) — needs PyPI lookup.
5. ✅ ~~`uv build` + `twine check` + clean-venv install-smoke~~ — all PASSED
   (wheel installs into a fresh venv, `gove-zone smoke` exits 0 with allow/deny/
   audit-chain checks green).
6. ⬜ Deploy apex landing page so `Homepage` resolves (or repoint to `/docs`).
7. ⬜ Hand off to a human for Trusted-Publishing upload (item #7).

Items 1–5 are reviewable engineering work suitable for a PR (and appear as a
good-first-issue cluster in [`CONTRIBUTING.md`](../CONTRIBUTING.md)). Item 6 is
the human-gated release step.
