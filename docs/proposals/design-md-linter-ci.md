# Proposal: wire `@google/design.md` lint into acgi-ai CI

**Status:** draft / proposal — not yet adopted.
**Scope:** `acgi-ai/` frontend only. Does not touch `console/**` runtime code.
**Author:** adaptation pass from GitHub-trending review (google-labs-code/design.md).

## Motivation

`acgi-ai/DESIGN.md` already conforms to the public **design.md** spec (YAML token
frontmatter + ordered `##` sections). The upstream tool
[`@google/design.md`](https://github.com/google-labs-code/design.md) adds
*validation* that our existing gate does not:

| Check | `acgi-ai/scripts/check-design-tokens.py` (current) | `@google/design.md lint` (proposed) |
|---|---|---|
| DESIGN.md color token ↔ `src/index.css` `--var` wiring | ✅ (the `DESIGN_TO_CSS` map) | ❌ (doesn't know our CSS) |
| Broken token references (`{colors.foo}` → missing token) | ❌ | ✅ |
| WCAG AA/AAA contrast on component token pairs | ❌ (DESIGN.md only *says* "validate contrast") | ✅ structured findings |
| Structural validation (section order, duplicate headings) | ❌ | ✅ |
| Token-level regression vs a baseline (`diff` mode) | ❌ | ✅ |

The two are **complementary**: keep `check-design-tokens.py` (it enforces the
DESIGN.md↔runtime-CSS contract the upstream tool can't see) and add the linter
for spec-structural + contrast validation.

## Risk review (acgi-ai is a privileged surface)

1. **New dependency.** `@google/design.md` would be a `devDependency` only, run in
   CI/scripts — **never** bundled into the marketing or console app. It therefore
   does **not** touch the locked 200KB marketing perf budget or the console CSP
   (no runtime code, no CDN/script in a privileged origin). This is the key
   constraint that must hold; verify it stays a pure dev/CI tool.
2. **Network at install.** Pin the version in `package.json` and rely on the
   existing lockfile + CI cache; no install-time network beyond the registry.
3. **Gate coupling.** Add it as a **new** `package.json` script + a **new** step
   in the marketing CI workflow. Do not modify `check-design-tokens.py` or the
   `check-*-foundation.mjs` gates (those assert exact DESIGN.md strings — moving
   them is a separate lockstep change, out of scope here).
4. **Failure mode.** Start the new step **non-blocking** (`continue-on-error` /
   warn-only) for one cycle to surface findings (e.g. the tracked `--muted`
   #6c7382 contrast debt) before making it required. Promote to required only
   after the baseline is clean.

## Implementation sketch

`acgi-ai/package.json`:

```jsonc
{
  "devDependencies": {
    "@google/design.md": "<pin-exact-version>"
  },
  "scripts": {
    // existing: "design:check": "python3 scripts/check-design-tokens.py",
    "design:lint": "design.md lint DESIGN.md --format json",
    "design:diff": "design.md diff DESIGN.md DESIGN.baseline.md"
  }
}
```

CI (the existing `marketing.yml` / acgi-ai workflow), as a new step **after**
`design:check`:

```yaml
- name: DESIGN.md spec lint (warn-only first cycle)
  working-directory: acgi-ai
  continue-on-error: true            # remove once baseline is clean
  run: pnpm design:lint
```

> Windows note (from the upstream README): the `design.md` bin name collides with
> the Markdown file association; use the `designmd` alias via `npx -p
> @google/design.md designmd ...` if anyone runs this on Windows. CI is Linux, so
> the plain form is fine there.

## Acceptance / rollout

1. Land `devDependency` + scripts + **non-blocking** CI step. Capture the first
   `design:lint` JSON output as the finding baseline.
2. Triage findings (expect the known `--muted` contrast item → route to design
   review, per existing tracked debt).
3. Once findings are resolved or explicitly accepted, drop `continue-on-error`
   to make the step required.
4. Optionally commit a `DESIGN.baseline.md` and enable `design:diff` to catch
   token regressions in PRs.

## Out of scope

- Editing `DESIGN.md` itself (already spec-conformant on master).
- Changing `check-design-tokens.py` or any `check-*-foundation.mjs` gate.
- Any console/runtime bundle change.
