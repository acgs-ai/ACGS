# design-sync notes — ACGS / acgi-ai (tokens-only DS)

- **This is a tokens+styles-only sync by design.** acgi-ai is an app, not a component library — zero React component exports. `srcDir: "public"` deliberately forces zero component discovery (without it, synth-entry bundles the whole app and dies on `@tanstack/react-query`, `@ag-ui/client`, msw imports and absolute `/static/fonts/` URLs).
- **Converter setup (fresh clone):** stage scripts per skill, then in `.ds-sync/`: `npm i esbuild ts-morph @types/react react react-dom typescript playwright@1.60.0` and `npm i --save "acgi-ai@file:../acgi-ai"`. The file: dep matters — a plain `ln -s` symlink gets PRUNED by the next `npm i` ("removed 1 package").
- **Path invariant:** always run the converter with `--node-modules .ds-sync/node_modules`. `cssEntry`/`extraFonts` relative paths resolve LEXICALLY from `.ds-sync/node_modules/acgi-ai/` (path.resolve collapses `..` before fs), hence `../../../.design-sync/…` for extraFonts and package-internal `dist/ds-compiled.css` for cssEntry (cssEntry is package-bounded; extraFonts is repo-bounded).
- **buildCmd** regenerates `acgi-ai/dist/ds-compiled.css`: vite marketing build, then `sed 's/@font-face{[^}]*}//g'` strips @font-face blocks. Stripping is REQUIRED: compiled faces carry absolute `/static/fonts/` URLs that dangle in the DS project and (being later in the cascade) would override the healthy faces shipped via extraFonts.
- **fonts-src.css** is generated from `acgi-ai/src/fonts.css` by: `sed 's|url("/static/fonts/|url("../acgi-ai/public/static/fonts/|g' acgi-ai/src/fonts.css > .design-sync/fonts-src.css`. Regenerate when fonts change (font-manifest gate guards the app side).
- **playwright/chromium:** playwright@1.60.0 pins chromium-1223 = the build already in ~/.cache/ms-playwright. Do NOT bump playwright without checking browsers.json.
- **Upstream app CSS quirks (pre-existing on master, not sync bugs):** `--risk-med` referenced but token is defined as `--risk-mid`; `--danger` and `--rust` referenced (workbench-* summaries) but never defined. Candidate app-side fixes.
- **Render verification gap:** headless chromium fails in this agent harness (file:// → ERR_FAILED; http → ERR_INSUFFICIENT_RESOURCES, sandbox-independent). Bundle verified statically (imports resolve, fonts on disk, tokens diffed). Eyeball the DS pane after upload.
- **Legacy project backup:** the pre-overwrite hand-authored DS ("ACGS GovernZone Design System", 15 components + ui_kits + foundations) is copied to `.design-sync/.cache/legacy-backup/` (gitignored, this worktree only). Re-create components from there if ever wanted back.

## Re-sync risks

- `dist/ds-compiled.css` mirrors the app build (tailwind content scan): stale unless `buildCmd` reruns — when in doubt, rebuild.
- `fonts-src.css` drifts silently if `src/fonts.css` gains/loses faces — regenerate with the sed line above.
- `conventions.md` names `.m-*`/`.gz-*`/`.ev-*`/`.c-*`/`.u-*`/`.btn*` classes and the token families — re-validate against the fresh `_ds_bundle.css` after App.css refactors.
- Renders were never machine-checked in this environment (see above); nothing downstream re-checks them automatically.
