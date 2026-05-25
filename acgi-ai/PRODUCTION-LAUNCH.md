# Production launch handoff

This is the operator handoff for a credentialed production launch of `acgs.ai`
and `console.acgs.ai`. It is deliberately a checklist, not a claim of launch.
Local readiness is not production deployment proof; production is proven only by
a successful `master` push deploy, live post-deploy verification, and attached
runtime evidence from the deployed origins.

## Claim boundary

- Do not claim production deployment until `production-authority.example.json`
  has been completed with signed deploy-owner/DNS/auth/claim-owner approvals,
  the GitHub Actions production runs finish green, and live URLs are attached.
- The example authority packet remains `pending-external:deploy-owner-approval`
  and is not production deployment proof by itself.
- Do not claim official Storybook runtime proof until
  `storybook-runtime.plan.json` has `pending-external:dependency-owner-approval`
  replaced by signed dependency-owner evidence, Storybook packages/config are
  installed, and the resulting build is attached.
- Do not claim hosted Storybook proof until `storybook.acgs.ai` serves the
  expected buyer-evidence artifact from the configured Pages origin.
- Do not claim legal, SOC2, WCAG conformance, pentest completion, or regulatory
  attestation from this handoff. Those remain external evidence requirements.

## Required GitHub secrets and variables

Marketing / Vercel production deploy:

- `VERCEL_TOKEN`
- `VERCEL_ORG_ID`
- `VERCEL_PROJECT_ID`

Console / Cloud Run production deploy:

- `GCP_PROJECT_ID`
- `GCP_REGION`
- `GCP_WORKLOAD_IDENTITY_PROVIDER`
- `GCP_SERVICE_ACCOUNT`
- `GCP_ARTIFACT_REGISTRY`
- `CONSOLE_AUTH_UPSTREAM`
- `CONSOLE_BUS_UPSTREAM`

Buyer-evidence publication:

- `STORYBOOK_PAGES_ENABLED=true` after DNS, GitHub Pages, and `storybook.acgs.ai`
  are ready for a live publication attempt.

## Local preflight commands

Run these before a production push or release handoff:

```bash
make verify-js-node24
make platform-readiness
make release-evidence
pnpm -F acgi-ai run test:production-deploy-contract
pnpm -F acgi-ai run test:production-launch-handoff
pnpm -F acgi-ai run test:production-authority-packet
pnpm -F acgi-ai run test:production-evidence-template
pnpm -F acgi-ai run test:production-live-verifier
pnpm -F acgi-ai run test:production-blocker-report
pnpm -F acgi-ai run test:production-evidence-validator
pnpm -F acgi-ai run test:production-cutover-plan
pnpm -F acgi-ai run test:production-evidence-draft
pnpm -F acgi-ai run test:storybook-runtime-plan
pnpm -F acgi-ai run test:hosted-storybook-handoff
```

Expected local state today: `make platform-readiness` may still report the
hosted Storybook item as pending. `storybook-runtime.plan.json` is a local
operator plan only, not official Storybook runtime proof. That pending item blocks stronger hosted
Storybook claims but does not weaken the production deploy fail-closed contract.

## Production execution sequence

1. Complete `production-authority.example.json` into a real authority packet
   with signed `pending-external:deploy-owner-approval`, DNS-owner, auth-owner,
   claim-owner, and rollback authority evidence before mutating production.
2. Confirm `storybook-runtime.plan.json` has signed
   `pending-external:dependency-owner-approval` and release-owner evidence before
   adding Storybook packages, replacing the current `storybook:build` shim, or
   claiming official Storybook runtime proof.
3. Confirm the secrets and `STORYBOOK_PAGES_ENABLED` setting above in GitHub.
4. Push or merge to `master` and record the GitHub Actions run URL.
5. For marketing, record the Vercel deployment URL and confirm that missing
   Vercel secrets would fail closed via `test:production-deploy-contract`.
6. For console, record the Cloud Run service URL, revision, image digest, and
   `EXPECTED_BUILD_ID` used by `scripts/postdeploy-verify.sh`.
7. Copy `production-evidence.example.json` to the real release evidence
   location and replace every `REPLACE_WITH_*` value with the corresponding
   GitHub Actions, Vercel, Cloud Run, `/healthz`, and postdeploy proof. Keep
   legal, pentest, WCAG/manual, browser screenshot, and hosted Storybook fields
   as `pending-external` unless the external proof is attached. The template is
   not live production proof by itself. Fill `productionLiveStatus`,
   `productionLiveBlockers`, `productionEvidenceValidationCommand`,
   `productionEvidenceValidationOutputRef`, and
   `validatedProductionEvidence` from the live verifier and validator artifacts.
8. Run the live console verification command against the deployed origin:

```bash
pnpm -F acgi-ai run verify:postdeploy -- https://console.acgs.ai
```

9. Run the live production verifier and attach its JSON output. It checks DNS,
   HTTPS reachability, `/healthz`, console security headers, and the hosted
   `storybook.acgs.ai` target, including the `storybook-manifest-live`
   `/manifest.json` proof-story/claim-boundary check. A failing output remains
   deployment-blocker evidence and is not live production proof; copy every JSON
   `blockers[].blockerId` value into `verification.productionLiveBlockers` in
   the completed manifest:

```bash
pnpm -F acgi-ai run verify:production-live -- --json
```

10. Build the local hosted Storybook handoff from the Pages-ready buyer-evidence
   manifest and live verifier JSON. The `hosted-storybook-handoff` captures
   `storybook.acgs.ai`, `storybook-manifest-live`, remaining live Storybook
   blockers, and `copyIntoProductionEvidence.hostedStorybook`. Blocked output
   keeps `pending-external:storybook-pages-proof` and the
   `hosted-storybook-buyer-evidence` blocker; it does not deploy, mutate DNS,
   fetch live origins, install the official Storybook runtime, or create live
   production proof.

```bash
pnpm -F acgi-ai run build:hosted-storybook-handoff -- --buyer-evidence-manifest <dist-buyer-evidence/manifest.json> --live-output <verify-production-live.json> --out <hosted-storybook-handoff.json>
```

11. If the live verifier is blocked, build a local blocker handoff report and
   attach it to the release record. The `production-blocker-report` includes
   `productionLiveStatus`, `productionLiveBlockers`, `blockedUntil`, and
   `copyIntoProductionEvidence`; it does not deploy, fetch live origins, or
   create live production proof.

```bash
pnpm -F acgi-ai run build:production-blocker-report -- --live-output <verify-production-live.json> --out <production-blocker-report.json>
```

12. Build the local production cutover plan from the saved live evidence and
   blocker report. The `production-cutover-plan` lists required GitHub secrets,
   DNS cutover records, remaining `productionLiveBlockers`, and
   `copyIntoProductionEvidence`; it does not deploy, mutate DNS, fetch live
   origins, or create live production proof.

```bash
pnpm -F acgi-ai run build:production-cutover-plan -- --live-output <verify-production-live.json> --blocker-report <production-blocker-report.json> --out <production-cutover-plan.json>
```

13. If the live verifier is still blocked, build a validator-ready
   deployment-blocked production evidence draft from the saved local artifacts.
   The `production-evidence-draft` copies `productionLiveStatus`,
   `productionLiveBlockers`, `productionBlockerReport`, `productionCutoverPlan`,
   and `productionEvidenceValidationCommand`, and records missing Cloud Run,
   Vercel, and GitHub Actions run URLs as explicit `pending-external:` refs. It
   does not deploy, fetch live origins, mutate DNS, or create live production
   proof.

```bash
pnpm -F acgi-ai run build:production-evidence-draft -- --live-output <verify-production-live.json> --blocker-report <production-blocker-report.json> --cutover-plan <production-cutover-plan.json> --out <production-evidence.deployment-blocked.json>
```

14. Validate the completed production evidence manifest against the attached live
   verifier JSON and attach the validator output:

```bash
pnpm -F acgi-ai run validate:production-evidence -- --manifest <completed-production-evidence.json> --live-output <verify-production-live.json>
```

   JSON output from `pnpm -F acgi-ai run validate:production-evidence -- --manifest ...`
   is required before stronger deployment evidence claims; it is still not legal,
   SOC2, WCAG, pentest, or regulatory proof.
15. Attach the release-evidence bundle and CI artifacts listed below.
16. Update buyer-facing claims only after live evidence exists for the exact
   claim. No stronger claims until live proof is attached.

## Required artifacts to attach

- `dist-release-evidence/manifest.json`
- `dist-release-evidence/platform-readiness.json`
- Completed production authority packet derived from
  `production-authority.example.json`
- Completed production evidence manifest derived from
  `production-evidence.example.json`
- Completed official Storybook runtime approval evidence derived from
  `storybook-runtime.plan.json`, or the unresolved
  `pending-external:dependency-owner-approval` blocker kept visible
- `buyer-evidence-gallery` CI artifact
- `console-dist` CI artifact from the production push run
- GitHub Actions run URL for `marketing.yml`
- GitHub Actions run URL for `console.yml`
- Vercel deployment URL for `acgs.ai`
- Cloud Run revision URL for `console.acgs.ai`
- Output from `scripts/postdeploy-verify.sh`
- JSON output from `pnpm -F acgi-ai run verify:production-live -- --json`
- JSON output from `pnpm -F acgi-ai run build:hosted-storybook-handoff -- --buyer-evidence-manifest <dist-buyer-evidence/manifest.json> --live-output <verify-production-live.json> --out <hosted-storybook-handoff.json>`
- JSON output from `pnpm -F acgi-ai run build:production-blocker-report -- --live-output <verify-production-live.json> --out <production-blocker-report.json>`
- JSON output from `pnpm -F acgi-ai run build:production-cutover-plan -- --live-output <verify-production-live.json> --blocker-report <production-blocker-report.json> --out <production-cutover-plan.json>`
- JSON output from `pnpm -F acgi-ai run build:production-evidence-draft -- --live-output <verify-production-live.json> --blocker-report <production-blocker-report.json> --cutover-plan <production-cutover-plan.json> --out <production-evidence.deployment-blocked.json>`
- `productionEvidenceChain` from `dist-release-evidence/manifest.json`, which
  compares the saved live verifier, blocker report, cutover plan,
  deployment-blocked draft, `production-evidence-validation.deployment-blocked.json`,
  and `hostedStorybookHandoff` blocker sets for local drift. This is not live
  production proof.
- `productionLiveBlockers` copied from the live verifier `blockers[].blockerId`
- JSON output from `pnpm -F acgi-ai run validate:production-evidence -- --manifest <completed-production-evidence.json> --live-output <verify-production-live.json>`
- `/healthz` served_hash and build_id values from the live console origin
- `EXPECTED_BUILD_ID` / commit SHA used for the deployed artifacts

## Rollback trigger notes

- If Vercel deploy fails, keep the previous marketing deployment active and do
  not claim the new build is live.
- If Cloud Run post-deploy verification fails, roll back to the previous known
  good revision and preserve the failing `postdeploy-verify.sh` output.
- If `CONSOLE_AUTH_UPSTREAM` or `CONSOLE_BUS_UPSTREAM` is missing or invalid,
  do not bypass the forward-auth/bus boundary; fix the secret and rerun the
  deploy.
