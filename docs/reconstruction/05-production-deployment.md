# Production Readiness & Deployment Plan (doc 5 of 6)

> Platform-reconstruction program, document 5 of 6.
> Basis: `01-internal-audit.md` (esp. §5 deployment reality, §6 test/sealed estate,
> §7 gap register) and `02-external-research.md` §2 (compliance evidence bar), plus
> direct reads of `.github/workflows/{console,marketing-cloudflare,release,
> constitutional-hash,python-clinicalguard,tests-root-hosted}.yml`,
> `acgi-ai/infra/**`, and `packages/agent-bus-analyzer/deploy/**`.
> This is a **proposal**. Every "current state" claim cites the audit or a file read.
> Sequencing references `04-platform-blueprint.md` by name only (concurrent peer work).

---

## 1. Service topology (target)

The estate is mostly libraries + static assets today; only two runtime services deploy.
The target adds three service surfaces, all thin adapters over the gove-zone kernel.

| Component | Kind | Runtime / image | Ingress | AuthN posture | Data / state | Tenancy |
|---|---|---|---|---|---|---|
| **marketing** | Static assets | CF Pages (`wrangler pages deploy`), no image | Public edge | Anonymous; report-only CSP | None (build output) | Single public site |
| **console** | Service (exists) | Cloud Run, `infra/Dockerfile.console` (Caddy-served) | Public, fail-closed `AUTH_UPSTREAM` forward-auth | Edge forward-auth; enforced CSP `script-src 'self'` | Stateless; proxies same-origin bus | Per-tenant via upstream |
| **receipt-verification / control-plane API** | Service (new) | Cloud Run, new image from `gove-zone` (`gove-zone-api` surface per blueprint) | Internal + LB; console is first client | Signed-receipt verify is stateless; write paths need workload identity | Audit/consumption ledger = hash-chained JSONL → GCS bucket or Cloud SQL | Tenant id on every receipt |
| **agent-bus-analyzer service** | Service (new pipeline) | Cloud Run, `deploy/Dockerfile`; `deploy/cloudrun/service.yaml` exists | `internal-and-cloud-load-balancing` (observer-only) | Runtime SA; evidence signing required (`ACGS_EVIDENCE_SIGNING_REQUIRED=true`) | SQLite + JSONL TraceStore over gcsfuse bucket; **`maxScale: 1`** (single writer) | Trace store per deployment |
| **eval-mvp governed MCP server** | Service (pilot) | Cloud Run or container pilot; `governed_mcp_v0` gate | Internal / gated | MCP OAuth 2.1 + PKCE (research §2) | Chain-hashed JSONL evidence | Pilot single-tenant |

Two topology facts pinned from files:
- The **audit-chain state problem** is real and already designed around: agent-bus-analyzer's
  `service.yaml` pins `minScale/maxScale: 1` precisely because "file-backed TraceStore uses
  SQLite + JSONL over the mounted bucket" and multi-writer fan-out is unowned
  (`packages/agent-bus-analyzer/deploy/cloudrun/service.yaml:19-23`). The same constraint
  applies to any JSONL audit-chain writer (receipt ledger). **Single-writer until an
  object-store/index backend or writer-partitioning lands** — do not autoscale audit writers.
- Evidence signing is wired to Secret Manager, not env plaintext: the analyzer mounts
  `acgs-evidence-signing-secret` and pins secret version `"1"` for reproducible proof exports
  (`service.yaml:25,53-61`). Extend this pattern to the receipt API.

**Data / state strategy for audit chains (proposal).** The JSONL hash-chain is the platform's
compliance substrate (research §2), so its durability posture is a production decision, not an
implementation detail. Two viable backends:
- **GCS bucket via gcsfuse** — the analyzer's current choice (`service.yaml:81-88`). Cheap,
  append-friendly, but locks the writer to a single instance (`maxScale: 1`). Fine for the
  observer and the pilot; acceptable for the receipt ledger at launch scale.
- **Cloud SQL (Postgres) append-only table** — needed only once receipt-write throughput
  outgrows a single writer. Migrate the ledger here *before* raising `maxScale`, never after.
Either way the chain stays **write-once + hash-linked**; the backend choice never weakens the
tamper-evidence property auditors check (research §2). Start on the bucket; hold Cloud SQL as
the documented scale path.

## 2. Environment ladder

Target ladder: **dev → staging → production**. Staging is currently **not deployed** — the
templates exist unused (`acgi-ai/infra/cloudrun/service.staging.yaml`,
`service.preview.yaml`; audit §5).

- **dev** — local `make verify` / per-package gate; no hosted surface. No change.
- **staging** (new) — deploy `service.staging.yaml` (one warm instance, `minScale: 1`, for
  pre-production smoke) to a `acgi-console-staging` Cloud Run service. Marketing gets a CF
  Pages **preview** deployment per non-master branch (`wrangler pages deploy --branch=<ref>`),
  which the platform already supports implicitly. Promotion rule: **staging deploys
  automatically on merge to master; production stays human-gated** (below).
- **production** — unchanged human gate. Both existing deploys are push-to-master and require
  the GitHub `production` environment approval (`console.yml:229,282`;
  `marketing-cloudflare.yml:94`). Keep that gate; add staging *below* it, never bypass it.

Promotion flow: PR verify → merge → **auto staging deploy + staging post-deploy verify** →
human approves `production` environment → production deploy + post-deploy verify. The
post-deploy verify step already exists for console (`scripts/postdeploy-verify.sh`,
`console.yml:324-332`); reuse it verbatim against the staging URL.

## 3. CI/CD hardening

Ordered by audited severity. Each item is agent-preparable unless marked human-gated.

1. **Single self-hosted runner SPOF** (audit §5: "nearly all 23 workflows AND both deploys
   run on one box"). The mitigation pattern already exists: `tests-root-hosted.yml` is a
   byte-faithful twin of the self-hosted gate that runs on `ubuntu-latest`
   (`tests-root-hosted.yml:10-11,57`). **Action:** either register a second self-hosted runner
   (human-gated — needs a box) or extend the hosted-twin pattern to the pure-verify jobs
   (lint/typecheck/pytest with no runner-local state). Deploy jobs must stay self-hosted (they
   hold the WIF trust + this box is the required verify runner). Keep hosted twins verify-only.
2. **Arm the GitHub `production` environment** (audit §5, gap: human gate may be unarmed).
   `marketing-cloudflare.yml:12-14` states plainly the `environment: production` line is
   "decorative … until a human creates it with required reviewers." **Verify current state,
   don't assume** (`gh api repos/:owner/:repo/environments`); if unarmed, a human must create
   the environment with required reviewers and scope GCP_*/CF_* secrets to it. **Human-gated.**
3. **Un-ignore the 5 readiness tests in a CI lane** (audit §6). `test_platform_readiness_report`,
   `test_release_evidence_bundle`, `test_production_blocker_evidence`,
   `test_production_launch_preflight`, `test_readiness_evidence_boundaries` are `--ignore`d and
   run in **no CI**. **Action:** add a dedicated `readiness-evidence` job (self-hosted, with a
   hosted twin) that runs exactly these five, so the readiness claims are gated, not aspirational.
4. **Deploy pipeline for agent-bus-analyzer** (audit §5: artifacts exist, no workflow —
   confirmed: `grep deploy .github/workflows/python-agent-bus-analyzer.yml` is empty).
   **Action:** add `deploy-agent-bus-analyzer.yml` mirroring `console.yml`'s publish/deploy
   split — build `deploy/Dockerfile` → Artifact Registry → `gcloud run services replace
   deploy/cloudrun/service.yaml` — gated on `environment: production`, fail-closed on absent
   WIF secrets. Respect `maxScale: 1`.
5. **Packaging/publish automation for Python packages.** gove-zone already has it:
   `release.yml` is tag-triggered PyPI **Trusted Publishing** via OIDC — build+`twine check` on
   self-hosted, publish on GitHub-hosted (`pypa/gh-action-pypi-publish` needs a container
   action), `environment: production`, **no long-lived token** (`release.yml:1-15,76-80`).
   **Action:** generalize this template to acgs-lite (currently manual PyPI publish, audit §5)
   and any other published package. Publish stays **human-gated** via the environment. Keep the
   "decorative environment" caveat in mind (`release.yml:12`).
6. **Fail-fast grouping for the ~55-gate `test:all` chain** (audit §5). ~55 serial
   `check-*.mjs` gates make failures slow and late. **Action:** group into fail-fast stages
   (structure/CSP contracts → build → browser) so a broken contract fails in the first minute,
   not the 30th. Non-behavioral; agent-preparable. Do not reorder gates that assert honesty
   strings without moving the doc+gate in lockstep.
7. **Playwright `--with-deps` provisioning** (`console.yml:176-178`). Today the browser-checks
   job installs chromium *without* `--with-deps` and relies on the long-lived box having OS
   libs + cached browsers. **Action:** document the provisioning contract and re-add
   `--with-deps` in any hosted-twin or reprovisioned-runner path (it needs apt/sudo, so it
   cannot run bare on the current self-hosted job). Fragile-but-documented today.

## 4. IaC (minimal Terraform / OpenTofu)

Goal: make the human-gated deploy prerequisites reproducible, not click-ops. Scope to the
prerequisites the workflows already reference (`console.yml:1-16`).

- **GCP WIF pool + provider + deploy SA** — the pool, GitHub OIDC provider, and the deploy
  service account with `run.admin` + `artifactregistry.writer` + `iam.serviceAccountUser`.
- **Artifact Registry** — the `acgi` Docker repo referenced by `GCP_ARTIFACT_REGISTRY`.
- **Cloud Run services** — `acgi-console` (staging + production) and `agent-bus-analyzer`
  as `google_cloud_run_v2_service`, plus the analyzer's **GCS trace bucket** and its
  gcsfuse-mount runtime SA (`service.yaml:81-88`), and the Secret Manager
  `acgs-evidence-signing-secret` (value set by a human, never in IaC).
- **CF Pages project** — `acgs-marketing` with production branch `master`
  (`marketing-cloudflare.yml:11-12`).

**Stays dashboard-managed (document why):** the GitHub `production` environment + required
reviewers (GitHub-side, not GCP/CF Terraform providers; human trust decision), the actual
**secret values** (WIF binding, CF API token, PyPI Trusted Publisher registration), and PyPI
Trusted Publisher setup (done in the PyPI UI against the repo). IaC provisions the *shapes*;
humans arm the *trust*.

## 5. Observability & SLOs

Minimal, solo-operator-friendly. The audit observer already exists — agent-bus-analyzer *is*
the audit-chain observability layer (audit §2, "Keep as core observability").

| Service | Measure | Where | Alert (minimalist) |
|---|---|---|---|
| console | Request latency, 5xx rate, deploy success, post-deploy verify pass | Cloud Run metrics + `postdeploy-verify.sh` | Alert only on post-deploy verify fail or sustained 5xx |
| receipt API | **Decision latency overhead** (governance cost per action), receipt **verification-failure** rate, audit-chain **integrity-check** cadence | Cloud Run metrics + kernel counters | Alert on verify-failure spike or chain break |
| agent-bus-analyzer | Trace ingest lag, evidence-signing failures, TraceStore write errors | analyzer API (`/api/bus/healthz`, `service.yaml:67`) | Alert on signing failure (fail-closed) |
| marketing | Deploy success, edge availability | CF Pages / CF analytics | Alert on deploy fail only |

SLO starting points (proposal, tune after baseline): console availability 99.5%; receipt-verify
p99 overhead < a documented budget; audit-chain integrity check runs on a fixed cadence and
**any** break pages. Keep the alert set small — a solo operator should get paged for
fail-closed breaches (signing, chain integrity, post-deploy verify), not for latency noise.

## 6. Security / compliance ops

- **Secrets inventory** (from the workflows read): `GCP_PROJECT_ID`, `GCP_REGION`,
  `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT`, `GCP_ARTIFACT_REGISTRY`,
  `CONSOLE_AUTH_UPSTREAM`, `CONSOLE_BUS_UPSTREAM` (`console.yml:9-16`);
  `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` (`marketing-cloudflare.yml:7-8`);
  `SUBMODULE_TOKEN` PAT (`python-clinicalguard.yml:51`); `acgs-evidence-signing-secret` in
  Secret Manager (`agent-bus-analyzer/deploy/cloudrun/service.yaml:25`). **No long-lived
  service-account JSON** — WIF only (`console.yml:2-4`).
- **Rotation:** WIF removes the biggest rotation burden (short-lived OIDC). Remaining
  long-lived items — `CLOUDFLARE_API_TOKEN`, `SUBMODULE_TOKEN`, evidence-signing secret —
  need a rotation cadence; pin the signing secret **version** (already done) so rotation is a
  new version, not a break.
- **Constitutional-hash gate — activate or descope** (audit §7 gap #3). The gate guards an
  **empty parent inventory** ("Today the inventory is empty", `constitutional-hash.yml:7`), so
  it is a no-op that *reads* as an active control. **Action:** either populate the parent
  inventory with real markers or explicitly descope the parent gate and document that nested
  repos (acgs-lite, clinicalguard) own their own hashes. A no-op control is worse than none.
- **clinicalguard PAT scope fix** (audit §7 gap #9). CI **soft-fails** without a scoped PAT:
  every step is `if: steps.clinicalguard.outputs.available == 'true'`, so a red private package
  passes silently (`python-clinicalguard.yml:57-85`). **Action:** rotate `SUBMODULE_TOKEN` to
  include Contents:Read on the clinical repo, then make the "unavailable" branch **fail** on
  master (keep soft-fail only for external-fork PRs). **Human-gated** (PAT issuance).
- **Fail-closed verification in the deploy pipeline.** The post-deploy verify pattern exists
  for console (`postdeploy-verify.sh`, `console.yml:324-332`). **Extend it** to staging, the
  receipt API, and agent-bus-analyzer so no deploy is "green" without a live post-deploy check.
  This is also the **compliance evidence** hook: research §2 requires tamper-evident,
  operation-level, write-once hash-chained logs, and notes auditors "discount logs that cannot
  prove non-alteration" — wire the audit-chain integrity check into post-deploy verify so each
  deploy emits fresh conformity evidence (EU AI Act logging, GDPR Art. 22, SOX/HIPAA).

## 7. Hardening checklist

| Item | Current state (cited) | Action | Owner-gate |
|---|---|---|---|
| Second CI runner | Single self-hosted SPOF (audit §5) | Register 2nd runner OR extend `tests-root-hosted` hosted-twin to verify jobs | Human-gated (runner box) / agent (twins) |
| `production` env armed | May be decorative (`marketing-cloudflare.yml:12-14`) | Verify via `gh api`; create env + required reviewers | **Human-gated** |
| 5 readiness tests | `--ignore`d, no CI (audit §6) | Add `readiness-evidence` CI job running the five | Agent-preparable |
| agent-bus-analyzer deploy | Artifacts exist, no workflow (audit §5; grep confirmed) | Add deploy workflow mirroring console publish/deploy split | Agent-preparable |
| Python publish automation | gove-zone has `release.yml`; acgs-lite manual (audit §5) | Generalize Trusted-Publishing template | Agent (workflow) / **Human (publish)** |
| `test:all` fail-fast | ~55 serial gates (audit §5) | Group into fail-fast stages | Agent-preparable |
| Playwright provisioning | No `--with-deps`, hand-provisioned (`console.yml:176-178`) | Document contract; add `--with-deps` to twin/reprovision path | Agent-preparable |
| Staging environment | Templates unused, not deployed (audit §5) | Deploy `service.staging.yaml` + preview flow | Agent (pipeline) / **Human (first deploy)** |
| WIF pool + AR + services IaC | No IaC (audit §5) | Minimal Terraform/OpenTofu (§4) | Agent (write) / **Human (apply)** |
| Constitutional-hash gate | Guards empty inventory (`constitutional-hash.yml:7`) | Populate inventory or descope parent gate | Agent-preparable (decision: human) |
| clinicalguard soft-fail | Silent pass w/o PAT (`python-clinicalguard.yml:57-85`) | Fail-closed on master; scope PAT | **Human-gated** (PAT) |
| Evidence-signing secret | Secret Manager, version-pinned (`service.yaml:25,61`) | Add rotation cadence; keep version pin | **Human-gated** (secret) |
| Post-deploy verify coverage | Console only (`console.yml:324`) | Extend to staging + new services | Agent-preparable |
| GitHub `production` secrets scope | Repo-wide vs env-scoped unclear | Move GCP_*/CF_* to env scope | **Human-gated** |
| Deploys (console, marketing, PyPI) | Human-gated by design | Keep human gate; never automate | **Human-gated** |

## 8. Rollout sequencing

Aligns to the Phase A–D structure in `04-platform-blueprint.md` (referenced by name only;
not read). Proposal ordering:

- **Phase A (foundations, agent-preparable):** fail-fast `test:all` grouping; `readiness-evidence`
  CI job (un-ignore the five tests); document Playwright provisioning; write the minimal IaC
  (unapplied). No trust changes; unblocks everything else.
- **Phase B (staging + resilience):** deploy staging from `service.staging.yaml`; extend
  post-deploy verify to staging; add the hosted-twin verify lane (SPOF mitigation). First
  human gate: staging first-deploy + (if needed) 2nd runner box.
- **Phase C (new services):** stand up the receipt-verification/control-plane API and the
  agent-bus-analyzer deploy workflow (respecting `maxScale: 1` + Secret Manager signing);
  extend post-deploy verify + audit-chain integrity checks as conformity evidence.
- **Phase D (compliance + publish hardening, human-gated):** arm `production` environment +
  reviewers; scope secrets to the environment; fix clinicalguard fail-closed + PAT; activate or
  descope the constitutional-hash gate; generalize PyPI Trusted Publishing; pilot the eval-mvp
  governed MCP server. This phase is where the human trust gates concentrate — deploys, secrets,
  PyPI, GitHub env config all live here and stay human-gated permanently.

The invariant across all phases: **agents prepare, humans deploy/publish/arm-trust.** Nothing in
this plan automates a deploy, a secret, a PyPI push, or a GitHub-environment trust decision.
