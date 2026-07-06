# Minimal deploy-prerequisite IaC (UNAPPLIED)

> **Status: written, never applied.** No `terraform init/plan/apply` has been run against
> any real project. Applying this is a **human-gated** step (see
> `docs/reconstruction/05-production-deployment.md` §4 and §8 Phase A). Agents prepare,
> humans deploy/arm-trust.

Scope is exactly the prerequisites the existing workflows already reference
(`.github/workflows/console.yml:1-16`, `.github/workflows/marketing-cloudflare.yml:1-14`,
`packages/agent-bus-analyzer/deploy/cloudrun/service.yaml`) — the goal is to make the
human-gated deploy prerequisites reproducible instead of click-ops:

| File | Provisions |
|---|---|
| `iam.tf` | GCP Workload Identity Federation pool + GitHub OIDC provider, deploy service account (`run.admin`, `artifactregistry.writer`, `iam.serviceAccountUser`), analyzer runtime service account |
| `artifact_registry.tf` | The `acgi` Docker repo referenced by the `GCP_ARTIFACT_REGISTRY` secret |
| `cloud_run.tf` | `acgi-console-staging`, `acgi-console` (production), and `agent-bus-analyzer` services; the analyzer's GCS trace bucket; the `acgs-evidence-signing-secret` Secret Manager **shape** (value set by a human, never in IaC) |
| `cloudflare_pages.tf` | Cloudflare Pages project `acgs-marketing`, production branch `master` |
| `variables.tf` / `outputs.tf` | Inputs; outputs map 1:1 to the GitHub Actions secrets the workflows consume |

## Stays dashboard-managed (deliberately NOT in IaC)

- The GitHub `production` environment + required reviewers (GitHub-side trust decision,
  not a GCP/Cloudflare provider concern).
- All **secret values**: the WIF binding trust is provisioned here, but the
  `CLOUDFLARE_API_TOKEN`, `SUBMODULE_TOKEN`, and the evidence-signing secret **value**
  (only the Secret Manager container is created; a human adds version `1`).
- PyPI Trusted Publisher registration (done in the PyPI UI against the repo).

IaC provisions the *shapes*; humans arm the *trust*.

## Relationship to the existing Knative YAML templates

`acgi-ai/infra/cloudrun/service.{staging,production}.yaml` remain the deploy-time
contract — `.github/workflows/console.yml` renders and `gcloud run services replace`s
them on every deploy, and `pnpm test:cloudrun-templates` gates them. The
`google_cloud_run_v2_service` resources here create the *service shells* with the same
scaling/resource posture and then ignore revision-level drift (`lifecycle.ignore_changes`)
so CI keeps owning revisions. On first real apply, `terraform import` the two console
services if they already exist.

The analyzer constraint is preserved verbatim: **`max_instance_count = 1`** because the
file-backed TraceStore is SQLite + JSONL over a gcsfuse mount — a single writer until an
object-store/index backend owns multi-writer fan-out
(`packages/agent-bus-analyzer/deploy/cloudrun/service.yaml:19-23`). Do not raise it here
without migrating the store first.

## Validation (what "proven" means today)

Neither `terraform` nor `tofu` is installed on the CI box, so the parse proof is
HCL2-syntax parsing of every `.tf` file (no network, no state, no providers):

```bash
uv run --no-project --with python-hcl2 python -c "
import glob, hcl2
for f in sorted(glob.glob('infra/terraform/*.tf')):
    with open(f) as fh:
        hcl2.load(fh)
    print('parsed', f)
"
```

Once a human runs it for real: `terraform init && terraform validate && terraform plan`
(plan-only review first), then apply from a workstation with `gcloud auth
application-default login` + `CLOUDFLARE_API_TOKEN` exported. Never wire apply into CI.
