# Workload Identity Federation + service accounts.
#
# Mirrors the auth model documented at .github/workflows/console.yml:1-16:
# GitHub OIDC token -> WIF pool/provider -> deploy SA. No service-account
# JSON keys anywhere; short-lived tokens only. Do not replace this with a
# long-lived secret.

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
  description               = "OIDC federation for GitHub Actions deploy jobs."
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  display_name                       = "GitHub OIDC"

  # Fail-closed: only this repository may mint credentials through the pool.
  attribute_condition = "assertion.repository == \"${var.github_repository}\""

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# Deploy identity assumed by CI (maps to the GCP_SERVICE_ACCOUNT repo secret).
resource "google_service_account" "deploy" {
  account_id   = "acgi-deploy"
  display_name = "acgi CI deploy (WIF-only, no keys)"
}

# Exactly the three roles the deploy path needs
# (docs/reconstruction/05-production-deployment.md §4).
resource "google_project_iam_member" "deploy_run_admin" {
  project = var.project_id
  role    = "roles/run.admin"
  member  = "serviceAccount:${google_service_account.deploy.email}"
}

resource "google_project_iam_member" "deploy_artifact_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.deploy.email}"
}

resource "google_project_iam_member" "deploy_sa_user" {
  project = var.project_id
  role    = "roles/iam.serviceAccountUser"
  member  = "serviceAccount:${google_service_account.deploy.email}"
}

# Let the federated GitHub identity impersonate the deploy SA — scoped to the
# single repository via the attribute, matching the provider condition above.
resource "google_service_account_iam_member" "deploy_wif_binding" {
  service_account_id = google_service_account.deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}

# Runtime identity for the analyzer service — referenced as
# REPLACE_ANALYZER_RUNTIME_SERVICE_ACCOUNT in
# packages/agent-bus-analyzer/deploy/cloudrun/service.yaml.
resource "google_service_account" "analyzer_runtime" {
  account_id   = "agent-bus-analyzer"
  display_name = "agent-bus-analyzer runtime (trace store + evidence signing)"
}
