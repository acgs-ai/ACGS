# Outputs map 1:1 to the GitHub Actions repo secrets the deploy workflows
# consume (.github/workflows/console.yml:9-16). A human copies these into the
# repo (ideally environment-scoped) secrets — Terraform never writes to GitHub.

output "workload_identity_provider" {
  description = "Full resource path for the GCP_WORKLOAD_IDENTITY_PROVIDER secret."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "deploy_service_account_email" {
  description = "Deploy SA email for the GCP_SERVICE_ACCOUNT secret."
  value       = google_service_account.deploy.email
}

output "artifact_registry" {
  description = "Image prefix for the GCP_ARTIFACT_REGISTRY secret."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.acgi.repository_id}"
}

output "analyzer_runtime_service_account_email" {
  description = "Value for REPLACE_ANALYZER_RUNTIME_SERVICE_ACCOUNT in packages/agent-bus-analyzer/deploy/cloudrun/service.yaml."
  value       = google_service_account.analyzer_runtime.email
}

output "analyzer_trace_bucket" {
  description = "Value for REPLACE_ANALYZER_TRACE_BUCKET in the analyzer service template."
  value       = google_storage_bucket.analyzer_trace_store.name
}
