# The Docker repo behind the GCP_ARTIFACT_REGISTRY secret
# (e.g. us-central1-docker.pkg.dev/<project>/acgi — .github/workflows/console.yml:13).

resource "google_artifact_registry_repository" "acgi" {
  repository_id = var.artifact_repo_id
  location      = var.region
  format        = "DOCKER"
  description   = "Console + analyzer container images built by CI."
}
