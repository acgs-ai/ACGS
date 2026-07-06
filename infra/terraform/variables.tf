# Inputs. No defaults for identity-bearing values — a human supplies them at
# plan time. Nothing here is a secret; secret VALUES never enter IaC.

variable "project_id" {
  description = "GCP project id (maps to the GCP_PROJECT_ID repo secret)."
  type        = string
}

variable "region" {
  description = "GCP region for Cloud Run + Artifact Registry (maps to GCP_REGION, e.g. us-central1)."
  type        = string
  default     = "us-central1"
}

variable "github_repository" {
  description = "GitHub repository allowed to assume the deploy identity, as owner/name. Pins the WIF provider's attribute condition."
  type        = string
}

variable "artifact_repo_id" {
  description = "Artifact Registry Docker repository id referenced by GCP_ARTIFACT_REGISTRY."
  type        = string
  default     = "acgi"
}

variable "cloudflare_account_id" {
  description = "Cloudflare account id (maps to the CLOUDFLARE_ACCOUNT_ID repo secret)."
  type        = string
}

variable "placeholder_image" {
  description = "Bootstrap-only container image for Cloud Run service shells. CI owns real revisions (gcloud run services replace); Terraform ignores image drift after creation."
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "trace_bucket_name" {
  description = "GCS bucket for the agent-bus-analyzer file-backed TraceStore (gcsfuse mount). Empty string derives <project_id>-agent-bus-analyzer-traces."
  type        = string
  default     = ""
}

locals {
  trace_bucket_name = var.trace_bucket_name != "" ? var.trace_bucket_name : "${var.project_id}-agent-bus-analyzer-traces"
}
