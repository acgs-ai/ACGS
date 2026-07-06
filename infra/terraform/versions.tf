# Minimal deploy-prerequisite IaC — UNAPPLIED. See README.md in this directory.
# Applying is human-gated (docs/reconstruction/05-production-deployment.md §4).

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Auth via the CLOUDFLARE_API_TOKEN environment variable at plan/apply time
# (human-run workstation). No token material lives in this configuration.
provider "cloudflare" {
}
