# Cloud Run service shells + analyzer state.
#
# Terraform owns the service SHAPE (name, ingress, scaling posture, runtime
# SA, volumes). CI owns REVISIONS: .github/workflows/console.yml renders
# acgi-ai/infra/cloudrun/service.<env>.yaml and `gcloud run services replace`s
# it on each human-approved deploy, so every service ignores revision-level
# drift after creation. Scaling/resource values below mirror those templates —
# change them there first (gated by `pnpm test:cloudrun-templates`), then here.

# --- console: staging (acgi-console-staging) ---------------------------------
# Mirrors acgi-ai/infra/cloudrun/service.staging.yaml
# (minScale 1 / maxScale 10 / concurrency 80 / 512Mi).

resource "google_cloud_run_v2_service" "console_staging" {
  name     = "acgi-console-staging"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    max_instance_request_concurrency = 80
    timeout                          = "30s"

    scaling {
      min_instance_count = 1
      max_instance_count = 10
    }

    containers {
      image = var.placeholder_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
  }

  lifecycle {
    # CI replaces the full revision template (image, env, probes) at deploy
    # time; Terraform must not fight it.
    ignore_changes = [
      template,
      client,
      client_version,
    ]
  }
}

# --- console: production (acgi-console) --------------------------------------
# Mirrors acgi-ai/infra/cloudrun/service.production.yaml
# (minScale 2 / maxScale 10 / concurrency 60 / 1Gi). Do not lower production
# readiness here — see acgi-ai/infra/cloudrun/AGENTS.md.

resource "google_cloud_run_v2_service" "console_production" {
  name     = "acgi-console"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    max_instance_request_concurrency = 60
    timeout                          = "30s"

    scaling {
      min_instance_count = 2
      max_instance_count = 10
    }

    containers {
      image = var.placeholder_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template,
      client,
      client_version,
    ]
  }
}

# --- agent-bus-analyzer (observer-only) --------------------------------------
# Mirrors packages/agent-bus-analyzer/deploy/cloudrun/service.yaml. The
# file-backed TraceStore is SQLite + JSONL over the gcsfuse mount below:
# keep max_instance_count = 1 (single writer) until an object-store/index
# backend owns multi-writer fan-out. NEVER autoscale audit-chain writers.

resource "google_cloud_run_v2_service" "analyzer" {
  name     = "agent-bus-analyzer"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account                  = google_service_account.analyzer_runtime.email
    max_instance_request_concurrency = 80
    timeout                          = "30s"
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"

    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    containers {
      image = var.placeholder_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      volume_mounts {
        name       = "analyzer-trace-store"
        mount_path = "/var/lib/agent-bus-analyzer"
      }

      env {
        name  = "ACGS_EVIDENCE_SIGNING_REQUIRED"
        value = "true"
      }
    }

    volumes {
      name = "analyzer-trace-store"

      gcs {
        bucket    = google_storage_bucket.analyzer_trace_store.name
        read_only = false
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template,
      client,
      client_version,
    ]
  }
}

# GCS trace bucket mounted via gcsfuse (service.yaml:81-88). Append-friendly
# and cheap; the documented scale path is Cloud SQL BEFORE raising maxScale.
resource "google_storage_bucket" "analyzer_trace_store" {
  name                        = local.trace_bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
}

resource "google_storage_bucket_iam_member" "analyzer_trace_writer" {
  bucket = google_storage_bucket.analyzer_trace_store.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.analyzer_runtime.email}"
}

# Evidence-signing secret SHAPE only. A human adds the value as version "1";
# the analyzer pins that version (service.yaml:25,61) so proof exports stay
# reproducible — rotation is a NEW version, never an overwrite. The value
# must never appear in IaC or state seeded from IaC.
resource "google_secret_manager_secret" "evidence_signing" {
  secret_id = "acgs-evidence-signing-secret"

  replication {
    auto {
    }
  }
}

resource "google_secret_manager_secret_iam_member" "analyzer_secret_access" {
  secret_id = google_secret_manager_secret.evidence_signing.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.analyzer_runtime.email}"
}
