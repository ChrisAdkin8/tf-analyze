# Expected finding: S-NNN HIGH — overly broad IAM role at project scope.
# `roles/owner` grants full project control; the workload only needs
# `roles/storage.objectAdmin` on a single bucket.

terraform {
  required_version = "~> 1.10"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.50"
    }
  }
}

provider "google" {
  project = "test-project"
  region  = "us-central1"
}

resource "google_service_account" "worker" {
  account_id   = "worker-sa"
  display_name = "Worker"
}

resource "google_project_iam_member" "worker_owner" {
  project = "test-project"
  role    = "roles/owner" # finding: too broad
  member  = "serviceAccount:${google_service_account.worker.email}"
}
