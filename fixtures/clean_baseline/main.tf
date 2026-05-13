# Expected findings: NONE
# This fixture validates that clean, well-written Terraform produces
# zero findings — catching false positives in detection patterns.

terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  backend "gcs" {
    bucket = "my-tf-state"
    prefix = "prod"
  }
}

variable "project_id" {
  type        = string
  description = "GCP project ID"

  validation {
    condition     = length(var.project_id) > 0
    error_message = "Project ID must not be empty."
  }
}

variable "region" {
  type        = string
  description = "GCP region"
  default     = "us-central1"

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "Region must match GCP region format (e.g., us-central1)."
  }
}

resource "google_storage_bucket" "data" {
  name          = "${var.project_id}-data"
  project       = var.project_id
  location      = var.region
  force_destroy = false

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  # Production data bucket — age out non-current versions (cost) and lock
  # a 7-day retention floor against ransomware-style mass-delete attacks
  # (STK-GCP-STORAGE-LIFECYCLE-001 + STK-GCP-STORAGE-RETENTION-001). The
  # `prevent_destroy` lifecycle below covers Terraform-driven deletes;
  # `retention_policy` covers tampering by anyone with bucket.objects.delete
  # (via leaked SA key, compromised CI, etc.).
  lifecycle_rule {
    condition {
      age                = 90
      with_state         = "ARCHIVED"
    }
    action {
      type = "Delete"
    }
  }

  retention_policy {
    retention_period = 604800 # 7 days
    is_locked        = false  # set to true once tested in non-prod
  }

  labels = {
    environment = "production"
    managed_by  = "terraform"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_audit_config" "all_services" {
  project = var.project_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

output "bucket_name" {
  description = "Name of the data bucket"
  value       = google_storage_bucket.data.name
}
