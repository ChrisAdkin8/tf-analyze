# Expected findings:
#  - STYLE-DESC-001 LOW — variable without description
#  - STYLE-DESC-001 LOW — output without description

variable "project_id" {
  type = string
}

variable "region" {
  type        = string
  description = "GCP region for resource placement"
  default     = "us-central1"
}

resource "google_storage_bucket" "data" {
  name     = "${var.project_id}-data"
  location = var.region
}

output "bucket_name" {
  value = google_storage_bucket.data.name
}

output "bucket_url" {
  description = "Self-link URL for the data bucket"
  value       = google_storage_bucket.data.self_link
}
