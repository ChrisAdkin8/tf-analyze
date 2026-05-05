# Expected findings:
#  - R-NNN HIGH — bucket holding stateful data lacks `lifecycle { prevent_destroy = true }`
#  - R-NNN HIGH — `force_destroy = true` is set, allowing apply to wipe non-empty buckets
#  - S-NNN MEDIUM — versioning not enabled

terraform {
  required_version = "~> 1.10"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.50" }
  }
}

provider "google" {
  project = "test-project"
  region  = "us-central1"
}

resource "google_storage_bucket" "data" {
  name                        = "test-project-stateful-data"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  force_destroy               = true # finding: data loss risk
  # finding: missing lifecycle { prevent_destroy = true }
  # finding: missing versioning { enabled = true }
}
