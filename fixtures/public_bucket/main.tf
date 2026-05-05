# Expected findings:
#  - S-NNN CRITICAL — bucket exposed to allUsers (public read)
#  - S-NNN HIGH — public_access_prevention not set to "enforced"
#  - S-NNN MEDIUM — uniform_bucket_level_access disabled

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

resource "google_storage_bucket" "public" {
  name                        = "test-project-public-data"
  location                    = "us-central1"
  uniform_bucket_level_access = false # finding
  # finding: public_access_prevention not enforced
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.public.name
  role   = "roles/storage.objectViewer"
  member = "allUsers" # finding: world-readable
}
