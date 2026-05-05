# Expected findings (on this fixture as a whole):
#  - ROB-BACKEND-001 MEDIUM — inconsistent backend types

terraform {
  backend "gcs" {
    bucket = "my-state-bucket"
    prefix = "env1"
  }
}

resource "google_storage_bucket" "test" {
  name     = "test"
  location = "US"
}
