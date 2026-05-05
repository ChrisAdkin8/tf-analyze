# Expected findings:
#  - ROB-PROVIDER-ALIAS-002 LOW — provider alias google.eu declared but never used

provider "google" {
  project = "my-project"
  region  = "us-central1"
}

provider "google" {
  alias   = "eu"
  project = "my-project"
  region  = "europe-west1"
}

resource "google_storage_bucket" "us" {
  name     = "us-data"
  location = "US"
}
