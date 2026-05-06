# Expected findings: ROB-VERSION-003

terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      # version intentionally omitted
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"  # this one is fine — should NOT fire
    }
  }
}

resource "google_storage_bucket" "main" {
  name     = "demo-bucket"
  location = "US"
}
