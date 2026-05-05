# Expected findings:
#  - ROB-PROVIDER-ALIAS-001 HIGH — module references provider alias google.eu not declared in calling config

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "my-project"
  region  = "us-central1"
}

module "eu_bucket" {
  source = "./modules/bucket"
  providers = {
    google = google.eu
  }
  name = "eu-data"
}
