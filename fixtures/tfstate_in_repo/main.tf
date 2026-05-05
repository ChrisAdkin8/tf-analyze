# Expected findings:
#  - SEC-STATE-001 CRITICAL — terraform.tfstate committed alongside this fixture

resource "google_storage_bucket" "example" {
  name     = "example"
  location = "US"
}
