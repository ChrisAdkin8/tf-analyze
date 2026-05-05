# Expected findings:
#  - CI-TEST-001 LOW — module directory has no .tftest.hcl files

variable "project_id" {
  type = string
}

resource "google_storage_bucket" "test" {
  name     = var.project_id
  location = "US"
}
