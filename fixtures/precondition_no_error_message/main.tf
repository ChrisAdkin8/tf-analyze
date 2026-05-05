# Expected findings:
#  - ROB-PRECONDITION-001 MEDIUM — precondition missing error_message

variable "environment" {
  type = string
}

resource "google_storage_bucket" "data" {
  name                        = "data"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  lifecycle {
    precondition {
      condition = var.environment != "prod" || true
      # error_message intentionally omitted — should fire ROB-PRECONDITION-001
    }
    prevent_destroy = true
  }
}
