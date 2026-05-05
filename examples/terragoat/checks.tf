# Lifecycle / check / refactor blocks — exercises ROB-CHECK-001,
# ROB-PRECONDITION-001, ROB-MOVED-001, ROB-REMOVED-001.

# ROB-CHECK-001 MEDIUM — empty check block (no assert).
check "placeholder" {
  # TODO: add an assert
}

# ROB-PRECONDITION-001 MEDIUM — precondition without error_message.
variable "environment" {
  type = string
}

resource "google_storage_bucket" "guarded" {
  name                        = "demo-guarded"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  lifecycle {
    precondition {
      condition = var.environment != "prod" || true
      # error_message intentionally omitted
    }
    prevent_destroy = true
  }
}

# ROB-MOVED-001 LOW — stale moved block.
moved {
  from = google_storage_bucket.old_legacy
  to   = google_storage_bucket.guarded
}

# ROB-REMOVED-001 LOW — stale removed block.
removed {
  from = google_storage_bucket.deprecated_audit
  lifecycle {
    destroy = true
  }
}
