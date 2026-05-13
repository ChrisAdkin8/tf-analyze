# Auto-generated clean fixture for SEC-GCP-SECRET-001.
# GCP Secret Manager secret has no rotation configured
# This is a CORRECT configuration; SEC-GCP-SECRET-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_secret_manager_secret" "example" {
  secret_id = "db-pw"
  replication { auto {} }
  topics { name = "projects/example/topics/secret-rotator" }
  rotation {
    next_rotation_time = "2026-07-01T00:00:00Z"
    rotation_period    = "2592000s"
  }
}
