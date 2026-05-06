# Expected findings:
#   SEC-GCP-REDIS-001  HIGH  auth_enabled missing (defaults to false)

resource "google_redis_instance" "no_auth" {
  name           = "demo-no-auth"
  memory_size_gb = 1
  region         = "us-central1"

  # transit_encryption_mode present and correct — SEC-GCP-REDIS-002 does NOT fire
  transit_encryption_mode = "SERVER_AUTHENTICATION"

  # auth_enabled intentionally omitted — defaults to false
}
