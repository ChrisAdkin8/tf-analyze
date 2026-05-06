# Expected findings:
#   SEC-GCP-REDIS-002  HIGH  transit_encryption_mode missing (defaults to DISABLED)

resource "google_redis_instance" "no_tls" {
  name           = "demo-no-tls"
  memory_size_gb = 1
  region         = "us-central1"

  # auth_enabled present and correct — SEC-GCP-REDIS-001 does NOT fire
  auth_enabled = true

  # transit_encryption_mode intentionally omitted — defaults to DISABLED
}
