# Auto-generated clean fixture for SEC-GCP-REDIS-001.
# Cloud Memorystore Redis instance AUTH disabled
# This is a CORRECT configuration; SEC-GCP-REDIS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_redis_instance" "example" {
  # ... other arguments ...
  auth_enabled = true
}
