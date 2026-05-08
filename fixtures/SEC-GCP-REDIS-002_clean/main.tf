# Auto-generated clean fixture for SEC-GCP-REDIS-002.
# Cloud Memorystore Redis instance transit encryption disabled
# This is a CORRECT configuration; SEC-GCP-REDIS-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_redis_instance" "example" {
  # ... other arguments ...
  transit_encryption_mode = "SERVER_AUTHENTICATION"
}
