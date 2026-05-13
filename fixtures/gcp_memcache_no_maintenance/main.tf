# Expected findings:
#  - STK-GCP-MEMCACHE-001 LOW — no maintenance_policy

resource "google_memcache_instance" "no_maint" {
  name       = "session-cache"
  region     = "us-central1"
  node_count = 1
  node_config {
    cpu_count      = 1
    memory_size_mb = 1024
  }
}
