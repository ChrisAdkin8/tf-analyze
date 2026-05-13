# Auto-generated clean fixture for STK-GCP-MEMCACHE-001.
# GCP Memorystore Memcache missing maintenance policy
# This is a CORRECT configuration; STK-GCP-MEMCACHE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_memcache_instance" "example" {
  name           = "example"
  region         = "us-central1"
  node_count     = 1
  node_config {
    cpu_count      = 1
    memory_size_mb = 1024
  }
  maintenance_policy {
    weekly_maintenance_window {
      day      = "SUNDAY"
      duration = "10800s"
      start_time {
        hours = 3
      }
    }
  }
}
