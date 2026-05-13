# Auto-generated clean fixture for STK-GCP-MIG-001.
# GCP managed instance group missing auto-healing
# This is a CORRECT configuration; STK-GCP-MIG-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_instance_group_manager" "example" {
  name               = "example"
  base_instance_name = "example"
  zone               = "us-central1-a"
  target_size        = 3

  version {
    instance_template = google_compute_instance_template.example.id
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.example.id
    initial_delay_sec = 300
  }
}
