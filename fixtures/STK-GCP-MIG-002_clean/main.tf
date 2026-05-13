# Auto-generated clean fixture for STK-GCP-MIG-002.
# GCP managed instance group missing autoscaler
# This is a CORRECT configuration; STK-GCP-MIG-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_autoscaler" "example" {
  name   = "example"
  zone   = "us-central1-a"
  target = google_compute_instance_group_manager.example.id
  autoscaling_policy {
    min_replicas    = 2
    max_replicas    = 20
    cooldown_period = 60
    cpu_utilization {
      target = 0.6
    }
  }
}
