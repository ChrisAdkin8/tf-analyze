# Expected findings:
#  - STK-GCP-MIG-002 LOW — no google_compute_autoscaler bound

resource "google_compute_instance_group_manager" "fixed" {
  name               = "app-mig"
  base_instance_name = "app"
  zone               = "us-central1-a"
  target_size        = 3
  version {
    instance_template = "projects/example/zones/us-central1-a/instanceTemplates/app-tpl"
  }
  auto_healing_policies {
    health_check      = "projects/example/global/healthChecks/app-hc"
    initial_delay_sec = 300
  }
}
