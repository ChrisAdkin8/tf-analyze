# Expected findings:
#  - STK-GCP-MIG-001 MEDIUM — no auto_healing_policies

resource "google_compute_instance_group_manager" "no_heal" {
  name               = "app-mig"
  base_instance_name = "app"
  zone               = "us-central1-a"
  target_size        = 3
  version {
    instance_template = "projects/example/zones/us-central1-a/instanceTemplates/app-tpl"
  }
}
