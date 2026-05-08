# Auto-generated clean fixture for STK-GCP-DEPRECATION-001.
# Resource uses deprecated argument
# This is a CORRECT configuration; STK-GCP-DEPRECATION-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_container_cluster" "app" {
  # Remove deprecated enable_legacy_abac — ABAC is disabled by default
  # Remove deprecated logging_service / monitoring_service — use blocks instead
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }
  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
  }
}

resource "google_compute_instance" "app" {
  metadata = {
    "startup-script" = file("${path.module}/startup.sh")
  }
  # Remove deprecated metadata_startup_script argument
}
