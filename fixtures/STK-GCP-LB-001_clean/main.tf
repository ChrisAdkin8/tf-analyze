# Auto-generated clean fixture for STK-GCP-LB-001.
# GCP load balancer backend service has logging disabled
# This is a CORRECT configuration; STK-GCP-LB-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_backend_service" "example" {
  name                  = "example"
  protocol              = "HTTPS"
  port_name             = "https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  log_config {
    enable      = true
    sample_rate = 1.0
  }
}
