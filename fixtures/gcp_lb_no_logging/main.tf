# Expected findings:
#  - STK-GCP-LB-001 MEDIUM — no log_config

resource "google_compute_backend_service" "no_logs" {
  name                  = "app-backend"
  protocol              = "HTTPS"
  port_name             = "https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 30
  # No log_config -- access logs not shipped.
}
