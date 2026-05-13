# Expected findings:
#  - SEC-GCP-IAP-001 MEDIUM — no iap block

resource "google_compute_backend_service" "no_iap" {
  name                  = "no-iap"
  protocol              = "HTTPS"
  port_name             = "https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 30
  log_config {
    enable      = true
    sample_rate = 1.0
  }
}
