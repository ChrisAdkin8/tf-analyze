# Auto-generated clean fixture for SEC-GCP-IAP-001.
# GCP backend service missing Identity-Aware Proxy (IAP)
# This is a CORRECT configuration; SEC-GCP-IAP-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_backend_service" "example" {
  name                  = "example"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  iap {
    enabled              = true
    oauth2_client_id     = google_iap_client.example.client_id
    oauth2_client_secret = google_iap_client.example.secret
  }
}
