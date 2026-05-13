# Auto-generated clean fixture for STK-GCP-LB-002.
# GCP HTTPS load balancer missing SSL policy (default permits TLS 1.0)
# This is a CORRECT configuration; STK-GCP-LB-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_ssl_policy" "modern" {
  name            = "modern-tls"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_target_https_proxy" "example" {
  name             = "example"
  url_map          = google_compute_url_map.example.id
  ssl_certificates = [google_compute_ssl_certificate.example.id]
  ssl_policy       = google_compute_ssl_policy.modern.id
}
