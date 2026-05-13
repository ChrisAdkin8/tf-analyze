# Expected findings:
#  - STK-GCP-LB-002 HIGH — no ssl_policy attached (default permits TLS 1.0)

resource "google_compute_target_https_proxy" "no_policy" {
  name             = "app-https-proxy"
  url_map          = "projects/example/global/urlMaps/app"
  ssl_certificates = ["projects/example/global/sslCertificates/app"]
  # No ssl_policy -- defaults to COMPATIBLE profile.
}
