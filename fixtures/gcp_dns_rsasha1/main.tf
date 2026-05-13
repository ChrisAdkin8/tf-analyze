# Expected findings:
#  - STK-GCP-DNS-002 LOW — algorithm = rsasha1

resource "google_dns_managed_zone" "weak" {
  name     = "weak"
  dns_name = "weak.example.com."
  dnssec_config {
    state = "on"
    default_key_specs {
      algorithm  = "rsasha1"
      key_type   = "zoneSigning"
      key_length = 1024
    }
  }
}
