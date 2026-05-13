# Auto-generated clean fixture for STK-GCP-DNS-002.
# Cloud DNS DNSSEC uses deprecated RSASHA1 algorithm
# This is a CORRECT configuration; STK-GCP-DNS-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_dns_managed_zone" "example" {
  name        = "example"
  dns_name    = "example.com."
  description = "primary"
  dnssec_config {
    state = "on"
    default_key_specs {
      algorithm  = "ecdsap256sha256"
      key_type   = "zoneSigning"
      key_length = 256
    }
  }
}
