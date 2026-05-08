# Auto-generated clean fixture for STK-GCP-DNS-001.
# Cloud DNS managed zone missing DNSSEC
# This is a CORRECT configuration; STK-GCP-DNS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_dns_managed_zone" "example" {
  name     = "example"
  dns_name = "example.com."
  dnssec_config {
    state = "on"
  }
}
