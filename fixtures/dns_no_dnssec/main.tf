# Expected findings:
#  - STK-GCP-DNS-001 HIGH — Cloud DNS managed zone missing dnssec_config.state

resource "google_dns_managed_zone" "no_dnssec" {
  name     = "no-dnssec"
  dns_name = "example.com."

  # No dnssec_config block — DNSSEC disabled.
}
