# Auto-generated clean fixture for SEC-AZURE-FRONTDOOR-002.
# Azure Front Door custom domain accepts TLS < 1.2
# This is a CORRECT configuration; SEC-AZURE-FRONTDOOR-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_cdn_frontdoor_custom_domain" "example" {
  name                     = "example"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.example.id
  host_name                = "example.com"
  tls {
    minimum_tls_version = "TLS12"
  }
}
