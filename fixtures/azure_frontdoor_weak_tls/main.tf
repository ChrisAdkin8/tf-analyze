# Expected findings:
#  - SEC-AZURE-FRONTDOOR-002 HIGH — TLS10 on Front Door custom domain

resource "azurerm_cdn_frontdoor_custom_domain" "weak" {
  name                     = "legacy"
  cdn_frontdoor_profile_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Cdn/profiles/edge"
  host_name                = "legacy.example.com"

  tls {
    minimum_tls_version = "TLS10"
  }
}
