# Expected findings:
#  - SEC-AZURE-FRONTDOOR-001 HIGH — Front Door profile without WAF policy

resource "azurerm_cdn_frontdoor_profile" "main" {
  name                = "edge"
  resource_group_name = "rg-main"
  sku_name            = "Premium_AzureFrontDoor"
}
