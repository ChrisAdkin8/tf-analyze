# Auto-generated clean fixture for SEC-AZURE-FRONTDOOR-001.
# Azure Front Door profile missing WAF policy attachment
# This is a CORRECT configuration; SEC-AZURE-FRONTDOOR-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_cdn_frontdoor_firewall_policy" "example" {
  name                = "example-waf"
  resource_group_name = azurerm_resource_group.example.name
  sku_name            = "Premium_AzureFrontDoor"
  enabled             = true
  mode                = "Prevention"
  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = "2.1"
    action  = "Block"
  }
}
