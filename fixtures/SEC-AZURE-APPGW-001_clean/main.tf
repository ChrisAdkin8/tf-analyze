# Auto-generated clean fixture for SEC-AZURE-APPGW-001.
# Azure Application Gateway has no WAF policy attached
# This is a CORRECT configuration; SEC-AZURE-APPGW-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_application_gateway" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 2
  }
  firewall_policy_id = azurerm_web_application_firewall_policy.example.id
}
