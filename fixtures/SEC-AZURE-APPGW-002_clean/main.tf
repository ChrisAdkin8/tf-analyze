# Auto-generated clean fixture for SEC-AZURE-APPGW-002.
# Azure Application Gateway uses weak TLS policy
# This is a CORRECT configuration; SEC-AZURE-APPGW-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_application_gateway" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 2
  }
  ssl_policy {
    policy_type          = "Predefined"
    policy_name          = "AppGwSslPolicy20220101S"
    min_protocol_version = "TLSv1_2"
  }
}
