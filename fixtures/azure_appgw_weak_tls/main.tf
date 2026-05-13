# Expected findings:
#  - SEC-AZURE-APPGW-002 HIGH — min_protocol_version = TLSv1_0

resource "azurerm_application_gateway" "weak_tls" {
  name                = "weak-tls"
  resource_group_name = "rg-main"
  location            = "eastus"

  sku {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 2
  }

  ssl_policy {
    policy_type          = "Custom"
    min_protocol_version = "TLSv1_0"
  }
}
