# Expected findings:
#  - SEC-AZURE-APPGW-001 HIGH — no firewall_policy_id

resource "azurerm_application_gateway" "no_waf" {
  name                = "no-waf"
  resource_group_name = "rg-main"
  location            = "eastus"

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
  # No firewall_policy_id.
}
