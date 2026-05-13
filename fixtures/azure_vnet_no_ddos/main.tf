# Expected findings:
#  - SEC-AZURE-DDOS-001 MEDIUM — no ddos_protection_plan

resource "azurerm_virtual_network" "main" {
  name                = "vnet-main"
  location            = "eastus"
  resource_group_name = "rg-main"
  address_space       = ["10.0.0.0/16"]
}
