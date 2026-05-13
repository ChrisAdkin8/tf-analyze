# Expected findings:
#  - STK-AZURE-DATA-FACTORY-001 MEDIUM — no managed_virtual_network_enabled

resource "azurerm_data_factory" "main" {
  name                = "etl"
  resource_group_name = "rg-main"
  location            = "eastus"
}
