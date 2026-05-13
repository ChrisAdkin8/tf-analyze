# Expected findings:
#  - STK-AZURE-NAT-001 MEDIUM — no diagnostic_setting bound

resource "azurerm_nat_gateway" "main" {
  name                = "nat-main"
  location            = "eastus"
  resource_group_name = "rg-main"
  sku_name            = "Standard"
}
