# Expected findings:
#  - SEC-AZURE-SERVICEBUS-001 MEDIUM — no CMK encryption

resource "azurerm_servicebus_namespace" "main" {
  name                = "main"
  resource_group_name = "rg-main"
  location            = "eastus"
  sku                 = "Premium"
  # No customer_managed_key block
}
