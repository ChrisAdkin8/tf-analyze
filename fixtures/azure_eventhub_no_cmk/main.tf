# Expected findings:
#  - SEC-AZURE-EVENTHUB-001 MEDIUM — no CMK encryption

resource "azurerm_eventhub_namespace" "main" {
  name                = "main"
  resource_group_name = "rg-main"
  location            = "eastus"
  sku                 = "Premium"
  capacity            = 1
  # No customer_managed_key block
}
