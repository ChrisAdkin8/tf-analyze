# Expected findings:
#  - SEC-AZURE-ACR-002 MEDIUM — no retention_policy

resource "azurerm_container_registry" "no_retention" {
  name                = "noretentionacr"
  resource_group_name = "rg-main"
  location            = "eastus"
  sku                 = "Premium"
  admin_enabled       = false
  # No retention_policy block.
}
