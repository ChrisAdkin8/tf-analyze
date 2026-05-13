# Expected findings:
#  - STK-AZURE-RECOVERY-001 HIGH — soft_delete_enabled = false

resource "azurerm_recovery_services_vault" "vault" {
  name                = "backup-vault"
  location            = "eastus"
  resource_group_name = "rg-main"
  sku                 = "Standard"
  soft_delete_enabled = false
}
