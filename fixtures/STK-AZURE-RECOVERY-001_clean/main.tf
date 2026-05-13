# Auto-generated clean fixture for STK-AZURE-RECOVERY-001.
# Azure Recovery Services Vault missing soft-delete protection
# This is a CORRECT configuration; STK-AZURE-RECOVERY-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_recovery_services_vault" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"
  soft_delete_enabled = true
  immutability        = "Unlocked"
}
