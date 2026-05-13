# Auto-generated clean fixture for SEC-AZURE-STORAGE-003.
# Azure storage account not using customer-managed key encryption
# This is a CORRECT configuration; SEC-AZURE-STORAGE-003 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_storage_account" "example" {
  name                     = "example"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  identity { type = "SystemAssigned" }
  customer_managed_key {
    key_vault_key_id = azurerm_key_vault_key.example.id
  }
}
