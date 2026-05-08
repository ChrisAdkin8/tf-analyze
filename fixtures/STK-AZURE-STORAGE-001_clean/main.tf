# Auto-generated clean fixture for STK-AZURE-STORAGE-001.
# Azure storage account missing blob versioning
# This is a CORRECT configuration; STK-AZURE-STORAGE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_storage_account" "example" {
  name                     = "example"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  blob_properties {
    versioning_enabled = true
  }
}
