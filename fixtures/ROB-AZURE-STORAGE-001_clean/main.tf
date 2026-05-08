# Auto-generated clean fixture for ROB-AZURE-STORAGE-001.
# Azure storage account missing blob soft delete
# This is a CORRECT configuration; ROB-AZURE-STORAGE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_storage_account" "example" {
  name                     = "example"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  blob_properties {
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }
}
