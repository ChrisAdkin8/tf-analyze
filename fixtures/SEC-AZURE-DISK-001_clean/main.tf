# Auto-generated clean fixture for SEC-AZURE-DISK-001.
# Azure managed disk not encrypted with customer-managed key
# This is a CORRECT configuration; SEC-AZURE-DISK-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_managed_disk" "example" {
  name                   = "example"
  location               = azurerm_resource_group.example.location
  resource_group_name    = azurerm_resource_group.example.name
  storage_account_type   = "Standard_LRS"
  create_option          = "Empty"
  disk_size_gb           = 32
  disk_encryption_set_id = azurerm_disk_encryption_set.example.id
}
