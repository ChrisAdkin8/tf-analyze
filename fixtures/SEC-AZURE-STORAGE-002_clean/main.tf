# Auto-generated clean fixture for SEC-AZURE-STORAGE-002.
# Azure storage account allows public blob access
# This is a CORRECT configuration; SEC-AZURE-STORAGE-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_storage_account" "example" {
  # ... other arguments ...
  allow_nested_items_to_be_public = false
}
