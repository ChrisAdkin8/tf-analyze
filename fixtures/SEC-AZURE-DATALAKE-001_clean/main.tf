# Auto-generated clean fixture for SEC-AZURE-DATALAKE-001.
# Azure Data Lake Gen 2 filesystem missing encryption scope
# This is a CORRECT configuration; SEC-AZURE-DATALAKE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_storage_data_lake_gen2_filesystem" "example" {
  name                     = "example"
  storage_account_id       = azurerm_storage_account.example.id
  default_encryption_scope = azurerm_storage_encryption_scope.example.name
}
