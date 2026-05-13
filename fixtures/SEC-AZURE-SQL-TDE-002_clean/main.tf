# Auto-generated clean fixture for SEC-AZURE-SQL-TDE-002.
# Azure SQL transparent data encryption uses service-managed key (no CMK)
# This is a CORRECT configuration; SEC-AZURE-SQL-TDE-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_mssql_server_transparent_data_encryption" "tde" {
  server_id        = azurerm_mssql_server.example.id
  key_vault_key_id = azurerm_key_vault_key.tde.id
}
