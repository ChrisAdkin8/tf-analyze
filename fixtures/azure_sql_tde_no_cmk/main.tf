# Expected findings:
#  - SEC-AZURE-SQL-TDE-002 MEDIUM — TDE uses service-managed key (no key_vault_key_id)

resource "azurerm_mssql_server_transparent_data_encryption" "tde" {
  server_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Sql/servers/sql-main"
  # No key_vault_key_id -- TDE falls back to ServiceManaged.
}
