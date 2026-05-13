# Expected findings:
#  - ROB-AZURE-SQL-002 MEDIUM — no long_term_retention_policy

resource "azurerm_mssql_database" "no_ltr" {
  name           = "app-db"
  server_id      = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Sql/servers/sql-main"
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  sku_name       = "S0"
  max_size_gb    = 250
  # No long_term_retention_policy block.
}
