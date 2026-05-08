# Auto-generated clean fixture for ROB-AZURE-SQL-001.
# Azure SQL database missing short-term backup retention policy
# This is a CORRECT configuration; ROB-AZURE-SQL-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_mssql_database" "example" {
  name      = "example"
  server_id = azurerm_mssql_server.example.id
  short_term_retention_policy {
    retention_days           = 35
    backup_interval_in_hours = 12
  }
}
