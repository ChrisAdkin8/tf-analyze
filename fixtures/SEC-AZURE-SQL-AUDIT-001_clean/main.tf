# Auto-generated clean fixture for SEC-AZURE-SQL-AUDIT-001.
# Azure SQL Server missing extended auditing policy
# This is a CORRECT configuration; SEC-AZURE-SQL-AUDIT-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_mssql_server_extended_auditing_policy" "example" {
  server_id              = azurerm_mssql_server.example.id
  log_monitoring_enabled = true
  retention_in_days      = 90
}
