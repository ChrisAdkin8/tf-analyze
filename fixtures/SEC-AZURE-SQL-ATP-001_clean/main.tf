# Auto-generated clean fixture for SEC-AZURE-SQL-ATP-001.
# Azure SQL Server missing advanced threat protection
# This is a CORRECT configuration; SEC-AZURE-SQL-ATP-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name  = azurerm_resource_group.example.name
  server_name          = azurerm_mssql_server.example.name
  state                = "Enabled"
  email_account_admins = true
  retention_days       = 90
}
