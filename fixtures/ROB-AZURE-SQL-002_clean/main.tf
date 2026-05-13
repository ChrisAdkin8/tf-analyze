# Auto-generated clean fixture for ROB-AZURE-SQL-002.
# Azure SQL database missing long-term retention policy
# This is a CORRECT configuration; ROB-AZURE-SQL-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_mssql_database" "example" {
  name      = "example"
  server_id = azurerm_mssql_server.example.id

  long_term_retention_policy {
    weekly_retention  = "P4W"
    monthly_retention = "P12M"
    yearly_retention  = "P7Y"
    week_of_year      = 1
  }
}
