# Auto-generated clean fixture for SEC-AZURE-SQL-002.
# Azure SQL Server firewall rule allows access from all IPs
# This is a CORRECT configuration; SEC-AZURE-SQL-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_mssql_firewall_rule" "example" {
  name             = "allow-specific-ip"
  server_id        = azurerm_mssql_server.example.id
  start_ip_address = "203.0.113.10"
  end_ip_address   = "203.0.113.10"
}
