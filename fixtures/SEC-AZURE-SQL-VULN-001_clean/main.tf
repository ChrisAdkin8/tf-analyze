# Auto-generated clean fixture for SEC-AZURE-SQL-VULN-001.
# Azure SQL Server missing vulnerability assessment
# This is a CORRECT configuration; SEC-AZURE-SQL-VULN-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_mssql_server_vulnerability_assessment" "example" {
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.example.id
  storage_container_path          = "${azurerm_storage_account.va.primary_blob_endpoint}vulnerability-assessment/"
  storage_account_access_key      = azurerm_storage_account.va.primary_access_key
  recurring_scans {
    enabled = true
  }
}
