resource "azurerm_mssql_server" "main" {
  name                          = "acme-sql"
  resource_group_name           = "rg-data"
  location                      = "uksouth"
  version                       = "12.0"
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false

  azuread_administrator {
    login_username              = "sql-admins"
    object_id                   = "00000000-0000-0000-0000-000000000000"
    azuread_authentication_only = true
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_mssql_database" "app" {
  name      = "app"
  server_id = azurerm_mssql_server.main.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_mssql_server_extended_auditing_policy" "main" {
  server_id              = azurerm_mssql_server.main.id
  log_monitoring_enabled = true
}

resource "azurerm_mssql_server_security_alert_policy" "main" {
  resource_group_name = "rg-data"
  server_name         = azurerm_mssql_server.main.name
  state               = "Enabled"
}

resource "azurerm_mssql_server_vulnerability_assessment" "main" {
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.main.id
  storage_container_path          = "https://acmesqlva.blob.core.windows.net/va/"

  recurring_scans {
    enabled = true
  }
}
