resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

resource "azurerm_mssql_server" "main" {
  name                         = "sql-main"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "PlaceholderP@ss1"
}

# Firewall rule allowing all IPs — any machine on the internet can
# attempt to connect to the SQL endpoint.
resource "azurerm_mssql_firewall_rule" "allow_all" {
  name             = "allow-all"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}
