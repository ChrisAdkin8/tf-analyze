resource "azurerm_resource_group" "example" {
  name     = "example-rg"
  location = "East US"
}

resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_password
}

resource "azurerm_mssql_server_azure_ad_administrator" "example" {
  server_id   = azurerm_mssql_server.example.id
  login       = "sqladmin"
  object_id   = var.aad_admin_object_id
  tenant_id   = var.tenant_id

  azuread_authentication_only = true
}
