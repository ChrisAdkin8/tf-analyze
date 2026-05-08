resource "azurerm_resource_group" "example" {
  name     = "example-rg"
  location = "East US"
}

resource "azurerm_network_security_group" "example" {
  name                = "example-nsg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_storage_account" "flow" {
  name                     = "flowlogstorage"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_network_watcher" "example" {
  name                = "example-watcher"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_network_watcher_flow_log" "example" {
  network_watcher_name = azurerm_network_watcher.example.name
  resource_group_name  = azurerm_resource_group.example.name
  name                 = "example-flowlog"

  network_security_group_id = azurerm_network_security_group.example.id
  storage_account_id        = azurerm_storage_account.flow.id
  enabled                   = true

  retention_policy {
    enabled = true
    days    = 7
  }
}
