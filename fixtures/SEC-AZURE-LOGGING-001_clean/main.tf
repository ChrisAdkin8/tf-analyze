resource "azurerm_resource_group" "example" {
  name     = "example-rg"
  location = "East US"
}

resource "azurerm_storage_account" "diag" {
  name                     = "diagstorage"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_monitor_diagnostic_setting" "example" {
  name               = "example"
  target_resource_id = azurerm_resource_group.example.id
  storage_account_id = azurerm_storage_account.diag.id

  log {
    category = "Administrative"
    enabled  = true
  }
}
