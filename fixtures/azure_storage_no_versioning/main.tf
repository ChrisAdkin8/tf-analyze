resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

resource "azurerm_storage_account" "no_versioning" {
  name                            = "demonoversioning1234"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  # blob_properties block absent — versioning off, overwrites are permanent
}
