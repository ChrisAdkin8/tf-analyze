# Expected findings:
#  - OPS-AZURE-TAGS-001 MEDIUM — azurerm_resource_group missing tags
#  - OPS-AZURE-TAGS-001 MEDIUM — azurerm_storage_account missing tags

resource "azurerm_resource_group" "no_tags" {
  name     = "example-rg"
  location = "eastus"
}

resource "azurerm_storage_account" "no_tags" {
  name                     = "nottaggedstorage"
  resource_group_name      = azurerm_resource_group.no_tags.name
  location                 = azurerm_resource_group.no_tags.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
