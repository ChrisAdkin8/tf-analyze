# Expected findings:
#  - SEC-AZURE-STORAGE-002 HIGH — allow_nested_items_to_be_public = true

resource "azurerm_storage_account" "public_blobs" {
  name                     = "publicblobstorage"
  resource_group_name      = "example-rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = true
}
