# Expected findings:
#  - ROB-AZURE-STORAGE-001 MEDIUM — no blob_properties block (soft delete missing)

resource "azurerm_storage_account" "no_soft_delete" {
  name                     = "nosoftdeletestorage"
  resource_group_name      = "example-rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  https_only      = true
  min_tls_version = "TLS1_2"
}
