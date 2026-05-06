# Expected findings:
#  - SEC-AZURE-STORAGE-001 HIGH — https_only = false allows plaintext HTTP

resource "azurerm_storage_account" "insecure" {
  name                     = "insecurestorage"
  resource_group_name      = "example-rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  https_only      = false
  min_tls_version = "TLS1_1"
}
