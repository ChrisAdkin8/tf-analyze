# Expected findings:
#  - SEC-AZURE-STORAGE-003 MEDIUM — no customer_managed_key block

resource "azurerm_storage_account" "no_cmk" {
  name                     = "nocmkstorage"
  resource_group_name      = "rg-main"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  https_only               = true
  min_tls_version          = "TLS1_2"
  # No customer_managed_key block.
}
