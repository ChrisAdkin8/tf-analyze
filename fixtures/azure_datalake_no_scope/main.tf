# Expected findings:
#  - SEC-AZURE-DATALAKE-001 MEDIUM — no default_encryption_scope

resource "azurerm_storage_data_lake_gen2_filesystem" "raw" {
  name               = "raw"
  storage_account_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Storage/storageAccounts/lake"
}
