# Expected findings:
#  - SEC-AZURE-DISK-001 MEDIUM — no disk_encryption_set_id (CMK)

resource "azurerm_managed_disk" "main" {
  name                 = "data-disk"
  location             = "eastus"
  resource_group_name  = "rg-main"
  storage_account_type = "Premium_LRS"
  create_option        = "Empty"
  disk_size_gb         = 64
  # No disk_encryption_set_id -- platform-managed key only.
}
