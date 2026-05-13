# Auto-generated clean fixture for SEC-AZURE-STORAGE-004.
# Azure storage account missing diagnostic logging
# This is a CORRECT configuration; SEC-AZURE-STORAGE-004 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_monitor_diagnostic_setting" "sa" {
  name                       = "${azurerm_storage_account.example.name}-diag"
  target_resource_id         = "${azurerm_storage_account.example.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
  enabled_log { category = "StorageRead" }
  enabled_log { category = "StorageWrite" }
  enabled_log { category = "StorageDelete" }
}
