# OWASP A08:2021 — Software and Data Integrity Failures
# Cloud: Azure
#
# Three Azure-shaped integrity failures:
#
#   1. Storage account containers without versioning or soft delete.
#      Object overwrite or `terraform destroy` is unrecoverable.
#   2. Storage account without `blob_properties.delete_retention_policy`
#      — soft delete off; deletes are immediate and permanent.
#   3. SQL Database without `short_term_retention_policy` configured
#      — point-in-time recovery is disabled.
#
# Real-world impact:
#   - Many ransomware playbooks specifically target storage soft-
#     delete and immutability features as a precursor to encrypting
#     data.
#   - SQL databases without retention policies have no recovery path
#     after malicious data corruption is discovered hours / days
#     after the event.
#
# Expected tf-analyze findings:
#   - STK-AZURE-SQL-TDE-001  HIGH  SQL DB missing transparent data encryption resource
#   - ROB-AZURE-SQL-001      HIGH  SQL Database without lifecycle.prevent_destroy
#
# Fix summary: turn on `versioning_enabled = true` plus a
# `delete_retention_policy { days = 7 }` on every storage account;
# configure short-term retention policy on every SQL DB.

# Storage account without versioning / soft delete.
resource "azurerm_storage_account" "no_soft_delete" {
  name                            = "demonosoftdelete1234"
  resource_group_name             = azurerm_resource_group.demo.name
  location                        = azurerm_resource_group.demo.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false

  # blob_properties block intentionally omitted — versioning off,
  # soft delete off, delete is permanent.
}

# SQL Database without short-term retention policy.
resource "azurerm_mssql_database" "no_retention" {
  name      = "demo-noretention"
  server_id = azurerm_mssql_server.sql_only.id
  sku_name  = "Basic"
  # No short_term_retention_policy block.
}
