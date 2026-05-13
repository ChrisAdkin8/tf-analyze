# Auto-generated clean fixture for SEC-AZURE-SYNAPSE-001.
# Azure Synapse workspace permits public network access
# This is a CORRECT configuration; SEC-AZURE-SYNAPSE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_synapse_workspace" "example" {
  name                                 = "example"
  resource_group_name                  = azurerm_resource_group.example.name
  location                             = azurerm_resource_group.example.location
  storage_data_lake_gen2_filesystem_id = azurerm_storage_data_lake_gen2_filesystem.example.id
  sql_administrator_login              = "synapseadmin"
  sql_administrator_login_password     = "REDACTED"
  public_network_access_enabled        = false
  managed_virtual_network_enabled      = true
  identity { type = "SystemAssigned" }
}
