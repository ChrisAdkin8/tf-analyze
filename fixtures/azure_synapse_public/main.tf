# Expected findings:
#  - SEC-AZURE-SYNAPSE-001 HIGH — public_network_access_enabled = true

resource "azurerm_synapse_workspace" "pub" {
  name                                 = "analytics"
  resource_group_name                  = "rg-main"
  location                             = "eastus"
  storage_data_lake_gen2_filesystem_id = "https://datalake.dfs.core.windows.net/raw"
  sql_administrator_login              = "synapseadmin"
  sql_administrator_login_password     = "REDACTED"
  public_network_access_enabled        = true

  identity {
    type = "SystemAssigned"
  }
}
