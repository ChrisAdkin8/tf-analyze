# Expected findings:
#  - SEC-AZURE-DATABRICKS-002 MEDIUM — no customer_managed_key_enabled

resource "azurerm_databricks_workspace" "no_cmk" {
  name                          = "analytics"
  resource_group_name           = "rg-main"
  location                      = "eastus"
  sku                           = "premium"
  public_network_access_enabled = false
  custom_parameters {
    no_public_ip = true
  }
}
