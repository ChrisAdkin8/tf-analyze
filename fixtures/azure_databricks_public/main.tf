# Expected findings:
#  - SEC-AZURE-DATABRICKS-001 HIGH — no_public_ip = false

resource "azurerm_databricks_workspace" "pub" {
  name                = "analytics"
  resource_group_name = "rg-main"
  location            = "eastus"
  sku                 = "premium"

  custom_parameters {
    no_public_ip = false
  }
}
