# Auto-generated clean fixture for SEC-AZURE-DATABRICKS-002.
# Azure Databricks workspace missing customer-managed key (DBFS)
# This is a CORRECT configuration; SEC-AZURE-DATABRICKS-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_databricks_workspace" "example" {
  name                         = "example"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  sku                          = "premium"
  customer_managed_key_enabled = true
}
