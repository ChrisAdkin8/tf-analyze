# Auto-generated clean fixture for SEC-AZURE-DATABRICKS-001.
# Azure Databricks workspace publicly accessible (no_public_ip = false)
# This is a CORRECT configuration; SEC-AZURE-DATABRICKS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_databricks_workspace" "example" {
  name                          = "example"
  resource_group_name           = azurerm_resource_group.example.name
  location                      = azurerm_resource_group.example.location
  sku                           = "premium"
  public_network_access_enabled = false
  custom_parameters {
    no_public_ip        = true
    virtual_network_id  = azurerm_virtual_network.example.id
    public_subnet_name  = azurerm_subnet.public.name
    private_subnet_name = azurerm_subnet.private.name
  }
}
