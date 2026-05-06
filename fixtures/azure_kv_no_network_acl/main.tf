resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

# Key Vault without network_acls — accepts requests from any public IP.
resource "azurerm_key_vault" "open" {
  name                = "kv-open"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
  # network_acls block absent — default_action is effectively "Allow"
}
