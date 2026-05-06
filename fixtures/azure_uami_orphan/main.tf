resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

# UAMI defined but never referenced in any azurerm_role_assignment.principal_id
resource "azurerm_user_assigned_identity" "orphan" {
  name                = "id-app"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
}
