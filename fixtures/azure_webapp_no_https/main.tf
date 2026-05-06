resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

resource "azurerm_service_plan" "main" {
  name                = "plan-app"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "B1"
}

# Web App without https_only — HTTP requests accepted alongside HTTPS.
resource "azurerm_linux_web_app" "no_https" {
  name                = "app-no-https"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.main.id
  # https_only intentionally absent

  site_config {}
}
