# Auto-generated clean fixture for SEC-AZURE-WEBAPP-002.
# App Service / Function App HTTPS not enforced
# This is a CORRECT configuration; SEC-AZURE-WEBAPP-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_linux_web_app" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id
  https_only          = true
  site_config {}
}
