# Auto-generated clean fixture for STK-AZURE-WEBAPP-RUNTIME-001.
# Azure App Service Web App uses end-of-life runtime
# This is a CORRECT configuration; STK-AZURE-WEBAPP-RUNTIME-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_linux_web_app" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id
  site_config {
    application_stack {
      python_version = "3.12"
    }
  }
}
