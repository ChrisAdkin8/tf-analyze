# Auto-generated clean fixture for STK-AZURE-FUNCTION-002.
# Azure Function App missing Application Insights instrumentation
# This is a CORRECT configuration; STK-AZURE-FUNCTION-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_linux_function_app" "example" {
  name                       = "example"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  service_plan_id            = azurerm_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

  site_config {
    application_insights_key               = azurerm_application_insights.example.instrumentation_key
    application_insights_connection_string = azurerm_application_insights.example.connection_string
  }
}
