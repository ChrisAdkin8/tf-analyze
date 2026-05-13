# Auto-generated clean fixture for STK-AZURE-FUNCTION-AUTH-001.
# Azure Function App missing platform-level authentication
# This is a CORRECT configuration; STK-AZURE-FUNCTION-AUTH-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_linux_function_app" "example" {
  name                       = "example"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  service_plan_id            = azurerm_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  site_config {}
  auth_settings_v2 {
    auth_enabled           = true
    require_authentication = true
    default_provider       = "AzureActiveDirectory"
    login {}
  }
}
