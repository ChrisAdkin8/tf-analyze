# Expected findings:
#  - STK-AZURE-FUNCTION-AUTH-001 HIGH — no auth_settings_v2

resource "azurerm_linux_function_app" "no_auth" {
  name                       = "open-api"
  resource_group_name        = "rg-main"
  location                   = "eastus"
  service_plan_id            = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Web/serverfarms/asp"
  storage_account_name       = "fnstoragemain"
  storage_account_access_key = "REDACTED"

  site_config {
    application_insights_key = "REDACTED"
  }
}
