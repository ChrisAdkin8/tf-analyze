# Expected findings:
#  - STK-AZURE-FUNCTION-002 MEDIUM — no site_config (App Insights wiring)

resource "azurerm_linux_function_app" "no_insights" {
  name                       = "no-insights-fn"
  resource_group_name        = "rg-main"
  location                   = "eastus"
  service_plan_id            = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Web/serverfarms/asp-main"
  storage_account_name       = "fnstoragemain"
  storage_account_access_key = "REDACTED"
  # No site_config block -- App Insights not wired.
}
