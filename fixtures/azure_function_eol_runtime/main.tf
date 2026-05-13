# Expected findings:
#  - STK-AZURE-FUNCTION-001 HIGH — python_version = "3.7" (EOL)

resource "azurerm_linux_function_app" "eol" {
  name                       = "eol-fn"
  resource_group_name        = "rg-main"
  location                   = "eastus"
  service_plan_id            = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Web/serverfarms/asp-main"
  storage_account_name       = "fnstoragemain"
  storage_account_access_key = "REDACTED"

  site_config {
    application_stack {
      python_version = "3.7"
    }
  }
}
