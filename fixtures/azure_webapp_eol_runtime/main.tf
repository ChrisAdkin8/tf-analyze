# Expected findings:
#  - STK-AZURE-WEBAPP-RUNTIME-001 HIGH — php_version = 7.4 (EOL)

resource "azurerm_linux_web_app" "legacy" {
  name                = "legacy-web"
  resource_group_name = "rg-main"
  location            = "eastus"
  service_plan_id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Web/serverfarms/asp"

  site_config {
    application_stack {
      php_version = "7.4"
    }
  }
}
