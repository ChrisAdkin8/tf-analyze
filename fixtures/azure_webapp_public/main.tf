# Expected findings:
#  - SEC-AZURE-WEBAPP-001 MEDIUM — no ip_restriction in site_config

resource "azurerm_linux_web_app" "public" {
  name                = "public-webapp"
  resource_group_name = "example-rg"
  location            = "eastus"
  service_plan_id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/example-rg/providers/Microsoft.Web/serverFarms/example-plan"

  site_config {}
}
