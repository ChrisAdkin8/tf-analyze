# Expected findings:
#  - SEC-AZURE-APIM-001 MEDIUM — no azurerm_api_management_diagnostic

resource "azurerm_api_management" "main" {
  name                = "api-mgmt"
  location            = "eastus"
  resource_group_name = "rg-main"
  publisher_name      = "Example"
  publisher_email     = "ops@example.com"
  sku_name            = "Developer_1"
}
