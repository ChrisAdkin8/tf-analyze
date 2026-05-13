# Expected findings:
#  - STK-AZURE-LOGIC-APP-001 MEDIUM — no diagnostic_setting bound

resource "azurerm_logic_app_workflow" "main" {
  name                = "etl"
  location            = "eastus"
  resource_group_name = "rg-main"
}
