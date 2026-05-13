# Expected findings:
#  - STK-AZURE-EVENT-GRID-001 MEDIUM — no identity block

resource "azurerm_eventgrid_topic" "main" {
  name                = "events"
  location            = "eastus"
  resource_group_name = "rg-main"
}
