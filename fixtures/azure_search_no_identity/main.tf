# Expected findings:
#  - STK-AZURE-SEARCH-001 MEDIUM — no identity block

resource "azurerm_search_service" "no_id" {
  name                = "search-svc"
  resource_group_name = "rg-main"
  location            = "eastus"
  sku                 = "standard"
}
