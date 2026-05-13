# Expected findings:
#  - SEC-AZURE-COSMOS-001 HIGH — public_network_access_enabled = true

resource "azurerm_cosmosdb_account" "main" {
  name                          = "main"
  location                      = "eastus"
  resource_group_name           = "rg-main"
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  public_network_access_enabled = true

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = "eastus"
    failover_priority = 0
  }
}
