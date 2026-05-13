# Expected findings:
#  - ROB-AZURE-COSMOS-002 MEDIUM — automatic_failover_enabled = false

resource "azurerm_cosmosdb_account" "no_failover" {
  name                       = "ha-cosmos"
  location                   = "eastus"
  resource_group_name        = "rg-main"
  offer_type                 = "Standard"
  kind                       = "GlobalDocumentDB"
  automatic_failover_enabled = false

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = "eastus"
    failover_priority = 0
  }
  geo_location {
    location          = "westus2"
    failover_priority = 1
  }
}
