# Expected findings:
#  - ROB-AZURE-COSMOS-001 MEDIUM — backup.type = Periodic

resource "azurerm_cosmosdb_account" "periodic" {
  name                = "periodic-cosmos"
  location            = "eastus"
  resource_group_name = "rg-main"
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  backup {
    type                = "Periodic"
    interval_in_minutes = 240
    retention_in_hours  = 24
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = "eastus"
    failover_priority = 0
  }
}
