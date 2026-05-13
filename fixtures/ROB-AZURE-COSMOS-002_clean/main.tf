# Auto-generated clean fixture for ROB-AZURE-COSMOS-002.
# Azure Cosmos DB automatic failover disabled
# This is a CORRECT configuration; ROB-AZURE-COSMOS-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_cosmosdb_account" "example" {
  name                       = "example"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  offer_type                 = "Standard"
  kind                       = "GlobalDocumentDB"
  automatic_failover_enabled = true
  consistency_policy { consistency_level = "Session" }
  geo_location {
    location          = azurerm_resource_group.example.location
    failover_priority = 0
  }
  geo_location {
    location          = "westus2"
    failover_priority = 1
  }
}
