# Auto-generated clean fixture for SEC-AZURE-COSMOS-001.
# Azure Cosmos DB account allows public network access
# This is a CORRECT configuration; SEC-AZURE-COSMOS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_cosmosdb_account" "example" {
  name                          = "example"
  location                      = azurerm_resource_group.example.location
  resource_group_name           = azurerm_resource_group.example.name
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  public_network_access_enabled = false
  consistency_policy { consistency_level = "Session" }
  geo_location {
    location          = azurerm_resource_group.example.location
    failover_priority = 0
  }
}
