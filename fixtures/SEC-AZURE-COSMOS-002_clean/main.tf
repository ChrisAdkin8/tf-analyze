# Auto-generated clean fixture for SEC-AZURE-COSMOS-002.
# Azure Cosmos DB account not using customer-managed key
# This is a CORRECT configuration; SEC-AZURE-COSMOS-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_cosmosdb_account" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"
  key_vault_key_id    = azurerm_key_vault_key.example.versionless_id
  identity { type = "SystemAssigned" }
  consistency_policy { consistency_level = "Session" }
  geo_location {
    location          = azurerm_resource_group.example.location
    failover_priority = 0
  }
}
