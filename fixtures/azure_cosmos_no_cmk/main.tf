# Expected findings:
#  - SEC-AZURE-COSMOS-002 MEDIUM — no key_vault_key_id (CMK)

resource "azurerm_cosmosdb_account" "main" {
  name                = "main"
  location            = "eastus"
  resource_group_name = "rg-main"
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = "eastus"
    failover_priority = 0
  }
  # No key_vault_key_id -- Microsoft-managed key only.
}
