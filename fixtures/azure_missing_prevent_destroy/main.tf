# Expected findings:
#  - ROB-AZURE-LIFECYCLE-001 HIGH — azurerm_mssql_database missing lifecycle.prevent_destroy
#  - ROB-AZURE-LIFECYCLE-001 HIGH — azurerm_storage_account missing lifecycle.prevent_destroy
#  - ROB-AZURE-LIFECYCLE-001 HIGH — azurerm_key_vault missing lifecycle.prevent_destroy

resource "azurerm_mssql_database" "app" {
  name      = "app-db"
  server_id = azurerm_mssql_server.main.id
  sku_name  = "S1"

  # No lifecycle block — database can be accidentally destroyed.
}

resource "azurerm_storage_account" "data" {
  name                     = "mystorageaccount"
  resource_group_name      = "my-rg"
  location                 = "East US"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # No lifecycle block.
}

resource "azurerm_key_vault" "secrets" {
  name                = "my-kv"
  location            = "East US"
  resource_group_name = "my-rg"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"

  # No lifecycle block.
}
