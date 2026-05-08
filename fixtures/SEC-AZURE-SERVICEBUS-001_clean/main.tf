# Auto-generated clean fixture for SEC-AZURE-SERVICEBUS-001.
# Service Bus namespace does not use CMK encryption
# This is a CORRECT configuration; SEC-AZURE-SERVICEBUS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_servicebus_namespace" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Premium"
  identity {
    type = "SystemAssigned"
  }
  customer_managed_key {
    key_vault_key_id = azurerm_key_vault_key.example.id
    infrastructure_encryption_enabled = true
  }
}
