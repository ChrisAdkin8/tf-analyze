# Auto-generated clean fixture for STK-AZURE-EVENT-GRID-002.
# Azure Event Grid event subscription missing dead-letter destination
# This is a CORRECT configuration; STK-AZURE-EVENT-GRID-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_eventgrid_event_subscription" "example" {
  name  = "example"
  scope = azurerm_eventgrid_topic.example.id
  webhook_endpoint {
    url = "https://example.com/webhook"
  }
  storage_blob_dead_letter_destination {
    storage_account_id          = azurerm_storage_account.dlq.id
    storage_blob_container_name = "dlq"
  }
  retry_policy {
    max_delivery_attempts = 30
    event_time_to_live    = 1440
  }
}
