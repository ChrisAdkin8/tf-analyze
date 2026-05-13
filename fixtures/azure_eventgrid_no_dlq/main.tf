# Expected findings:
#  - STK-AZURE-EVENT-GRID-002 MEDIUM — no dead-letter destination

resource "azurerm_eventgrid_event_subscription" "subscription" {
  name  = "events-sub"
  scope = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.EventGrid/topics/events"

  webhook_endpoint {
    url = "https://example.com/webhook"
  }
}
