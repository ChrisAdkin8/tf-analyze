# Expected findings:
#  - SEC-AZURE-RBAC-001 HIGH — role assignment scope is subscription-wide

data "azurerm_subscription" "primary" {}

resource "azurerm_role_assignment" "too_broad" {
  scope                = data.azurerm_subscription.primary.id
  role_definition_name = "Contributor"
  principal_id         = "00000000-0000-0000-0000-000000000000"
}
