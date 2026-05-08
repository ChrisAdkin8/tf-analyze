# Auto-generated clean fixture for SEC-AZURE-RBAC-001.
# Azure role assignment scope is subscription-wide
# This is a CORRECT configuration; SEC-AZURE-RBAC-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_role_assignment" "example" {
  scope                = azurerm_resource_group.example.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.example.principal_id
}
