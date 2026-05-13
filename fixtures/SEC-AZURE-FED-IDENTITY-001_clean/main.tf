# Auto-generated clean fixture for SEC-AZURE-FED-IDENTITY-001.
# Azure federated identity credential accepts wildcard subject claim
# This is a CORRECT configuration; SEC-AZURE-FED-IDENTITY-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_federated_identity_credential" "github" {
  name                = "github-main"
  resource_group_name = azurerm_resource_group.main.name
  parent_id           = azurerm_user_assigned_identity.gh.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = "repo:my-org/my-repo:ref:refs/heads/main"
}
