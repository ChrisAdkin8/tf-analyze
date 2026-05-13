# Expected findings:
#  - SEC-AZURE-FED-IDENTITY-001 CRITICAL — wildcard in subject claim

resource "azurerm_federated_identity_credential" "any_repo" {
  name                = "any-repo"
  resource_group_name = "rg-main"
  parent_id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.ManagedIdentity/userAssignedIdentities/gh-ci"
  audience            = ["api://AzureADTokenExchange"]
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = "repo:my-org/*:ref:refs/heads/main"
}
