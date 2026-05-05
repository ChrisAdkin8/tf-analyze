# OWASP A01:2021 — Broken Access Control
# Cloud: Azure
#
# Three Azure-shaped patterns:
#
#   1. `azurerm_role_assignment` with `scope = data.azurerm_subscription
#      .primary.id` — assigns a role at subscription scope, granting
#      authority over every resource in the subscription. The Azure
#      analogue of `roles/owner` at GCP project level.
#   2. Storage account allowing anonymous blob access
#      (`allow_nested_items_to_be_public = true`). Anyone on the
#      internet can read every blob with a public-read access tier.
#   3. Role assignment using the built-in "Owner" role rather than a
#      custom RBAC role with the minimum required actions.
#
# Real-world impact:
#   - 2018 ABTA, 2019 several finance providers: leaked Azure storage
#     accounts with anonymous blob access exposed customer data.
#   - Subscription-scope contributor grants are a routine finding in
#     Azure security reviews — once granted, virtually unreviewable.
#
# Expected tf-analyze findings:
#   - SEC-AZURE-RBAC-001  HIGH   Azure role assignment scope is subscription-wide
#   - (SEC-AZURE-STORAGE-001 currently a stub — anonymous blob access
#    detection is roadmap)
#
# Fix summary: scope every role assignment to a resource group or
# specific resource; disable anonymous blob access at the storage-
# account level (`allow_nested_items_to_be_public = false`); prefer
# narrow custom roles over Owner / Contributor.

data "azurerm_subscription" "primary" {}

# Subscription-scope Contributor — the canonical anti-pattern.
resource "azurerm_role_assignment" "subscription_contributor" {
  scope                = data.azurerm_subscription.primary.id
  role_definition_name = "Contributor"
  principal_id         = "00000000-0000-0000-0000-000000000000"
}

# Storage account allowing public blob access at the account level.
resource "azurerm_storage_account" "anon_blob" {
  name                            = "demoanonblob1234"
  resource_group_name             = azurerm_resource_group.demo.name
  location                        = azurerm_resource_group.demo.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
}

resource "azurerm_storage_container" "public" {
  name                  = "public"
  storage_account_name  = azurerm_storage_account.anon_blob.name
  container_access_type = "blob" # anonymous blob reads
}
