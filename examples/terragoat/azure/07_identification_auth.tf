# OWASP A07:2021 — Identification and Authentication Failures
# Cloud: Azure
#
# Three Azure auth-failure shapes:
#
#   1. Storage Account access via account key (or SAS token) instead
#      of Managed Identity + RBAC. Account keys are long-lived,
#      shared, and embedded in app config; an MI + RBAC binding is
#      short-lived and per-workload.
#   2. SQL Server with `azuread_administrator` not configured —
#      authentication is SQL-only, no Entra ID integration, password
#      rotation manual.
#   3. App Service / Function App without a User-Assigned Managed
#      Identity attached, falling back to the System-Assigned
#      identity (which is fine but harder to grant narrowly across
#      multiple workloads).
#
# Real-world impact:
#   - Storage account keys leak in app config files routinely;
#     they grant full control of the account (read/write/delete
#     every blob).
#   - SQL servers without Entra integration force shared SQL logins,
#     which become single-points-of-compromise.
#
# Expected tf-analyze findings:
#   - SEC-AZURE-MI-001  MEDIUM   Azure user-assigned identity grants without explicit scope (stub)
#
# Fix summary: use Managed Identity + RBAC for storage access; configure
# `azuread_administrator` on every SQL Server; one UAMI per workload
# with explicit role bindings on its target resources.

# Web App using account key — should be MI + RBAC.
resource "azurerm_storage_account" "for_app" {
  name                            = "demoforappstorage1234"
  resource_group_name             = azurerm_resource_group.demo.name
  location                        = azurerm_resource_group.demo.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
}

resource "azurerm_service_plan" "auth_plan" {
  name                = "demo-auth-plan"
  resource_group_name = azurerm_resource_group.demo.name
  location            = azurerm_resource_group.demo.location
  os_type             = "Linux"
  sku_name            = "B1"
}

resource "azurerm_linux_web_app" "key_based" {
  name                = "demo-keybased-webapp"
  resource_group_name = azurerm_resource_group.demo.name
  location            = azurerm_resource_group.demo.location
  service_plan_id     = azurerm_service_plan.auth_plan.id

  site_config {
    application_stack {
      docker_image     = "mcr.microsoft.com/appsvc/staticsite:latest"
      docker_image_tag = "latest"
    }
  }

  app_settings = {
    # Storage account key in app settings — long-lived, shared,
    # routinely leaks in support tickets.
    AZURE_STORAGE_KEY = azurerm_storage_account.for_app.primary_access_key
  }
}

# SQL Server without Entra ID admin configured.
resource "azurerm_mssql_server" "sql_only" {
  name                         = "demo-sql-only"
  resource_group_name          = azurerm_resource_group.demo.name
  location                     = azurerm_resource_group.demo.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "ShouldBeKVRef!123"
  # No azuread_administrator block.
}
