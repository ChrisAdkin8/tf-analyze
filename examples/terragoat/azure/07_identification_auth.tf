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
#   - SEC-AZURE-WEBAPP-001  HIGH    Web App using storage account key in app_settings
#   - SEC-AZURE-WEBAPP-002  HIGH    Web App HTTPS not enforced (https_only absent)
#   - SEC-AZURE-SQL-001     HIGH    SQL Server without Entra ID administrator
#   - SEC-AZURE-VM-001      HIGH    Linux VM allows SSH password authentication
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

# Linux VM with password authentication enabled — SEC-AZURE-VM-001.
resource "azurerm_linux_virtual_machine" "password_auth" {
  name                            = "demo-password-auth"
  resource_group_name             = azurerm_resource_group.demo.name
  location                        = azurerm_resource_group.demo.location
  size                            = "Standard_B1s"
  admin_username                  = "azureuser"
  disable_password_authentication = false
  admin_password                  = "DemoP@ssw0rd123!"
  network_interface_ids           = []

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}
