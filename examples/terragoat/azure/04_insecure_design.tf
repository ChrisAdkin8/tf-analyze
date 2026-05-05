# OWASP A04:2021 — Insecure Design
# Cloud: Azure
#
# Three Azure design failures:
#
#   1. Hardcoded secrets in HCL (admin_password, connection strings).
#      Same shape as every other cloud — compromised at the moment
#      of the first commit.
#   2. Single User-Assigned Managed Identity (UAMI) used by every
#      VM / Function App / Container App. A compromise of any
#      compute resource inherits the union of every grant.
#   3. SQL Server / Storage Account / Key Vault without
#      `prevent_destroy` — `terraform destroy` against the wrong
#      workspace wipes the data plane.
#
# Real-world impact:
#   - 2017+ wave of Azure VMs spun up with admin_password in HCL,
#     then committed to public GitHub repos. GitHub's secret
#     scanning catches some, but not all (especially when wrapped
#     in `random_password`).
#   - Shared UAMIs are the Azure equivalent of GCP's monolithic SA
#     anti-pattern — same blast radius story.
#
# Expected tf-analyze findings:
#   - ROB-LIFECYCLE-001  HIGH    Stateful resource missing prevent_destroy
#   - (Step 0a credential pattern detection flags the hardcoded
#    password if it matches a known pattern)
#
# Fix summary: secrets via Key Vault references at runtime, never
# hardcoded; one UAMI per workload boundary; prevent_destroy on every
# stateful resource.

# Hardcoded admin password — the canonical anti-pattern.
locals {
  bad_admin_password = "P@ssw0rd123!"
}

# Single UAMI shared across every workload.
resource "azurerm_user_assigned_identity" "monolith" {
  name                = "monolith-uami"
  resource_group_name = azurerm_resource_group.demo.name
  location            = azurerm_resource_group.demo.location
}

# Stateful SQL Server without prevent_destroy.
resource "azurerm_mssql_server" "stateful" {
  name                         = "demo-sqlserver-stateful"
  resource_group_name          = azurerm_resource_group.demo.name
  location                     = azurerm_resource_group.demo.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = local.bad_admin_password
  # No lifecycle { prevent_destroy = true }
}
