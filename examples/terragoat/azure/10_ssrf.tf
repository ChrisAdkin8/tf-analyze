# OWASP A10:2021 — Server-Side Request Forgery
# Cloud: Azure
#
# Azure's SSRF surface centres on:
#
#   1. The Instance Metadata Service (IMDS) at 169.254.169.254 —
#      same shape as the AWS metadata service. A workload with an
#      SSRF flaw can fetch a Managed Identity token by hitting IMDS
#      and impersonate the workload to every resource the MI has
#      role bindings on.
#   2. Web App / Function App / API Management instances reachable
#      directly from the internet without Private Endpoints — a
#      compromised front-end can dial backend PaaS services
#      (Storage, Cosmos, SQL) over the public internet.
#   3. AKS workloads without egress restrictions — pod with RCE can
#      egress to attacker-controlled hosts.
#
# Three IaC-shaped controls:
#
#   1. Use Managed Identities with narrow per-workload role
#      bindings — even if IMDS leaks, the role can't read every
#      secret.
#   2. `azurerm_private_endpoint` for every PaaS service the
#      workload uses (Storage, KV, SQL, Cosmos), with
#      `public_network_access_enabled = false` on the target.
#   3. AKS with `outbound_type = "userAssignedNATGateway"` and a
#      restrictive firewall in the egress path.
#
# Expected tf-analyze findings:
#   - SEC-AZURE-WEBAPP-002  HIGH  Web App / Function App HTTPS not enforced
#
# Fix summary: every PaaS resource gets `public_network_access_enabled
# = false` plus a Private Endpoint; AKS clusters route egress through
# Azure Firewall; workloads use User-Assigned Managed Identities with
# minimum role bindings.

# Public-facing Web App (no Private Endpoint, no IP restrictions).
resource "azurerm_service_plan" "ssrf_plan" {
  name                = "demo-ssrf-plan"
  resource_group_name = azurerm_resource_group.demo.name
  location            = azurerm_resource_group.demo.location
  os_type             = "Linux"
  sku_name            = "B1"
}

resource "azurerm_linux_web_app" "publicly_reachable" {
  name                = "demo-public-webapp"
  resource_group_name = azurerm_resource_group.demo.name
  location            = azurerm_resource_group.demo.location
  service_plan_id     = azurerm_service_plan.ssrf_plan.id

  public_network_access_enabled = true

  site_config {
    # No ip_restriction blocks — every IP can reach the front door.
  }
}

# Storage account reachable directly from the internet — no Private
# Endpoint, no firewall rules. A compromised app can pivot to it.
resource "azurerm_storage_account" "ssrf_target" {
  name                            = "demossrftarget1234"
  resource_group_name             = azurerm_resource_group.demo.name
  location                        = azurerm_resource_group.demo.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  public_network_access_enabled   = true
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
}
