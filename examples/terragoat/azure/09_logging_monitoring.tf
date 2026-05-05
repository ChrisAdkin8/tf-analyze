# OWASP A09:2021 — Security Logging and Monitoring Failures
# Cloud: Azure
#
# Five Azure-specific shapes:
#
#   1. Subscription without an Activity Log diagnostic setting —
#      the audit log of every Resource Manager API call is not
#      streamed to Log Analytics or a storage account, so it ages
#      out at the default 90-day retention with no archival.
#   2. NSG without a flow log resource — east-west and north-south
#      traffic at L4 is invisible.
#   3. Key Vault without a diagnostic setting forwarding `AuditEvent`
#      to Log Analytics — secret access is unaudited.
#   4. Storage account without `queue_properties.logging` configured
#      — read/write to queues unaudited.
#   5. AKS cluster without `monitor_metrics` block — no Prometheus
#      metrics, no out-of-box diagnostics.
#
# Real-world impact:
#   - Key Vault without audit logging means any secret read is
#     invisible. Post-incident investigation has no evidence.
#   - NSG flow logs off means lateral-movement detection at the
#     network layer is impossible.
#
# Expected tf-analyze findings:
#   - (no Azure-specific catalogue rule fires here today; documented
#    as roadmap)
#
# Fix summary: one `azurerm_monitor_diagnostic_setting` per audit-
# critical resource, sink to Log Analytics with 365-day+ retention;
# `azurerm_network_watcher_flow_log` on every NSG.

# Key Vault without diagnostic setting.
resource "azurerm_key_vault" "unaudited" {
  name                       = "demo-kv-unaudited"
  resource_group_name        = azurerm_resource_group.demo.name
  location                   = azurerm_resource_group.demo.location
  tenant_id                  = "00000000-0000-0000-0000-000000000000"
  sku_name                   = "standard"
  purge_protection_enabled   = true
  soft_delete_retention_days = 7

  # No companion azurerm_monitor_diagnostic_setting → no AuditEvent
  # forwarding to Log Analytics. Reads of secrets are invisible.
}

# NSG without flow logs.
resource "azurerm_network_security_group" "unmonitored" {
  name                = "demo-nsg-unmonitored"
  resource_group_name = azurerm_resource_group.demo.name
  location            = azurerm_resource_group.demo.location

  security_rule {
    name                       = "allow-internal"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "*"
  }
  # No companion azurerm_network_watcher_flow_log resource.
}
