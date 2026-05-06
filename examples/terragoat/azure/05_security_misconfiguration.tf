# OWASP A05:2021 — Security Misconfiguration
# Cloud: Azure
#
# The largest OWASP category by volume on Azure too. Five common
# anti-patterns:
#
#   1. Network Security Group rule with `source_address_prefix = "*"`
#      and a destination port range covering SSH (22), RDP (3389),
#      SQL (1433), MongoDB (27017), Redis (6379), Elasticsearch (9200).
#      World-open SSH/RDP/SQL is the most-attacked Azure surface.
#   2. AKS cluster with `role_based_access_control_enabled = false`
#      — Kubernetes RBAC off, every pod has cluster-admin on the
#      apiserver. Effectively no authorization layer.
#   3. AKS cluster with `enable_host_encryption = false` and
#      `enable_node_public_ip = true` on node pools — nodes both
#      lack disk encryption and have public IPs.
#   4. Storage account with `public_network_access_enabled = true`
#      and no `network_rules` block — reachable from any IP.
#   5. App Service / Function App with `https_only = false`.
#
# Expected tf-analyze findings (selected):
#   - STK-AZURE-NSG-001    HIGH  NSG rule open to the internet on sensitive ports
#   - SEC-AZURE-AKS-001    HIGH  AKS RBAC disabled / node public IPs
#   - SEC-AZURE-AKS-002    HIGH  AKS cluster missing network policy
#
# Fix summary: every NSG rule needs a specific CIDR or service tag
# (`AzureCloud`, `Storage`, `VirtualNetwork`); RBAC on for every AKS
# cluster; `https_only = true` on every web workload.

# NSG rule with world-open SSH — the canonical anti-pattern.
resource "azurerm_network_security_group" "open_ssh" {
  name                = "demo-nsg-open-ssh"
  resource_group_name = azurerm_resource_group.demo.name
  location            = azurerm_resource_group.demo.location

  security_rule {
    name                       = "allow-ssh-from-anywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-rdp-from-anywhere"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# AKS cluster with RBAC off (the provider has flipped the default a
# few times; explicit `false` is unambiguous).
resource "azurerm_kubernetes_cluster" "no_rbac" {
  name                              = "demo-aks-no-rbac"
  resource_group_name               = azurerm_resource_group.demo.name
  location                          = azurerm_resource_group.demo.location
  dns_prefix                        = "demo-aks-no-rbac"
  role_based_access_control_enabled = false

  default_node_pool {
    name                 = "default"
    node_count           = 1
    vm_size              = "Standard_D2_v2"
    enable_node_public_ip = true # nodes have public IPs
  }

  identity {
    type = "SystemAssigned"
  }
}

# Storage account with no network rules + public access on.
resource "azurerm_storage_account" "open_storage" {
  name                            = "demoopenstorage1234"
  resource_group_name             = azurerm_resource_group.demo.name
  location                        = azurerm_resource_group.demo.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  public_network_access_enabled   = true
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  # No network_rules block — reachable from any IP.
}
