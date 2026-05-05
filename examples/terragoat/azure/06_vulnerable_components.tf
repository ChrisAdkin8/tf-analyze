# OWASP A06:2021 — Vulnerable and Outdated Components
# Cloud: Azure
#
# Three Azure-shaped vulnerable-component anti-patterns:
#
#   1. Function App / Web App on a deprecated runtime (`dotnet:3.1`,
#      `node:10`, `python:3.7`, `java:8`). Microsoft publishes a
#      runtime support calendar; once deprecated, the workload
#      continues to run but receives no security patches.
#   2. AKS cluster pinned to an old `kubernetes_version`. AKS
#      maintains N-2 of the latest GA; older versions stop receiving
#      patches and lose support.
#   3. Module sources without `version` constraint — same as every
#      other cloud's A06.
#
# Real-world impact:
#   - Functions on EOL runtimes are a CVE-exposure shape: once
#     Microsoft stops shipping security patches, vulns in the
#     runtime apply directly.
#   - AKS clusters more than 1 year out of date routinely fail
#     compliance audits and lose Microsoft support.
#
# Expected tf-analyze findings:
#   - MOD-PIN-001  MEDIUM   Registry module source missing version
#
# Fix summary: pin every runtime to a non-deprecated version and
# subscribe to the deprecation calendar; pin AKS to N-1 at most;
# pin every module to an exact version.

# Function App on dotnet 3.1 — long-EOL.
resource "azurerm_service_plan" "linux_plan" {
  name                = "demo-plan"
  resource_group_name = azurerm_resource_group.demo.name
  location            = azurerm_resource_group.demo.location
  os_type             = "Linux"
  sku_name            = "Y1"
}

resource "azurerm_storage_account" "fnapp" {
  name                            = "demofnstorage1234"
  resource_group_name             = azurerm_resource_group.demo.name
  location                        = azurerm_resource_group.demo.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
}

resource "azurerm_linux_function_app" "eol_runtime" {
  name                = "demo-fnapp-eol"
  resource_group_name = azurerm_resource_group.demo.name
  location            = azurerm_resource_group.demo.location
  service_plan_id     = azurerm_service_plan.linux_plan.id
  storage_account_name       = azurerm_storage_account.fnapp.name
  storage_account_access_key = azurerm_storage_account.fnapp.primary_access_key

  site_config {
    application_stack {
      dotnet_version              = "3.1"
      use_dotnet_isolated_runtime = false
    }
  }
}

# AKS pinned to a long-out-of-date Kubernetes version.
resource "azurerm_kubernetes_cluster" "old_k8s" {
  name                = "demo-aks-old"
  resource_group_name = azurerm_resource_group.demo.name
  location            = azurerm_resource_group.demo.location
  dns_prefix          = "demo-aks-old"
  kubernetes_version  = "1.21.7" # well below current GA

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}

# Module without version pin.
module "unpinned_aks" {
  source = "Azure/aks/azurerm"
  # version intentionally omitted

  resource_group_name = azurerm_resource_group.demo.name
  prefix              = "unpinned"
}
