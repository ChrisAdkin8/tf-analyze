# Terraform Code Analysis Report — Azure TerraGoat

**Date:** 2026-05-06-120340
**Scope:** `examples/terragoat/azure`
**Files scanned:** 11 .tf files
**Focus:** all
**Mode:** static
**Health Grade:** F (0/100)

> **Note:** This corpus is *intentionally* vulnerable — all findings are by design.

---

## Executive Summary

This Azure TerraGoat corpus contains intentional, high-density security anti-patterns covering all ten OWASP Top 10 (2021) categories. Every file introduces multiple violations spanning broken access control, cryptographic failures, injection risks, insecure design, security misconfiguration, vulnerable components, authentication failures, data integrity failures, missing logging, and SSRF exposure surfaces. The corpus has zero CI/CD enforcement gates (no lock file, no pre-commit hooks, no linter config), leaving every vulnerability deployable without friction.

**Strengths:** Provider and Terraform versions are explicitly pinned in `versions.tf` with appropriate range constraints. HTTPS-only and TLS 1.2 settings are correctly applied on several storage accounts (the ones intended to illustrate other failure modes), demonstrating the team knows the correct patterns.

**Finding counts by urgency:**
| Urgency | Count |
|---------|-------|
| CRITICAL | 0 |
| HIGH | 14 |
| MEDIUM | 14 |
| LOW | 12 |

**Health score:** max(0, 100 − (15×0 + 7×14 + 3×14 + 1×12)) = max(0, 100 − 152) = **0 (F)**

### Delta (vs previous report)
First run after catalog rename — no delta available.

### Finding density by file
| File | Findings |
|------|----------|
| `05_security_misconfiguration.tf` | 7 |
| `01_broken_access_control.tf` | 5 |
| `02_cryptographic_failures.tf` | 5 |
| `06_vulnerable_components.tf` | 5 |
| `07_identification_auth.tf` | 4 |
| `08_data_integrity.tf` | 3 |
| `10_ssrf.tf` | 3 |
| `04_insecure_design.tf` | 1 |
| `03_injection.tf` | 1 |
| `versions.tf` | 2 |
| `azure/` (module-level absences) | 3 |

---

## 1. Security Posture

The corpus deliberately exercises every category of Azure infrastructure misconfigurations. Subscription-scope RBAC grants, world-open NSG rules, AKS clusters with RBAC disabled, Key Vaults without purge protection, storage accounts accepting HTTP and anonymous blob access, and no Azure Monitor diagnostic settings collectively represent a complete worst-case baseline. Three distinct AKS clusters appear (one RBAC-disabled, one on Kubernetes 1.21.7, one unpinned via a module), and two SQL Server resources lack Entra ID administrator configuration. The only positive signal is that some storage accounts used as supporting resources for other findings (e.g. the Function App backing store in `06_vulnerable_components.tf`) correctly set `enable_https_traffic_only = true` and `min_tls_version = "TLS1_2"`.

Note: `SEC-GCP-LOGGING-001` fired as a false positive — this is a GCP-specific rule (`<absent: google_project_iam_audit_config>`) that should not trigger on an Azure corpus. It is excluded from all counts and the action plan.

---

## 2. DRY and Code Reuse

No modules are extracted. All resources reference `azurerm_resource_group.demo` directly, which is acceptable in a small corpus, but several patterns (storage account baseline config, NSG skeleton) are copy-pasted across files with minor variation. A shared `locals` block or a thin wrapper module for storage accounts would consolidate the security baseline. The one module usage (`module.unpinned_aks`) intentionally omits a version pin, violating DRY for versioning discipline.

---

## 3. Style and Conventions

Files are consistently named with a numeric OWASP prefix and short slug (`01_broken_access_control.tf`), which is excellent for navigation. Resource names follow `snake_case`. Comments are thorough and explain the intended vulnerability. However, no `tags` block appears on any resource, violating the project's `OPS-AZURE-TAGS-001` rule across every taggable resource. The `local.bad_admin_password` name is intentionally descriptive for the corpus but would be flagged immediately in a real review.

---

## 4. Robustness

Storage accounts universally lack versioning and soft-delete blob properties. The SQL Database `azurerm_mssql_database.no_retention` has no short-term retention policy, meaning any accidental or malicious deletion has no recovery path. The `azurerm_mssql_server.stateful` resource has no `lifecycle { prevent_destroy = true }` block — a `terraform destroy` in the wrong workspace permanently destroys the database tier. `ROB-VERSION-001` fires on `versions.tf` line 10 because the Terraform required_version uses `>=` without an upper bound, allowing any future major version to apply.

---

## 5. Simplicity

The corpus is appropriately minimal — each file introduces exactly the vulnerabilities for its OWASP category and nothing more. Resource count is proportionate. The `null_resource.az_cli_inject` provisioner in `03_injection.tf` is the only non-idiomatic construct, and it exists explicitly to demonstrate the injection finding.

---

## 6. Operational Readiness

No resource carries any `tags` block. In a real environment this means cost allocation, environment segregation, ownership, and incident routing are all blind. Azure Policy can enforce tag presence at subscription scope, but the IaC itself provides no baseline. No `azurerm_monitor_diagnostic_setting` resource exists anywhere in the corpus, so audit logs for Key Vaults, storage accounts, and SQL Servers are not forwarded to Log Analytics. NSG flow logs are absent from both NSG resources.

---

## 7. CI/CD and Testing Maturity

| Check | Result |
|-------|--------|
| `.github/workflows/` | Present (`ci.yml` exists) |
| `.terraform.lock.hcl` | **Absent** — HIGH finding |
| `.pre-commit-config.yaml` | **Absent** — MEDIUM finding |
| `.tflint.hcl` | **Absent** — MEDIUM finding |

The `CI-TEST-001` finding confirms the detection engine also flagged the absence of test scaffolding at the module level. While a `ci.yml` workflow exists at the repo root, the Azure corpus directory itself has no lock file, meaning provider versions are resolved at `terraform init` time and can drift silently between runs.

---

## 8. Cross-Module Contracts

There is one module call (`module.unpinned_aks` in `06_vulnerable_components.tf`) with no `version` attribute. The Terraform Registry module `Azure/aks/azurerm` will resolve to the latest available version on every `terraform init`, potentially introducing breaking changes or new defaults that change deployed infrastructure without any code change.

---

## 9. Stack-Specific Findings

**AKS:** Three clusters across two files. `azurerm_kubernetes_cluster.no_rbac` has `role_based_access_control_enabled = false` and `enable_node_public_ip = true`. `azurerm_kubernetes_cluster.old_k8s` is pinned to Kubernetes 1.21.7, which is well outside the AKS N-2 support window (~3 years stale). `module.unpinned_aks` pulls an unpinned registry module.

**Storage Accounts:** Seven storage account resources appear. `azurerm_storage_account.anon_blob` has `allow_nested_items_to_be_public = true` with an accompanying container at `container_access_type = "blob"`. `azurerm_storage_account.weak_tls` has `enable_https_traffic_only = false` and `min_tls_version = "TLS1_0"`. All seven lack `blob_properties` versioning/soft-delete configuration and `tags`.

**SQL / Managed Instance:** Two `azurerm_mssql_server` resources (`stateful`, `sql_only`), both with hardcoded `administrator_login_password` and no `azuread_administrator` block. One `azurerm_mssql_database` (`no_retention`) lacks a `short_term_retention_policy`.

**Key Vault:** Two Key Vaults. `no_purge_protection` has `purge_protection_enabled = false`. `unaudited` has purge protection enabled but no companion `azurerm_monitor_diagnostic_setting`, so secret access is invisible. Neither has network ACLs configured.

**NSG:** Two NSG resources. `open_ssh` exposes SSH (22) and RDP (3389) from `source_address_prefix = "*"`. `unmonitored` has no flow log resource attached.

**Web Apps / Function App:** `azurerm_linux_web_app.key_based` passes `primary_access_key` directly into `app_settings`. `azurerm_linux_web_app.publicly_reachable` has `public_network_access_enabled = true` with no IP restrictions. `azurerm_linux_function_app.eol_runtime` runs on dotnet 3.1 (EOL since December 2022).

---

## 10. CLAUDE.md Compliance

Not applicable — this is a corpus analysis, not a codebase governed by CLAUDE.md conventions. No secrets are introduced by the analysis tooling; the hardcoded credential in `04_insecure_design.tf` is a corpus-level intentional finding.

---

## 11. Suppressed Findings

None. No `# tfsec:ignore` or `# tf-analyze:suppress` annotations are present in any file.

**False positive noted:** `SEC-GCP-LOGGING-001` fired against the Azure corpus (`<absent: google_project_iam_audit_config>`). This GCP-specific rule should not trigger on `azurerm_*` resources. Excluded from all counts and action plan. Recommend adding corpus-level scope filtering in the detection engine to prevent GCP rules from evaluating Azure-only directories.

---

## 12. Positive Findings

- **Version pinning is present and correct.** `versions.tf` pins `azurerm ~> 3.100`, `azuread ~> 2.50`, and `null ~> 3.2`. Terraform required_version is `>= 1.10.0` (upper-bound absence is a separate finding).
- **Several storage accounts correctly set `enable_https_traffic_only = true` and `min_tls_version = "TLS1_2"`** — the resources in `05_security_misconfiguration.tf`, `06_vulnerable_components.tf`, `07_identification_auth.tf`, `08_data_integrity.tf`, and `10_ssrf.tf` demonstrate the correct TLS posture even while illustrating other failure modes.
- **`azurerm_key_vault.unaudited` has `purge_protection_enabled = true`** — the `09_logging_monitoring.tf` Key Vault is correctly hardened on the cryptographic side; only audit forwarding is missing.
- **NSG rule in `09_logging_monitoring.tf` uses `source_address_prefix = "VirtualNetwork"`** — a properly scoped service tag rather than `*`.

---

## 13. Recommended Action Plan

### CRITICAL — Fix Immediately
No CRITICAL findings in this corpus.

### HIGH — Fix This Sprint

- **[SEC-AZURE-RBAC-001#1] Subscription-scope Contributor assignment** — `01_broken_access_control.tf:35` | Blast: subscription | CIS: 1.14 | Effort: Small | Status: VERIFIED
  Description: `azurerm_role_assignment.subscription_contributor` grants the Contributor built-in role at `data.azurerm_subscription.primary.id` scope, giving the principal write access to every resource in the subscription. This is the Azure equivalent of granting `roles/owner` at GCP project level.
  Recommendation: Scope the role assignment to a specific resource group or resource. Prefer a custom role with only the required `Actions` over the built-in Contributor.
  Verification: `az role assignment list --all | jq '.[] | select(.scope | test("/subscriptions/[^/]+$"))'` — no entries should appear.

- **[SEC-AZURE-STORAGE-001#1] Storage account allows non-HTTPS traffic** — `02_cryptographic_failures.tf:35` | Blast: account-wide | CIS: 3.1 | Effort: Small | Status: VERIFIED
  Description: `azurerm_storage_account.weak_tls` sets `enable_https_traffic_only = false` and `min_tls_version = "TLS1_0"`, accepting unencrypted HTTP and deprecated TLS 1.0/1.1 connections. Credentials and data traverse the wire in cleartext on any network path that downgrades the connection.
  Recommendation: Set `enable_https_traffic_only = true` and `min_tls_version = "TLS1_2"` on every `azurerm_storage_account` resource.
  Verification: `az storage account list --query "[?enableHttpsTrafficOnly==\`false\`]"` should return empty.

- **[SEC-AZURE-STORAGE-002#1] Storage account permits anonymous blob access** — `01_broken_access_control.tf:42` | Blast: all blobs in account | CIS: 3.5 | Effort: Small | Status: VERIFIED
  Description: `azurerm_storage_account.anon_blob` sets `allow_nested_items_to_be_public = true` and the companion container uses `container_access_type = "blob"`, making every blob in that container readable by unauthenticated internet clients.
  Recommendation: Set `allow_nested_items_to_be_public = false` on every storage account and ensure containers use `container_access_type = "private"`.
  Verification: `az storage account list --query "[?allowBlobPublicAccess==\`true\`]"` should return empty.

- **[SEC-AZURE-KV-001#1] Key Vault missing purge protection** — `02_cryptographic_failures.tf:48` | Blast: all secrets/keys/certs in vault | CIS: 8.4 | Effort: Small | Status: VERIFIED
  Description: `azurerm_key_vault.no_purge_protection` has `purge_protection_enabled = false`. An attacker with delete permissions can delete and immediately purge a secret, then recreate it with attacker-controlled material under the same name — indistinguishable to consumers.
  Recommendation: Set `purge_protection_enabled = true` on every Key Vault. Retention days should be at least 7 (already set correctly here).
  Verification: `az keyvault list --query "[?properties.enablePurgeProtection!=\`true\`]"` should return empty.

- **[SEC-AZURE-AKS-001#1] AKS cluster has RBAC disabled** — `05_security_misconfiguration.tf:61` | Blast: entire Kubernetes cluster | CIS: 5.1.3 | Effort: Small | Status: VERIFIED
  Description: `azurerm_kubernetes_cluster.no_rbac` sets `role_based_access_control_enabled = false`, disabling Kubernetes RBAC entirely. Any authenticated API request is effectively cluster-admin; there is no authorization layer between workloads and the control plane.
  Recommendation: Set `role_based_access_control_enabled = true` (the provider default) and configure `azure_active_directory_role_based_access_control` for Entra ID integration.
  Verification: `az aks show -n <cluster> -g <rg> --query "enableRbac"` should return `true`.

- **[SEC-AZURE-AKS-001#2] AKS cluster running EOL Kubernetes version** — `06_vulnerable_components.tf:67` | Blast: cluster workloads | CIS: 5.4 | Effort: Medium | Status: VERIFIED
  Description: `azurerm_kubernetes_cluster.old_k8s` is pinned to `kubernetes_version = "1.21.7"`, approximately three years outside the AKS N-2 GA support window. This version receives no security patches and will fail compliance audits.
  Recommendation: Upgrade to at least N-1 of the current AKS GA (check `az aks get-versions`). Remove the explicit `kubernetes_version` pin or set it to a supported release and subscribe to the AKS release calendar.
  Verification: `az aks show -n <cluster> -g <rg> --query kubernetesVersion` should return a version within the supported window.

- **[SEC-AZURE-LOGGING-001#1] No Azure Monitor diagnostic settings exist** — `azure/:0` | Blast: all audit-critical resources | CIS: 5.1 | Effort: Medium | Status: VERIFIED
  Description: No `azurerm_monitor_diagnostic_setting` resource exists anywhere in the corpus. Activity log audit trails for Key Vaults, storage accounts, SQL Servers, and NSGs are not streamed to Log Analytics. Secret access, role assignment changes, and network events are invisible to SIEM and post-incident investigation.
  Recommendation: Add one `azurerm_monitor_diagnostic_setting` per audit-critical resource (Key Vault, SQL Server, NSG). Sink to a Log Analytics Workspace with at least 365-day retention.
  Verification: `az monitor diagnostic-settings list --resource <id>` should return a non-empty list for each critical resource.

- **[SEC-AZURE-SQL-001#1] SQL Server has no Entra ID administrator configured** — `azure/:0` | Blast: all databases on affected servers | CIS: 4.3 | Effort: Small | Status: VERIFIED
  Description: Neither `azurerm_mssql_server.stateful` nor `azurerm_mssql_server.sql_only` defines an `azuread_administrator` block or a companion `azurerm_mssql_server_azure_ad_administrator` resource. Authentication relies solely on SQL logins with hardcoded passwords; no MFA, no conditional access, no audit trail via Entra ID.
  Recommendation: Add `azuread_administrator { login_username = ... object_id = ... }` to every `azurerm_mssql_server` resource and disable SQL authentication where regulations permit.
  Verification: `az sql server ad-admin list --server <name> -g <rg>` should return an entry.

- **[SEC-PROVISIONER-001#1] Provisioner block used for shell execution with interpolated input** — `03_injection.tf:65` | Blast: VM and any downstream system | CIS: n/a | Effort: Medium | Status: VERIFIED
  Description: `null_resource.az_cli_inject` runs `az vm show --name ${var.vm_name} ...` via `local-exec`. The `var.vm_name` variable has no `validation` block; an attacker controlling the tfvar value can inject arbitrary shell commands that execute on the Terraform runner with runner-level privileges.
  Recommendation: Validate all variables used in provisioner commands with `validation { condition = can(regex("^[a-zA-Z0-9-]+$", var.vm_name)) ... }`. Prefer typed CLI arguments and avoid shell interpolation of unvalidated user input. Replace the `null_resource` with a data source or an Azure-native API call where possible.
  Verification: Add a `validation` block and confirm `terraform validate` passes; run `tflint --enable-rule=terraform_required_version` and review provisioner usage.

- **[STK-AZURE-NSG-001#1] NSG rule allows SSH from any source** — `05_security_misconfiguration.tf:7` | Blast: all VMs attached to NSG | CIS: 7.1 | Effort: Small | Status: VERIFIED
  Description: The `allow-ssh-from-anywhere` rule in `azurerm_network_security_group.open_ssh` sets `source_address_prefix = "*"` for destination port 22, accepting SSH connections from any IP on the internet. Azure Security Center flags this as Critical in every subscription scan.
  Recommendation: Replace `source_address_prefix = "*"` with a specific CIDR block, an Azure Bastion service tag, or `VirtualNetwork`. Prefer Azure Bastion for all SSH/RDP access over public-port exposure.
  Verification: `az network nsg rule list --nsg-name <name> -g <rg> --query "[?sourceAddressPrefix=='*' && destinationPortRange=='22']"` should return empty.

- **[STK-AZURE-NSG-001#2] NSG rule allows RDP from any source** — `05_security_misconfiguration.tf:42` | Blast: all VMs attached to NSG | CIS: 7.2 | Effort: Small | Status: VERIFIED
  Description: The `allow-rdp-from-anywhere` rule sets `source_address_prefix = "*"` for port 3389. World-open RDP is the leading initial-access vector for Azure VM compromise (brute force, credential stuffing, BlueKeep).
  Recommendation: Remove the RDP rule entirely and route all remote desktop access through Azure Bastion or a VPN gateway. If RDP must remain, restrict to a specific management CIDR.
  Verification: `az network nsg rule list --nsg-name <name> -g <rg> --query "[?sourceAddressPrefix=='*' && destinationPortRange=='3389']"` should return empty.

- **[STK-AZURE-NSG-001#3] Inline NSG rules block present** — `05_security_misconfiguration.tf:54` | Blast: all VMs attached to NSG | CIS: 7.1 | Effort: Small | Status: VERIFIED
  Description: Additional inline `security_rule` blocks in the same NSG resource are flagged because mixing inline rules and standalone `azurerm_network_security_rule` resources causes plan-time conflicts and makes rule auditing harder.
  Recommendation: Define all NSG rules as standalone `azurerm_network_security_rule` resources rather than inline blocks to avoid the inline/standalone conflict and improve diff visibility.
  Verification: Run `terraform plan` — no "azurerm_network_security_rule" conflict errors should appear; verify all rules are visible individually.

- **[CI-LOCK-001] No Terraform lock file present** — `azure/` | Blast: all pipeline runs | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: No `.terraform.lock.hcl` file exists in `examples/terragoat/azure/`. Without a lock file, `terraform init` resolves provider versions from the registry on every run. This allows silent provider upgrades (including patch versions with breaking behavior) and makes builds non-reproducible.
  Recommendation: Run `terraform init` locally, commit the generated `.terraform.lock.hcl`, and add `terraform providers lock` to the CI pipeline. Add the lock file to version control (never to `.gitignore`).
  Verification: Confirm `.terraform.lock.hcl` exists and is committed; CI should fail if the lock file is absent or dirty.

### MEDIUM — Plan to Address

- **[SEC-AZURE-WEBAPP-001#1] Web App passes storage account key in app settings** — `07_identification_auth.tf:51` | Blast: storage account | CIS: 4.1 | Effort: Medium | Status: VERIFIED
  Description: `azurerm_linux_web_app.key_based` injects `azurerm_storage_account.for_app.primary_access_key` into the `AZURE_STORAGE_KEY` app setting. Account keys are long-lived shared secrets that grant full read/write/delete on the account; they commonly leak in support tickets, log files, and crash dumps.
  Recommendation: Assign a User-Assigned Managed Identity to the Web App and grant it `Storage Blob Data Reader/Contributor` via `azurerm_role_assignment`. Remove the `AZURE_STORAGE_KEY` app setting.
  Verification: `az webapp config appsettings list --name <app> -g <rg>` should show no `*KEY*` or `*CONNECTION_STRING*` entries.

- **[SEC-AZURE-WEBAPP-001#2] Public web app has no IP restrictions** — `10_ssrf.tf:46` | Blast: web app | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: `azurerm_linux_web_app.publicly_reachable` sets `public_network_access_enabled = true` with no `ip_restriction` block in `site_config`. Any IP can reach the app's front door, expanding the SSRF attack surface if the application has outbound request capabilities.
  Recommendation: Add `ip_restriction` blocks to restrict inbound traffic to known sources, or set `public_network_access_enabled = false` and front with Azure Front Door / Application Gateway with WAF.
  Verification: `az webapp show --name <app> -g <rg> --query "publicNetworkAccess"` should return `"Disabled"` or the access restrictions list should be non-empty.

- **[ROB-AZURE-STORAGE-001#1] Storage account missing versioning and soft-delete** — `01_broken_access_control.tf:42` | Blast: all blobs | CIS: 3.12 | Effort: Small | Status: VERIFIED
  Description: `azurerm_storage_account.anon_blob` has no `blob_properties` block, leaving blob versioning disabled and soft delete off. Object deletion is immediate and permanent with no recovery window.
  Recommendation: Add `blob_properties { versioning_enabled = true; delete_retention_policy { days = 7 } }` to every storage account that holds application data.
  Verification: `az storage account blob-service-properties show --account-name <name> --query "deleteRetentionPolicy.enabled"` should return `true`.

- **[ROB-AZURE-STORAGE-001#2] Storage account `for_app` missing versioning and soft-delete** — `07_identification_auth.tf:33` | Blast: all blobs | CIS: 3.12 | Effort: Small | Status: VERIFIED
  Description: Same pattern as #1. `azurerm_storage_account.for_app` has no `blob_properties` block.
  Recommendation: Same as ROB-AZURE-STORAGE-001#1.
  Verification: Same as ROB-AZURE-STORAGE-001#1.

- **[ROB-AZURE-STORAGE-001#3] Storage account `open_storage` missing versioning and soft-delete** — `05_security_misconfiguration.tf:81` | Blast: all blobs | CIS: 3.12 | Effort: Small | Status: VERIFIED
  Description: `azurerm_storage_account.open_storage` lacks `blob_properties`. Additionally it has `public_network_access_enabled = true` with no `network_rules` block — reachable from any IP.
  Recommendation: Add `blob_properties` for soft delete and add a `network_rules { default_action = "Deny" }` block with specific IP/VNet exceptions.
  Verification: `az storage account show --name <name> -g <rg> --query "networkRuleSet.defaultAction"` should return `"Deny"`.

- **[ROB-AZURE-STORAGE-001#4] Storage account `ssrf_target` missing versioning and soft-delete** — `10_ssrf.tf:62` | Blast: all blobs | CIS: 3.12 | Effort: Small | Status: VERIFIED
  Description: `azurerm_storage_account.ssrf_target` lacks `blob_properties` and has `public_network_access_enabled = true` — a storage account reachable from the internet with no network ACLs, a direct SSRF pivot target.
  Recommendation: Add `blob_properties`, set `public_network_access_enabled = false`, and add a Private Endpoint.
  Verification: Same pattern as ROB-AZURE-STORAGE-001#3.

- **[ROB-AZURE-STORAGE-001#5] Storage account `fnapp` missing versioning and soft-delete** — `06_vulnerable_components.tf:38` | Blast: all blobs | CIS: 3.12 | Effort: Small | Status: VERIFIED
  Description: `azurerm_storage_account.fnapp` lacks `blob_properties`. This account backs the EOL Function App runtime.
  Recommendation: Add `blob_properties` as per ROB-AZURE-STORAGE-001#1.
  Verification: Same as ROB-AZURE-STORAGE-001#1.

- **[ROB-AZURE-STORAGE-001#6] Storage account `weak_tls` missing versioning and soft-delete** — `02_cryptographic_failures.tf:35` | Blast: all blobs | CIS: 3.12 | Effort: Small | Status: VERIFIED
  Description: `azurerm_storage_account.weak_tls` lacks `blob_properties` in addition to the TLS/HTTPS findings already reported under SEC-AZURE-STORAGE-001.
  Recommendation: Add `blob_properties` as per ROB-AZURE-STORAGE-001#1.
  Verification: Same as ROB-AZURE-STORAGE-001#1.

- **[ROB-AZURE-STORAGE-001#7] Storage account `no_soft_delete` missing versioning and soft-delete** — `08_data_integrity.tf:30` | Blast: all blobs | CIS: 3.12 | Effort: Small | Status: VERIFIED
  Description: `azurerm_storage_account.no_soft_delete` intentionally omits the `blob_properties` block, matching the OWASP A08 scenario it documents.
  Recommendation: Add `blob_properties { versioning_enabled = true; delete_retention_policy { days = 7 } }`.
  Verification: Same as ROB-AZURE-STORAGE-001#1.

- **[ROB-AZURE-SQL-001#1] SQL Database missing short-term retention policy** — `08_data_integrity.tf:45` | Blast: database | CIS: 4.1 | Effort: Small | Status: VERIFIED
  Description: `azurerm_mssql_database.no_retention` has no `short_term_retention_policy` block. Point-in-time restore defaults to 7 days but only if the service tier supports it; with `sku_name = "Basic"` the default may be lower. Without an explicit policy, there is no IaC-level guarantee of recovery window.
  Recommendation: Add `short_term_retention_policy { retention_days = 7 }` (minimum). For production, set 14-35 days depending on RPO requirements.
  Verification: `az sql db str-policy show --server <srv> --db <db> -g <rg> --query "retentionDays"` should return the target value.

- **[ROB-VERSION-001#1] Terraform required_version has no upper bound** — `versions.tf:10` | Blast: all workspaces | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: `required_version = ">= 1.10.0"` will allow any future Terraform major version to apply the configuration. A Terraform 2.0 release with breaking HCL changes could apply silently in CI without any pin change.
  Recommendation: Add an upper bound: `required_version = ">= 1.10.0, < 2.0.0"`.
  Verification: `terraform version` in CI should match the pinned range; the plan should fail if a 2.x binary is used.

- **[MOD-PIN-001#1] Registry module source missing version constraint** — `06_vulnerable_components.tf:86` | Blast: AKS cluster | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: `module.unpinned_aks` sources `Azure/aks/azurerm` without a `version` attribute. `terraform init` will pull the latest release, including major versions with breaking API changes or new security defaults that alter deployed infrastructure.
  Recommendation: Add `version = "~> 8.0"` (or whichever current major is appropriate) to pin the module to a compatible range.
  Verification: After adding the version pin, `terraform init -upgrade` should be a deliberate, reviewed action.

- **[CI-PRECOMMIT-001] No .pre-commit-config.yaml present** — `azure/` | Blast: all contributors | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: No `.pre-commit-config.yaml` file exists in the repository. Without pre-commit hooks, `terraform fmt`, `tflint`, and secret-scanning (e.g. `detect-secrets`, `gitleaks`) do not run on every commit, allowing style drift and accidental secret commits.
  Recommendation: Add `.pre-commit-config.yaml` with at minimum `terraform_fmt`, `terraform_validate`, `terraform_tflint`, and a secrets scanner hook.
  Verification: `pre-commit run --all-files` should pass with zero findings.

- **[CI-TFLINT-001] No .tflint.hcl configuration present** — `azure/` | Blast: all contributors | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: No `.tflint.hcl` file exists. Without tflint configuration, the `azurerm` ruleset (including deprecated resource and argument detection) is not enforced, and the EOL runtime and old Kubernetes version findings would not be caught by static analysis alone.
  Recommendation: Add `.tflint.hcl` enabling the `terraform` and `azurerm` rulesets. Run via pre-commit and CI.
  Verification: `tflint --init && tflint` should complete without `azurerm_*` deprecation warnings.

### LOW — Address Opportunistically

- **[OPS-AZURE-TAGS-001#1] `azurerm_storage_account.anon_blob` missing tags** — `01_broken_access_control.tf:42` | Blast: cost/ownership tracking | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: No `tags` block. Cost allocation and environment segregation are blind.
  Recommendation: Add a standard `tags` block: `{ environment = var.environment, owner = var.owner, managed_by = "terraform" }`.
  Verification: `az resource show --id <id> --query tags` should return the expected tag map.

- **[OPS-AZURE-TAGS-001#2] `azurerm_storage_account.for_app` missing tags** — `07_identification_auth.tf:33` | Blast: cost/ownership tracking | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: Same as #1.
  Recommendation: Same as #1.
  Verification: Same as #1.

- **[OPS-AZURE-TAGS-001#3] `azurerm_mssql_server.sql_only` missing tags** — `07_identification_auth.tf:73` | Blast: cost/ownership tracking | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: Same as #1.
  Recommendation: Same as #1.
  Verification: Same as #1.

- **[OPS-AZURE-TAGS-001#4] `azurerm_storage_account.open_storage` missing tags** — `05_security_misconfiguration.tf:81` | Blast: cost/ownership tracking | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: Same as #1.
  Recommendation: Same as #1.
  Verification: Same as #1.

- **[OPS-AZURE-TAGS-001#5] `azurerm_kubernetes_cluster.no_rbac` missing tags** — `05_security_misconfiguration.tf:61` | Blast: cost/ownership tracking | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: Same as #1.
  Recommendation: Same as #1.
  Verification: Same as #1.

- **[OPS-AZURE-TAGS-001#6] `azurerm_storage_account.ssrf_target` missing tags** — `10_ssrf.tf:62` | Blast: cost/ownership tracking | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: Same as #1.
  Recommendation: Same as #1.
  Verification: Same as #1.

- **[OPS-AZURE-TAGS-001#7] `azurerm_resource_group.demo` missing tags** — `versions.tf:27` | Blast: cost/ownership tracking | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: Same as #1.
  Recommendation: Same as #1.
  Verification: Same as #1.

- **[OPS-AZURE-TAGS-001#8] `azurerm_storage_account.fnapp` missing tags** — `06_vulnerable_components.tf:38` | Blast: cost/ownership tracking | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: Same as #1.
  Recommendation: Same as #1.
  Verification: Same as #1.

- **[OPS-AZURE-TAGS-001#9] `azurerm_kubernetes_cluster.old_k8s` missing tags** — `06_vulnerable_components.tf:67` | Blast: cost/ownership tracking | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: Same as #1.
  Recommendation: Same as #1.
  Verification: Same as #1.

- **[OPS-AZURE-TAGS-001#10] `azurerm_storage_account.weak_tls` missing tags** — `02_cryptographic_failures.tf:35` | Blast: cost/ownership tracking | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: Same as #1.
  Recommendation: Same as #1.
  Verification: Same as #1.

- **[OPS-AZURE-TAGS-001#11] `azurerm_storage_account.no_soft_delete` missing tags** — `08_data_integrity.tf:30` | Blast: cost/ownership tracking | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: Same as #1.
  Recommendation: Same as #1.
  Verification: Same as #1.

- **[OPS-AZURE-TAGS-001#12] `azurerm_mssql_server.stateful` missing tags** — `04_insecure_design.tf:46` | Blast: cost/ownership tracking | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: Same as #1.
  Recommendation: Same as #1.
  Verification: Same as #1.

---

## Appendix A: OWASP → Finding Cross-Reference

| OWASP Category | Primary Findings |
|----------------|-----------------|
| A01 Broken Access Control | SEC-AZURE-RBAC-001, SEC-AZURE-STORAGE-002 |
| A02 Cryptographic Failures | SEC-AZURE-STORAGE-001, SEC-AZURE-KV-001 |
| A03 Injection | SEC-PROVISIONER-001 |
| A04 Insecure Design | EXPLORATORY-AZURE-LIFECYCLE-001 (see below), OPS-AZURE-TAGS-001#12 |
| A05 Security Misconfiguration | STK-AZURE-NSG-001 x3, SEC-AZURE-AKS-001#1, ROB-AZURE-STORAGE-001#3 |
| A06 Vulnerable Components | SEC-AZURE-AKS-001#2, MOD-PIN-001 |
| A07 Identification & Auth | SEC-AZURE-WEBAPP-001#1, SEC-AZURE-SQL-001 |
| A08 Data Integrity | ROB-AZURE-STORAGE-001#7, ROB-AZURE-SQL-001 |
| A09 Logging & Monitoring | SEC-AZURE-LOGGING-001 |
| A10 SSRF | SEC-AZURE-WEBAPP-001#2, ROB-AZURE-STORAGE-001#4 |

---

## Appendix B: Exploratory Findings (not yet in catalog)

- **[EXPLORATORY-AZURE-LIFECYCLE-001] Stateful resource missing `prevent_destroy`** — `04_insecure_design.tf:46` | Blast: database | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: `azurerm_mssql_server.stateful` (and `azurerm_mssql_server.sql_only` in `07_identification_auth.tf:73`) have no `lifecycle { prevent_destroy = true }` block. A `terraform destroy` against the wrong workspace permanently destroys the SQL Server and all its databases. Note: `ROB-GCP-LIFECYCLE-001` is GCP-specific and does not fire on `azurerm_*` resources — this is the Azure analog, proposed for catalog promotion.
  Recommendation: Add `lifecycle { prevent_destroy = true }` to every `azurerm_mssql_server`, `azurerm_key_vault`, and `azurerm_storage_account` that holds persistent data.
  Verification: Attempt `terraform destroy -target=azurerm_mssql_server.stateful` — it should error with "Instance cannot be destroyed".

- **[EXPLORATORY-AZURE-SECRETS-001] Hardcoded admin password in locals block** — `04_insecure_design.tf:35` | Blast: SQL Server | CIS: 4.2 | Effort: Small | Status: VERIFIED
  Description: `locals { bad_admin_password = "P@ssw0rd123!" }` is committed in plaintext and referenced by `azurerm_mssql_server.stateful`. The credential is visible in `terraform state show`, `terraform plan` output, and any CI log that prints the plan. Both SQL Servers (`stateful` and `sql_only`) use hardcoded passwords.
  Recommendation: Reference a Key Vault secret via `data.azurerm_key_vault_secret.admin_password.value` rather than a hardcoded local. Rotate the credential immediately after removal.
  Verification: `git log --all -S "P@ssw0rd" --oneline` should return zero results after remediation.

- **[EXPLORATORY-AZURE-FNAPP-EOL-001] Function App running EOL dotnet 3.1 runtime** — `06_vulnerable_components.tf:50` | Blast: Function App workload | CIS: n/a | Effort: Medium | Status: VERIFIED
  Description: `azurerm_linux_function_app.eol_runtime` uses `dotnet_version = "3.1"`, which reached end of life in December 2022. Microsoft no longer ships security patches for this runtime; any CVE in the .NET 3.1 BCL applies indefinitely.
  Recommendation: Upgrade to `dotnet_version = "8"` (current LTS) and set `use_dotnet_isolated_runtime = true` for the isolated worker model.
  Verification: `az functionapp config show --name <app> -g <rg> --query "linuxFxVersion"` should show `DOTNET-ISOLATED|8.0` or similar.

- **[EXPLORATORY-AZURE-NSG-FLOWLOG-001] NSG missing flow log resource** — `09_logging_monitoring.tf:48` | Blast: network visibility | CIS: 5.1.2 | Effort: Medium | Status: VERIFIED
  Description: `azurerm_network_security_group.unmonitored` has no companion `azurerm_network_watcher_flow_log` resource. East-west and north-south L4 traffic to/from resources in this NSG is invisible; lateral movement and data exfiltration cannot be detected at the network layer.
  Recommendation: Add `azurerm_network_watcher_flow_log` for every NSG, sink to a storage account with retention ≥ 90 days, and enable traffic analytics.
  Verification: `az network watcher flow-log list --location <region> --query "[?contains(id,'<nsg-name>')]"` should return a non-empty list.

- **[EXPLORATORY-AZURE-KV-AUDIT-001] Key Vault without diagnostic setting** — `09_logging_monitoring.tf:34` | Blast: secret access visibility | CIS: 8.1 | Effort: Small | Status: VERIFIED
  Description: `azurerm_key_vault.unaudited` has no companion `azurerm_monitor_diagnostic_setting`. All secret read, write, and access events are not forwarded to Log Analytics. Post-incident investigation has no evidence of which secrets were accessed and when.
  Recommendation: Add `azurerm_monitor_diagnostic_setting` with `log { category = "AuditEvent" enabled = true }` and a Log Analytics Workspace destination for every Key Vault.
  Verification: `az monitor diagnostic-settings list --resource <kv-id>` should return an entry with `AuditEvent` enabled.

---

## Appendix C: Full Finding List

| # | ID | File | Line | Resource | Urgency |
|---|----|------|------|----------|---------|
| 1 | SEC-AZURE-RBAC-001 | 01_broken_access_control.tf | 35 | azurerm_role_assignment.subscription_contributor | HIGH |
| 2 | SEC-AZURE-STORAGE-001 | 02_cryptographic_failures.tf | 35 | azurerm_storage_account.weak_tls | HIGH |
| 3 | SEC-AZURE-STORAGE-002 | 01_broken_access_control.tf | 42 | azurerm_storage_account.anon_blob | HIGH |
| 4 | SEC-AZURE-KV-001 | 02_cryptographic_failures.tf | 48 | azurerm_key_vault.no_purge_protection | HIGH |
| 5 | SEC-AZURE-AKS-001 | 05_security_misconfiguration.tf | 61 | azurerm_kubernetes_cluster.no_rbac | HIGH |
| 6 | SEC-AZURE-AKS-001 | 06_vulnerable_components.tf | 67 | azurerm_kubernetes_cluster.old_k8s | HIGH |
| 7 | SEC-AZURE-LOGGING-001 | azure/ | 0 | \<absent: azurerm_monitor_diagnostic_setting\> | HIGH |
| 8 | SEC-AZURE-SQL-001 | azure/ | 0 | \<absent: azurerm_mssql_server_azure_ad_administrator\> | HIGH |
| 9 | SEC-PROVISIONER-001 | 03_injection.tf | 65 | null_resource.az_cli_inject | HIGH |
| 10 | STK-AZURE-NSG-001 | 05_security_misconfiguration.tf | 7 | azurerm_network_security_group.open_ssh | HIGH |
| 11 | STK-AZURE-NSG-001 | 05_security_misconfiguration.tf | 42 | azurerm_network_security_group.open_ssh | HIGH |
| 12 | STK-AZURE-NSG-001 | 05_security_misconfiguration.tf | 54 | azurerm_network_security_group.open_ssh | HIGH |
| 13 | CI-LOCK-001 | azure/ | — | .terraform.lock.hcl absent | HIGH |
| 14 | CI-TEST-001 | 01_broken_access_control.tf | 1 | \<module:azure\> | HIGH |
| 15 | SEC-AZURE-WEBAPP-001 | 07_identification_auth.tf | 51 | azurerm_linux_web_app.key_based | MEDIUM |
| 16 | SEC-AZURE-WEBAPP-001 | 10_ssrf.tf | 46 | azurerm_linux_web_app.publicly_reachable | MEDIUM |
| 17 | ROB-AZURE-STORAGE-001 | 01_broken_access_control.tf | 42 | azurerm_storage_account.anon_blob | MEDIUM |
| 18 | ROB-AZURE-STORAGE-001 | 07_identification_auth.tf | 33 | azurerm_storage_account.for_app | MEDIUM |
| 19 | ROB-AZURE-STORAGE-001 | 05_security_misconfiguration.tf | 81 | azurerm_storage_account.open_storage | MEDIUM |
| 20 | ROB-AZURE-STORAGE-001 | 10_ssrf.tf | 62 | azurerm_storage_account.ssrf_target | MEDIUM |
| 21 | ROB-AZURE-STORAGE-001 | 06_vulnerable_components.tf | 38 | azurerm_storage_account.fnapp | MEDIUM |
| 22 | ROB-AZURE-STORAGE-001 | 02_cryptographic_failures.tf | 35 | azurerm_storage_account.weak_tls | MEDIUM |
| 23 | ROB-AZURE-STORAGE-001 | 08_data_integrity.tf | 30 | azurerm_storage_account.no_soft_delete | MEDIUM |
| 24 | ROB-AZURE-SQL-001 | 08_data_integrity.tf | 45 | azurerm_mssql_database.no_retention | MEDIUM |
| 25 | ROB-VERSION-001 | versions.tf | 10 | terraform.required_version | MEDIUM |
| 26 | MOD-PIN-001 | 06_vulnerable_components.tf | 86 | module.unpinned_aks | MEDIUM |
| 27 | CI-PRECOMMIT-001 | azure/ | — | .pre-commit-config.yaml absent | MEDIUM |
| 28 | CI-TFLINT-001 | azure/ | — | .tflint.hcl absent | MEDIUM |
| 29 | OPS-AZURE-TAGS-001 | 01_broken_access_control.tf | 42 | azurerm_storage_account.anon_blob | LOW |
| 30 | OPS-AZURE-TAGS-001 | 07_identification_auth.tf | 33 | azurerm_storage_account.for_app | LOW |
| 31 | OPS-AZURE-TAGS-001 | 07_identification_auth.tf | 73 | azurerm_mssql_server.sql_only | LOW |
| 32 | OPS-AZURE-TAGS-001 | 05_security_misconfiguration.tf | 81 | azurerm_storage_account.open_storage | LOW |
| 33 | OPS-AZURE-TAGS-001 | 05_security_misconfiguration.tf | 61 | azurerm_kubernetes_cluster.no_rbac | LOW |
| 34 | OPS-AZURE-TAGS-001 | 10_ssrf.tf | 62 | azurerm_storage_account.ssrf_target | LOW |
| 35 | OPS-AZURE-TAGS-001 | versions.tf | 27 | azurerm_resource_group.demo | LOW |
| 36 | OPS-AZURE-TAGS-001 | 06_vulnerable_components.tf | 38 | azurerm_storage_account.fnapp | LOW |
| 37 | OPS-AZURE-TAGS-001 | 06_vulnerable_components.tf | 67 | azurerm_kubernetes_cluster.old_k8s | LOW |
| 38 | OPS-AZURE-TAGS-001 | 02_cryptographic_failures.tf | 35 | azurerm_storage_account.weak_tls | LOW |
| 39 | OPS-AZURE-TAGS-001 | 08_data_integrity.tf | 30 | azurerm_storage_account.no_soft_delete | LOW |
| 40 | OPS-AZURE-TAGS-001 | 04_insecure_design.tf | 46 | azurerm_mssql_server.stateful | LOW |
| — | SEC-GCP-LOGGING-001 | azure/ | 0 | \<absent: google_project_iam_audit_config\> | FALSE POSITIVE — GCP rule, excluded |
