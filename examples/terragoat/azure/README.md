# Azure — OWASP Top 10 corpus

10 deliberately vulnerable Terraform files demonstrating OWASP 2021 categories on Azure.

## File layout

| File | OWASP | What's vulnerable |
|---|---|---|
| [`01_broken_access_control.tf`](01_broken_access_control.tf) | A01 | Subscription-scope `Contributor` role; storage with `allow_nested_items_to_be_public = true`; container with anonymous blob access |
| [`02_cryptographic_failures.tf`](02_cryptographic_failures.tf) | A02 | Storage `enable_https_traffic_only = false`; `min_tls_version = "TLS1_0"`; Key Vault without purge protection |
| [`03_injection.tf`](03_injection.tf) | A03 | VM `custom_data` with unvalidated tfvar; `null_resource` shelling to `az` CLI; Linux VM missing `disable_password_authentication` |
| [`04_insecure_design.tf`](04_insecure_design.tf) | A04 | Hardcoded admin password; orphan UAMI (no role_assignment); SQL Server without `prevent_destroy` |
| [`05_security_misconfiguration.tf`](05_security_misconfiguration.tf) | A05 | NSG with `source_address_prefix = "*"` on tcp:22 and tcp:3389; AKS with RBAC off and node public IPs; storage with `public_network_access_enabled = true` |
| [`06_vulnerable_components.tf`](06_vulnerable_components.tf) | A06 | Function App on `dotnet:3.1` (EOL); AKS pinned to `1.21.7`; module without `version` |
| [`07_identification_auth.tf`](07_identification_auth.tf) | A07 | Web App using storage account key in app_settings; SQL Server without Entra ID admin; Linux VM with password authentication enabled |
| [`08_data_integrity.tf`](08_data_integrity.tf) | A08 | Storage without versioning / soft delete; SQL DB without short-term retention |
| [`09_logging_monitoring.tf`](09_logging_monitoring.tf) | A09 | Key Vault without `azurerm_monitor_diagnostic_setting`; NSG without flow logs |
| [`10_ssrf.tf`](10_ssrf.tf) | A10 | Public-facing Web App with no IP restrictions; storage reachable directly from the internet |
| [`versions.tf`](versions.tf) | — | `~> 3.100` azurerm; `>= 1.10.0` Terraform; declares the demo resource group |

## Expected findings

88 findings across 35 unique rule IDs. From inside this directory:

```sh
python3 ../../../scripts/detect.py --target . --format json \
  | python3 -c '
import json, sys
from collections import Counter
fs = json.load(sys.stdin)["findings"]
for k, v in sorted(Counter(f["id"] for f in fs).items()):
    print(f"{v:>3} {k}")
print(f"---\n{len(fs)} total")
'
```

Active rules that fire against this corpus:

| Rule ID | Files | What it catches |
|---|---|---|
| `SEC-AZURE-RBAC-001` | 01 | Subscription-scope role assignment |
| `SEC-AZURE-STORAGE-001` | 02, 05, 10 | Storage HTTPS not enforced |
| `SEC-AZURE-STORAGE-002` | 05 | Storage allows public blob access |
| `SEC-AZURE-KV-001` | 02 | Key Vault without purge protection |
| `SEC-AZURE-KV-002` | 02 | Key Vault missing network ACL deny-by-default |
| `SEC-AZURE-KV-003` | 02 | Key Vault key missing rotation policy |
| `SEC-AZURE-AKS-001` | 05, 06 | AKS with RBAC disabled |
| `SEC-AZURE-AKS-002` | 05 | AKS cluster missing network policy |
| `SEC-AZURE-ACR-001` | 06 | Container Registry admin account enabled |
| `SEC-AZURE-SQL-001` | 07 | SQL Server without Entra admin (corpus-level `resource_absent`) |
| `SEC-AZURE-SQL-002` | 05 | SQL Server firewall rule open to all IPs |
| `SEC-AZURE-LOGGING-001` | 09 | Key Vault without diagnostic setting |
| `SEC-AZURE-MONITOR-001` | — | Subscription missing activity log diagnostic setting (corpus-level) |
| `SEC-AZURE-VM-001` | 03, 07 | Linux VM with `disable_password_authentication = false` or missing (CIS Azure 7.3) |
| `SEC-AZURE-WEBAPP-001` | 07, 10 | App Service missing IP access restrictions |
| `SEC-AZURE-WEBAPP-002` | 06, 07, 10 | App Service / Function App HTTPS not enforced |
| `SEC-AZURE-MI-001` | 04 | Orphan UAMI — no role_assignment referencing its principal_id |
| `STK-AZURE-AKS-003` | 05, 06 | AKS workload identity not enabled |
| `STK-AZURE-AKS-004` | 05, 06 | AKS cluster is publicly accessible |
| `STK-AZURE-AKS-005` | 05, 06 | AKS API server missing authorized IP ranges |
| `STK-AZURE-DB-001` | 07 | MySQL/PostgreSQL server missing SSL enforcement |
| `STK-AZURE-NSG-001` | 05 | NSG rule open to the internet on sensitive ports |
| `STK-AZURE-NSG-FLOWLOG-001` | — | NSG present with no flow log resource (corpus-level) |
| `STK-AZURE-SQL-001` | 07 | Deprecated MySQL/PostgreSQL single-server resource |
| `STK-AZURE-SQL-TDE-001` | — | Azure SQL Database missing TDE resource (corpus-level) |
| `STK-AZURE-STORAGE-001` | 08 | Storage account missing blob versioning |
| `ROB-AZURE-LIFECYCLE-001` | various | Stateful resource missing `lifecycle.prevent_destroy` |
| `ROB-AZURE-SQL-001` | 04 | SQL database missing short-term backup retention |
| `ROB-AZURE-STORAGE-001` | 08 | Storage without blob soft delete |
| `ROB-VERSION-001` | versions.tf | `required_version` floor too old |
| `OPS-AZURE-TAGS-001` | various | Resources missing `tags` |
| `SEC-PROVISIONER-001` | 03 | `null_resource` with shell provisioner |
| `MOD-PIN-001` | 06 | Module reference without `version` |
| `SEC-SECRETS-001` | 04 | Hardcoded admin password in HCL |
| `CI-TEST-001` | — | No `*.tftest.hcl` test files (corpus-level) |

## OWASP → Azure control mapping

### A01 — Broken Access Control

Subscription-scope role assignments are the single most common Azure misconfiguration in public datasets. A `Contributor` at subscription scope is effectively Owner-minus-IAM. The corpus also demonstrates anonymous blob access, which has caused several high-profile data leaks.

### A02 — Cryptographic Failures

Three opt-outs that override safe defaults — `enable_https_traffic_only = false`, `min_tls_version = "TLS1_0"`, Key Vault without purge protection. Defaults vary by provider version; these are routine findings in real accounts.

### A03 — Injection

Azure-specific vector: `custom_data` on Linux VMs (cloud-init) and `null_resource` provisioners shelling to the `az` CLI without input validation.

### A04 — Insecure Design

Hardcoded admin passwords are unfortunately routine. The orphan UAMI pattern (`SEC-AZURE-MI-001`) catches identities that were created for a workload that was later removed — they accumulate silently and widen blast radius.

### A05 — Security Misconfiguration

NSG rules with `source_address_prefix = "*"` are the Azure analogue of AWS security groups with `0.0.0.0/0`. AKS RBAC off completely defeats the cluster's authorization layer.

### A06 — Vulnerable and Outdated Components

Microsoft publishes runtime support calendars for App Service / Function App. AKS is N-2 supported — anything older stops receiving CVE patches.

### A07 — Identification and Authentication Failures

Storage account keys in App Settings are long-lived and shared. Replace with Managed Identity + RBAC. SQL servers without Entra integration force shared SQL logins.

### A08 — Software and Data Integrity Failures

Soft delete + versioning on storage; short-term retention on SQL databases. Ransomware playbooks specifically target disabling soft delete before encryption.

### A09 — Security Logging and Monitoring Failures

`azurerm_monitor_diagnostic_setting` ships audit logs to Log Analytics. Without one per audit-critical resource, post-incident investigation has no evidence beyond the default 90-day Activity Log. NSG flow logs (`STK-AZURE-NSG-FLOWLOG-001`) are the Azure equivalent of VPC flow logs — the primary network-layer evidence source.

### A10 — Server-Side Request Forgery

Azure's SSRF surface: IMDS (same shape as AWS) and PaaS services reachable from the internet. Mitigate with `azurerm_private_endpoint` + `public_network_access_enabled = false`.

## Running it

```sh
python3 ../../../scripts/detect.py --target . --format text
```
