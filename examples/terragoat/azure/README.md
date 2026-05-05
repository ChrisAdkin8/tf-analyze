# Azure — OWASP Top 10 corpus

10 deliberately vulnerable Terraform files demonstrating OWASP 2021 categories on Azure. Azure-specific catalogue coverage in `tf-analyze` is currently 1 active rule + 4 stubs, so the corpus does heavier documentation lifting and serves as a roadmap for promoting the stubs.

## File layout

| File | OWASP | What's vulnerable |
|---|---|---|
| [`01_broken_access_control.tf`](01_broken_access_control.tf) | A01 | Subscription-scope `Contributor` role; storage with `allow_nested_items_to_be_public = true`; container with anonymous blob access |
| [`02_cryptographic_failures.tf`](02_cryptographic_failures.tf) | A02 | Storage `enable_https_traffic_only = false`; `min_tls_version = "TLS1_0"`; Key Vault without purge protection |
| [`03_injection.tf`](03_injection.tf) | A03 | VM `custom_data` with unvalidated tfvar; `null_resource` shelling to `az` CLI |
| [`04_insecure_design.tf`](04_insecure_design.tf) | A04 | Hardcoded admin password; one shared UAMI; SQL Server without `prevent_destroy` |
| [`05_security_misconfiguration.tf`](05_security_misconfiguration.tf) | A05 | NSG with `source_address_prefix = "*"` on tcp:22 and tcp:3389; AKS with RBAC off and node public IPs; storage with `public_network_access_enabled = true` |
| [`06_vulnerable_components.tf`](06_vulnerable_components.tf) | A06 | Function App on `dotnet:3.1` (EOL); AKS pinned to `1.21.7`; module without `version` |
| [`07_identification_auth.tf`](07_identification_auth.tf) | A07 | Web App using storage account key in app_settings; SQL Server without Entra ID admin |
| [`08_data_integrity.tf`](08_data_integrity.tf) | A08 | Storage without versioning / soft delete; SQL DB without short-term retention |
| [`09_logging_monitoring.tf`](09_logging_monitoring.tf) | A09 | Key Vault without `azurerm_monitor_diagnostic_setting`; NSG without flow logs |
| [`10_ssrf.tf`](10_ssrf.tf) | A10 | Public-facing Web App with no IP restrictions; storage reachable directly from the internet |
| [`versions.tf`](versions.tf) | — | `~> 3.100` azurerm; `>= 1.10.0` Terraform; declares the demo resource group |

## Expected findings

The Azure catalogue currently has 1 active rule (`SEC-AZURE-RBAC-001`) and 4 stubs (`SEC-AZURE-STORAGE-001`, `SEC-AZURE-KV-001`, `STK-AZURE-NSG-001`, `SEC-AZURE-MI-001`). The stubs aren't loaded by default, so they won't fire on a normal run. From inside this directory:

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

You'll see at least: `SEC-AZURE-RBAC-001`, `SEC-PROVISIONER-001`, `MOD-PIN-001`, `ROB-LIFECYCLE-001`. To exercise the stubs (which have placeholder patterns):

```sh
python3 ../../../scripts/detect.py --target . --include-stubs --format text
```

## OWASP → Azure control mapping

### A01 — Broken Access Control

The single most common Azure misconfiguration in the Bridgecrew/tfsec public datasets is "role assignment at subscription scope". The Azure RBAC model is hierarchical (management group → subscription → resource group → resource), and a Contributor at subscription scope is effectively Owner-minus-IAM. The corpus also demonstrates anonymous blob access, which has caused several high-profile public-cloud data leaks.

### A02 — Cryptographic Failures

Three explicit opt-outs that would otherwise default safely on a current `azurerm` provider — but defaults vary by provider version, and this is a routine finding. Key Vault purge protection is a particularly important defence in depth: without it, an attacker who reaches the vault can delete a secret and recreate it under the same name with attacker-controlled value, bypassing audit if logging isn't separately on.

### A03 — Injection

Same shape as AWS / GCP. The Azure-specific vector is `custom_data` on Linux VMs (cloud-init) and the Windows analogue.

### A04 — Insecure Design

Hardcoded admin passwords are unfortunately routine in Azure Terraform — `random_password` + Key Vault is the standard mitigation but adds boilerplate. Step 0a credential pattern detection in `tf-analyze` flags any matching pattern; pair with `azurerm_key_vault_secret` references in app settings.

### A05 — Security Misconfiguration

NSG rules with `source_address_prefix = "*"` are the Azure analogue of AWS security groups with `0.0.0.0/0` ingress. AKS RBAC off is a configuration error that completely defeats the cluster's authorization layer; it's an opt-out flag the operator usually doesn't realise they've set.

### A06 — Vulnerable and Outdated Components

Microsoft publishes the runtime support calendar for App Service / Function App; staying on a supported runtime is a quarterly upkeep task. AKS is N-2 supported — anything older loses Microsoft support and stops receiving CVE patches.

### A07 — Identification and Authentication Failures

Storage account keys in App Settings are the Azure-specific shape — they're long-lived, shared, and embedded in app config. Replacing with Managed Identity + RBAC is a multi-line change but eliminates the credential entirely. SQL servers without Entra integration force shared SQL logins, which become single-points-of-compromise.

### A08 — Software and Data Integrity Failures

Soft delete + versioning on storage accounts; short-term retention on SQL databases. These are increasingly important as ransomware playbooks specifically target Azure storage soft-delete features as a precursor to encryption.

### A09 — Security Logging and Monitoring Failures

`azurerm_monitor_diagnostic_setting` is the universal "ship audit logs to Log Analytics" resource. Without one per audit-critical resource (Key Vault, NSG, SQL Server), post-incident investigation has no evidence beyond the default 90-day Activity Log retention.

### A10 — Server-Side Request Forgery

Azure's SSRF surface centres on IMDS (same shape as AWS) and on PaaS services reachable directly from the internet. Private Endpoints (`azurerm_private_endpoint`) plus `public_network_access_enabled = false` on the target are the standard mitigation; this corpus demonstrates the inverse.

## Running it

```sh
python3 ../../../scripts/detect.py --target . --format text
python3 ../../../scripts/detect.py --target . --include-stubs --format text  # exercise stubs
```

## Catalogue expansion roadmap

Promoting the four Azure stubs is the next obvious step:

1. **`SEC-AZURE-STORAGE-001`** — fires on `enable_https_traffic_only = false` or `min_tls_version` < `TLS1_2`. Triggered by `02_cryptographic_failures.tf`.
2. **`SEC-AZURE-KV-001`** — fires on `purge_protection_enabled = false` or missing soft-delete retention. Triggered by `02_cryptographic_failures.tf`.
3. **`STK-AZURE-NSG-001`** — fires on NSG rules with `source_address_prefix = "*"` and a sensitive port range. Triggered by `05_security_misconfiguration.tf`.
4. **`SEC-AZURE-MI-001`** — fires on UAMI without role assignments (orphan) or with subscription-scope role assignments (over-broad). Triggered by `04_insecure_design.tf`.

For each: edit the YAML to `status: active`, fill in the `patterns:` field, add a triggering fixture under `fixtures/<slug>/`, run `python3 scripts/self_test.py`, and confirm the rule fires here.
