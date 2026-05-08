# tf-analyze sample report — terragoat `azure` (2026-05-08)

> Generated from [`examples/terragoat/azure`](../examples/terragoat/azure) — an intentionally-vulnerable Terraform corpus modelled on Bridgecrew's [terragoat](https://github.com/bridgecrewio/terragoat). The score is **expected** to be poor; this report exists to demonstrate the tool's output, not to grade real infrastructure.

---

## 📊 Risk score

**0 / 100  ·  Grade F**

| 🚨 CRITICAL | ⚠️ HIGH | 💡 MEDIUM | ℹ️ LOW | INFO | Suppressed |
|---:|---:|---:|---:|---:|---:|
| **3** | **11** | 45 | 31 | 0 | 0 |

<sub>Scoring version `1`. Formula: `max(0, 100 - sum(weight * count)); weights: CRITICAL=15, HIGH=7, MEDIUM=3, LOW=1, INFO=0; suppressed at half weight`</sub>

---

## 🎯 Executive summary

`detect.py` flagged **90 finding(s)** across **37 unique catalogue rules** in azure. The corpus deliberately exercises every OWASP Top-10 category, so a clean run is not the goal — these findings are the intended demonstrations.

- 3 CRITICAL — immediate-blast: data exposure, privesc, audit blackout
- 11 HIGH — direct security boundary breach with realistic exploit path
- 45 MEDIUM — defence-in-depth gaps
- 31 LOW — hygiene and style

---

## 🚨 CRITICAL findings

| Rule | Urgency | File:Line | Resource |
|------|---------|-----------|----------|
| `ROB-AZURE-LIFECYCLE-001` | CRITICAL | `examples/terragoat/azure/06_vulnerable_components.tf`:50 | `azurerm_storage_account.fnapp` |
| `SEC-AZURE-WEBAPP-002` | CRITICAL | `examples/terragoat/azure/06_vulnerable_components.tf`:61 | `azurerm_linux_function_app.eol_runtime` |
| `SEC-SECRETS-001` | CRITICAL | `examples/terragoat/azure/04_insecure_design.tf`:35 | `—` |


## ⚠️ HIGH findings

| Rule | Urgency | File:Line | Resource |
|------|---------|-----------|----------|
| `MOD-SUPPLY-003` | HIGH | `examples/terragoat/azure/06_vulnerable_components.tf`:125 | `—` |
| `OPS-AZURE-TAGS-001` | HIGH | `examples/terragoat/azure/06_vulnerable_components.tf`:50 | `azurerm_storage_account.fnapp` |
| `ROB-AZURE-STORAGE-001` | HIGH | `examples/terragoat/azure/06_vulnerable_components.tf`:50 | `azurerm_storage_account.fnapp` |
| `SEC-AZURE-WEBAPP-002` | HIGH | `examples/terragoat/azure/07_identification_auth.tf`:54 | `azurerm_linux_web_app.key_based` |
| `SEC-AZURE-WEBAPP-002` | HIGH | `examples/terragoat/azure/10_ssrf.tf`:45 | `azurerm_linux_web_app.publicly_reachable` |
| `SEC-SECRETS-001` | HIGH | `examples/terragoat/azure/05_security_misconfiguration.tf`:91 | `azurerm_mssql_server.demo` |
| `SEC-SECRETS-001` | HIGH | `examples/terragoat/azure/06_vulnerable_components.tf`:107 | `azurerm_mysql_server.deprecated` |
| `SEC-SECRETS-001` | HIGH | `examples/terragoat/azure/07_identification_auth.tf`:82 | `azurerm_mssql_server.sql_only` |
| `SEC-SECRETS-001` | HIGH | `examples/terragoat/azure/07_identification_auth.tf`:94 | `azurerm_linux_virtual_machine.password_auth` |
| `STK-AZURE-NSG-001` | HIGH | `examples/terragoat/azure/05_security_misconfiguration.tf`:7 | `—` |
| `STK-AZURE-STORAGE-001` | HIGH | `examples/terragoat/azure/06_vulnerable_components.tf`:50 | `azurerm_storage_account.fnapp` |


## 🔗 MITRE ATT&CK coverage

Findings carry MITRE ATT&CK technique IDs where the catalogue rule has a confident mapping. Counts are per-finding (a rule mapped to two techniques contributes to both rows).

| Technique | Findings | Example rule |
|-----------|---------:|--------------|
| `T1530` | 4 | `SEC-AZURE-KV-001` (MEDIUM) |
| `T1133` | 2 | `SEC-AZURE-KV-002` (MEDIUM) |
| `T1562.008` | 2 | `SEC-AZURE-LOGGING-001` (MEDIUM) |
| `T1059` | 1 | `SEC-PROVISIONER-001` (MEDIUM) |
| `T1195.002` | 1 | `MOD-SUPPLY-003` (HIGH) |


---

## 🛤️  Attack graph

Built by `--attack-graph`. Each resource is a node; edges are IAM/network/dependency references. The critical path is BFS from `INTERNET` to the most-exposed crown jewel.

- **Nodes:** 35 resources, **6 edges**
- **Crown jewels:** 13 (databases, KMS keys, secrets, buckets)
- **Internet-reachable:** 4 entry-point resources
- **Critical path length:** 3 hops (`INTERNET` → `azurerm_linux_function_app.eol_runtime` → `azurerm_storage_account.fnapp`)


---

## 🛠️  Top suggested fixes

Highest-urgency findings with `fix_hcl` snippets. Disruption labels indicate operational impact: `none` = config-only re-plan, `plan_required` = a Terraform plan must be reviewed, `forces_replacement` = resource is destroyed and recreated.

### 🚨 `ROB-AZURE-LIFECYCLE-001` — Stateful Azure resource missing lifecycle.prevent_destroy

**Disruption:** `none`  ·  **Resource:** `azurerm_storage_account.fnapp`  ·  **Location:** `examples/terragoat/azure/06_vulnerable_components.tf`:50

```hcl
resource "azurerm_storage_account" "example" {
  # ... other arguments ...
  lifecycle {
    prevent_destroy = true
  }
}
```

### 🚨 `SEC-AZURE-WEBAPP-002` — App Service / Function App HTTPS not enforced

**Disruption:** `none`  ·  **Resource:** `azurerm_linux_function_app.eol_runtime`  ·  **Location:** `examples/terragoat/azure/06_vulnerable_components.tf`:61

```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id
  https_only          = true
  site_config {}
}
```

### 🚨 `SEC-SECRETS-001` — Hardcoded credential or API key in Terraform source

**Disruption:** `none`  ·  **Resource:** ``  ·  **Location:** `examples/terragoat/azure/04_insecure_design.tf`:35

```hcl
# Replace hardcoded credential with a variable (never set a default)
variable "db_password" {
  type      = string
  sensitive = true
}

# Or fetch from AWS Secrets Manager
data "aws_secretsmanager_secret_version" "db" {
  secret_id = "prod/app/db_password"
}

resource "aws_db_instance" "app" {
  password = var.db_password
  # or: password = jsondecode(data.aws_secretsmanager_secret_version.db.secret_string)["password"]
}
```

### ⚠️ `MOD-SUPPLY-003` — Registry module missing version constraint

**Disruption:** `none`  ·  **Resource:** ``  ·  **Location:** `examples/terragoat/azure/06_vulnerable_components.tf`:125

```hcl
module "example" {
  source  = "hashicorp/consul/aws"
  version = ">= 0.11.0, < 0.12.0"
}
```

### ⚠️ `OPS-AZURE-TAGS-001` — Azure resource missing tags

**Disruption:** `none`  ·  **Resource:** `azurerm_storage_account.fnapp`  ·  **Location:** `examples/terragoat/azure/06_vulnerable_components.tf`:50

```hcl
resource "azurerm_resource_group" "example" {
  # ... other arguments ...
  tags = {
    Environment = "prod"
    Owner       = "platform-team"
    Project     = "my-project"
  }
}
```

---

## 🔁 Reproduce

```sh
python3 scripts/detect.py --target examples/terragoat/azure --format json --attack-graph
```

This report file was generated by `scripts/gen_sample_reports.py` on **2026-05-08**.
