# tf-analyze sample report — terragoat `all` (2026-05-08)

> Generated from [`examples/terragoat`](../examples/terragoat) — an intentionally-vulnerable Terraform corpus modelled on Bridgecrew's [terragoat](https://github.com/bridgecrewio/terragoat). The score is **expected** to be poor; this report exists to demonstrate the tool's output, not to grade real infrastructure.

---

## 📊 Risk score

**0 / 100  ·  Grade F**

| 🚨 CRITICAL | ⚠️ HIGH | 💡 MEDIUM | ℹ️ LOW | INFO | Suppressed |
|---:|---:|---:|---:|---:|---:|
| **6** | **42** | 146 | 98 | 0 | 0 |

<sub>Scoring version `1`. Formula: `max(0, 100 - sum(weight * count)); weights: CRITICAL=15, HIGH=7, MEDIUM=3, LOW=1, INFO=0; suppressed at half weight`</sub>

---

## 🎯 Executive summary

`detect.py` flagged **292 finding(s)** across **142 unique catalogue rules** in all. The corpus deliberately exercises every OWASP Top-10 category, so a clean run is not the goal — these findings are the intended demonstrations.

- 6 CRITICAL — immediate-blast: data exposure, privesc, audit blackout
- 42 HIGH — direct security boundary breach with realistic exploit path
- 146 MEDIUM — defence-in-depth gaps
- 98 LOW — hygiene and style

---

## 🚨 CRITICAL findings

| Rule | Urgency | File:Line | Resource |
|------|---------|-----------|----------|
| `ROB-GCP-LIFECYCLE-001` | CRITICAL | `examples/terragoat/gcp/05_security_misconfiguration.tf`:94 | `google_sql_database_instance.main` |
| `SEC-GCP-SQL-PUBLIC-001` | CRITICAL | `examples/terragoat/gcp/05_security_misconfiguration.tf`:94 | `google_sql_database_instance.main` |
| `SEC-SECRETS-001` | CRITICAL | `examples/terragoat/aws/04_insecure_design.tf`:37 | `—` |
| `SEC-SECRETS-001` | CRITICAL | `examples/terragoat/aws/04_insecure_design.tf`:37 | `—` |
| `SEC-SECRETS-001` | CRITICAL | `examples/terragoat/azure/04_insecure_design.tf`:35 | `—` |
| `STK-GCP-CLOUDSQL-004` | CRITICAL | `examples/terragoat/gcp/05_security_misconfiguration.tf`:94 | `google_sql_database_instance.main` |


## ⚠️ HIGH findings

| Rule | Urgency | File:Line | Resource |
|------|---------|-----------|----------|
| `COST-GCP-RISK-001` | HIGH | `examples/terragoat/gcp/05_security_misconfiguration.tf`:94 | `google_sql_database_instance.main` |
| `MOD-SUPPLY-003` | HIGH | `examples/terragoat/aws/06_vulnerable_components.tf`:86 | `—` |
| `MOD-SUPPLY-003` | HIGH | `examples/terragoat/azure/06_vulnerable_components.tf`:125 | `—` |
| `MOD-SUPPLY-003` | HIGH | `examples/terragoat/gcp/06_vulnerable_components.tf`:38 | `—` |
| `OPS-GCP-LABELS-001` | HIGH | `examples/terragoat/gcp/05_security_misconfiguration.tf`:94 | `google_sql_database_instance.main` |
| `ROB-AWS-LIFECYCLE-001` | HIGH | `examples/terragoat/aws/05_security_misconfiguration.tf`:99 | `aws_db_instance.public_db` |
| `ROB-AWS-RDS-001` | HIGH | `examples/terragoat/aws/05_security_misconfiguration.tf`:99 | `aws_db_instance.public_db` |
| `ROB-AWS-RDS-002` | HIGH | `examples/terragoat/aws/05_security_misconfiguration.tf`:99 | `aws_db_instance.public_db` |
| `ROB-GCP-LIFECYCLE-001` | HIGH | `examples/terragoat/gcp/10_ssrf.tf`:42 | `google_sql_database_instance.public_db` |
| `SEC-AWS-CLOUDTRAIL-001` | HIGH | `examples/terragoat/aws/09_logging_monitoring.tf`:44 | `aws_cloudtrail.single_region` |
| `SEC-AWS-IAM-002` | HIGH | `examples/terragoat/aws/01_broken_access_control.tf`:61 | `aws_iam_role.anyone` |
| `SEC-AWS-IAM-POLICY-005` | HIGH | `examples/terragoat/aws/01_broken_access_control.tf`:34 | `data.aws_iam_policy_document.all_access` |
| `SEC-AWS-RDS-001` | HIGH | `examples/terragoat/aws/05_security_misconfiguration.tf`:99 | `aws_db_instance.public_db` |
| `SEC-AWS-SG-001` | HIGH | `examples/terragoat/aws/05_security_misconfiguration.tf`:37 | `aws_security_group.ssh_open` |
| `SEC-AWS-SG-001` | HIGH | `examples/terragoat/aws/05_security_misconfiguration.tf`:44 | `aws_security_group.ssh_open` |
| _… 27 more_ |  |  |  |


## 🔗 MITRE ATT&CK coverage

Findings carry MITRE ATT&CK technique IDs where the catalogue rule has a confident mapping. Counts are per-finding (a rule mapped to two techniques contributes to both rows).

| Technique | Findings | Example rule |
|-----------|---------:|--------------|
| `T1530` | 12 | `SEC-AWS-EBS-001` (MEDIUM) |
| `T1562.008` | 8 | `SEC-AWS-CLOUDTRAIL-001` (HIGH) |
| `T1078.004` | 6 | `SEC-AWS-IAM-002` (HIGH) |
| `T1059` | 4 | `SEC-PROVISIONER-001` (HIGH) |
| `T1195.002` | 3 | `MOD-SUPPLY-003` (HIGH) |
| `T1071.001` | 2 | `SEC-AWS-CLOUDFRONT-001` (MEDIUM) |
| `T1098.001` | 2 | `SEC-AWS-IAM-POLICY-005` (HIGH) |
| `T1133` | 2 | `SEC-AZURE-KV-002` (MEDIUM) |
| `T1552.001` | 2 | `SEC-SENSITIVE-001` (MEDIUM) |
| `T1562.001` | 2 | `SEC-AWS-GUARDDUTY-001` (MEDIUM) |
| `T1190` | 1 | `SEC-AWS-APIGW-001` (LOW) |
| `T1552.005` | 1 | `STK-AWS-LAUNCH-TEMPLATE-001` (MEDIUM) |
| `T1556.006` | 1 | `SEC-AWS-COGNITO-001` (MEDIUM) |


---

## 🛤️  Attack graph

Built by `--attack-graph`. Each resource is a node; edges are IAM/network/dependency references. The critical path is BFS from `INTERNET` to the most-exposed crown jewel.

- **Nodes:** 46 resources, **16 edges**
- **Crown jewels:** 35 (databases, KMS keys, secrets, buckets)
- **Internet-reachable:** 12 entry-point resources
- **Critical path length:** 2 hops (`INTERNET` → `google_sql_database_instance.main`)


---

## 🛠️  Top suggested fixes

Highest-urgency findings with `fix_hcl` snippets. Disruption labels indicate operational impact: `none` = config-only re-plan, `plan_required` = a Terraform plan must be reviewed, `forces_replacement` = resource is destroyed and recreated.

### 🚨 `SEC-GCP-SQL-PUBLIC-001` — Cloud SQL instance permits public IPv4

**Disruption:** `plan_required`  ·  **Resource:** `google_sql_database_instance.main`  ·  **Location:** `examples/terragoat/gcp/05_security_misconfiguration.tf`:94

```hcl
resource "google_sql_database_instance" "example" {
  name             = "example"
  database_version = "POSTGRES_14"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }
  }
}
```

### 🚨 `ROB-GCP-LIFECYCLE-001` — Stateful resource missing lifecycle.prevent_destroy

**Disruption:** `none`  ·  **Resource:** `google_sql_database_instance.main`  ·  **Location:** `examples/terragoat/gcp/05_security_misconfiguration.tf`:94

```hcl
resource "google_sql_database_instance" "example" {
  # ... other arguments ...
  lifecycle {
    prevent_destroy = true
  }
}
```

### 🚨 `SEC-SECRETS-001` — Hardcoded credential or API key in Terraform source

**Disruption:** `none`  ·  **Resource:** ``  ·  **Location:** `examples/terragoat/aws/04_insecure_design.tf`:37

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

### 🚨 `STK-GCP-CLOUDSQL-004` — Cloud SQL instance does not require SSL connections

**Disruption:** `plan_required`  ·  **Resource:** `google_sql_database_instance.main`  ·  **Location:** `examples/terragoat/gcp/05_security_misconfiguration.tf`:94

```hcl
resource "google_sql_database_instance" "example" {
  # ... other arguments ...
  settings {
    ip_configuration {
      ssl_mode = "ENCRYPTED_ONLY"
    }
  }
}
```

### ⚠️ `SEC-AWS-SSRF-001` — EC2 instance metadata service v1 enabled (IMDSv2 not enforced)

**Disruption:** `forces_replacement`  ·  **Resource:** `aws_instance.public`  ·  **Location:** `examples/terragoat/aws/05_security_misconfiguration.tf`:49

```hcl
metadata_options {
  http_endpoint               = "enabled"
  http_tokens                 = "required"
  http_put_response_hop_limit = 1
}
```

---

## 🔁 Reproduce

```sh
python3 scripts/detect.py --target examples/terragoat --format json --attack-graph
```

This report file was generated by `scripts/gen_sample_reports.py` on **2026-05-08**.
