# tf-analyze sample report — terragoat `aws` (2026-05-08)

> Generated from [`examples/terragoat/aws`](../examples/terragoat/aws) — an intentionally-vulnerable Terraform corpus modelled on Bridgecrew's [terragoat](https://github.com/bridgecrewio/terragoat). The score is **expected** to be poor; this report exists to demonstrate the tool's output, not to grade real infrastructure.

---

## 📊 Risk score

**0 / 100  ·  Grade F**

| 🚨 CRITICAL | ⚠️ HIGH | 💡 MEDIUM | ℹ️ LOW | INFO | Suppressed |
|---:|---:|---:|---:|---:|---:|
| **6** | **11** | 60 | 42 | 0 | 0 |

<sub>Scoring version `1`. Formula: `max(0, 100 - sum(weight * count)); weights: CRITICAL=15, HIGH=7, MEDIUM=3, LOW=1, INFO=0; suppressed at half weight`</sub>

---

## 🎯 Executive summary

`detect.py` flagged **119 finding(s)** across **66 unique catalogue rules** in aws. The corpus deliberately exercises every OWASP Top-10 category, so a clean run is not the goal — these findings are the intended demonstrations.

- 6 CRITICAL — immediate-blast: data exposure, privesc, audit blackout
- 11 HIGH — direct security boundary breach with realistic exploit path
- 60 MEDIUM — defence-in-depth gaps
- 42 LOW — hygiene and style

---

## 🚨 CRITICAL findings

| Rule | Urgency | File:Line | Resource |
|------|---------|-----------|----------|
| `ROB-AWS-LIFECYCLE-001` | CRITICAL | `examples/terragoat/aws/05_security_misconfiguration.tf`:99 | `aws_db_instance.public_db` |
| `ROB-AWS-RDS-001` | CRITICAL | `examples/terragoat/aws/05_security_misconfiguration.tf`:99 | `aws_db_instance.public_db` |
| `ROB-AWS-RDS-002` | CRITICAL | `examples/terragoat/aws/05_security_misconfiguration.tf`:99 | `aws_db_instance.public_db` |
| `SEC-AWS-RDS-001` | CRITICAL | `examples/terragoat/aws/05_security_misconfiguration.tf`:99 | `aws_db_instance.public_db` |
| `SEC-SECRETS-001` | CRITICAL | `examples/terragoat/aws/04_insecure_design.tf`:37 | `—` |
| `SEC-SECRETS-001` | CRITICAL | `examples/terragoat/aws/04_insecure_design.tf`:37 | `—` |


## ⚠️ HIGH findings

| Rule | Urgency | File:Line | Resource |
|------|---------|-----------|----------|
| `MOD-SUPPLY-003` | HIGH | `examples/terragoat/aws/06_vulnerable_components.tf`:86 | `—` |
| `OPS-AWS-TAGS-001` | HIGH | `examples/terragoat/aws/05_security_misconfiguration.tf`:99 | `aws_db_instance.public_db` |
| `SEC-AWS-CLOUDTRAIL-001` | HIGH | `examples/terragoat/aws/09_logging_monitoring.tf`:44 | `aws_cloudtrail.single_region` |
| `SEC-AWS-IAM-002` | HIGH | `examples/terragoat/aws/01_broken_access_control.tf`:61 | `aws_iam_role.anyone` |
| `SEC-AWS-IAM-POLICY-005` | HIGH | `examples/terragoat/aws/01_broken_access_control.tf`:34 | `data.aws_iam_policy_document.all_access` |
| `SEC-AWS-SG-001` | HIGH | `examples/terragoat/aws/05_security_misconfiguration.tf`:37 | `aws_security_group.ssh_open` |
| `SEC-AWS-SG-001` | HIGH | `examples/terragoat/aws/05_security_misconfiguration.tf`:44 | `aws_security_group.ssh_open` |
| `SEC-AWS-SSRF-001` | HIGH | `examples/terragoat/aws/05_security_misconfiguration.tf`:49 | `aws_instance.public` |
| `SEC-SECRETS-001` | HIGH | `examples/terragoat/aws/02_cryptographic_failures.tf`:50 | `aws_db_instance.unencrypted` |
| `SEC-SECRETS-001` | HIGH | `examples/terragoat/aws/02_cryptographic_failures.tf`:78 | `aws_db_instance.eol_engine` |
| `SEC-SECRETS-001` | HIGH | `examples/terragoat/aws/08_data_integrity.tf`:51 | `aws_db_instance.no_backups` |


## 🔗 MITRE ATT&CK coverage

Findings carry MITRE ATT&CK technique IDs where the catalogue rule has a confident mapping. Counts are per-finding (a rule mapped to two techniques contributes to both rows).

| Technique | Findings | Example rule |
|-----------|---------:|--------------|
| `T1530` | 8 | `SEC-AWS-EBS-001` (MEDIUM) |
| `T1078.004` | 6 | `SEC-AWS-IAM-002` (HIGH) |
| `T1562.008` | 5 | `SEC-AWS-CLOUDTRAIL-001` (HIGH) |
| `T1071.001` | 2 | `SEC-AWS-CLOUDFRONT-001` (MEDIUM) |
| `T1098.001` | 2 | `SEC-AWS-IAM-POLICY-005` (HIGH) |
| `T1562.001` | 2 | `SEC-AWS-GUARDDUTY-001` (MEDIUM) |
| `T1059` | 1 | `SEC-PROVISIONER-001` (MEDIUM) |
| `T1190` | 1 | `SEC-AWS-APIGW-001` (LOW) |
| `T1195.002` | 1 | `MOD-SUPPLY-003` (HIGH) |
| `T1552.005` | 1 | `STK-AWS-LAUNCH-TEMPLATE-001` (MEDIUM) |
| `T1556.006` | 1 | `SEC-AWS-COGNITO-001` (MEDIUM) |


---

## 🛤️  Attack graph

Built by `--attack-graph`. Each resource is a node; edges are IAM/network/dependency references. The critical path is BFS from `INTERNET` to the most-exposed crown jewel.

- **Nodes:** 46 resources, **5 edges**
- **Crown jewels:** 11 (databases, KMS keys, secrets, buckets)
- **Internet-reachable:** 4 entry-point resources
- **Critical path length:** 2 hops (`INTERNET` → `aws_db_instance.public_db`)


---

## 🛠️  Top suggested fixes

Highest-urgency findings with `fix_hcl` snippets. Disruption labels indicate operational impact: `none` = config-only re-plan, `plan_required` = a Terraform plan must be reviewed, `forces_replacement` = resource is destroyed and recreated.

### 🚨 `SEC-AWS-RDS-001` — RDS instance or Aurora cluster publicly accessible

**Disruption:** `plan_required`  ·  **Resource:** `aws_db_instance.public_db`  ·  **Location:** `examples/terragoat/aws/05_security_misconfiguration.tf`:99

```hcl
resource "aws_db_instance" "example" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}
```

### 🚨 `ROB-AWS-LIFECYCLE-001` — Stateful AWS resource missing lifecycle.prevent_destroy

**Disruption:** `none`  ·  **Resource:** `aws_db_instance.public_db`  ·  **Location:** `examples/terragoat/aws/05_security_misconfiguration.tf`:99

```hcl
lifecycle {
  prevent_destroy = true
}
```

### 🚨 `ROB-AWS-RDS-001` — RDS instance or Aurora cluster backup retention disabled

**Disruption:** `plan_required`  ·  **Resource:** `aws_db_instance.public_db`  ·  **Location:** `examples/terragoat/aws/05_security_misconfiguration.tf`:99

```hcl
resource "aws_db_instance" "example" {
  # ... other arguments ...
  backup_retention_period = 7
  backup_window           = "03:00-04:00"
}
```

### 🚨 `ROB-AWS-RDS-002` — RDS instance or Aurora cluster skips final snapshot on deletion

**Disruption:** `plan_required`  ·  **Resource:** `aws_db_instance.public_db`  ·  **Location:** `examples/terragoat/aws/05_security_misconfiguration.tf`:99

```hcl
resource "aws_db_instance" "example" {
  # ... other arguments ...
  skip_final_snapshot       = false
  final_snapshot_identifier = "final-snapshot-${replace(timestamp(), ":", "-")}"
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

---

## 🔁 Reproduce

```sh
python3 scripts/detect.py --target examples/terragoat/aws --format json --attack-graph
```

This report file was generated by `scripts/gen_sample_reports.py` on **2026-05-08**.
