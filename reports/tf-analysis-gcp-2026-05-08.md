# tf-analyze sample report — terragoat `gcp` (2026-05-08)

> Generated from [`examples/terragoat/gcp`](../examples/terragoat/gcp) — an intentionally-vulnerable Terraform corpus modelled on Bridgecrew's [terragoat](https://github.com/bridgecrewio/terragoat). The score is **expected** to be poor; this report exists to demonstrate the tool's output, not to grade real infrastructure.

---

## 📊 Risk score

**0 / 100  ·  Grade F**

| 🚨 CRITICAL | ⚠️ HIGH | 💡 MEDIUM | ℹ️ LOW | INFO | Suppressed |
|---:|---:|---:|---:|---:|---:|
| **3** | **19** | 39 | 22 | 0 | 0 |

<sub>Scoring version `1`. Formula: `max(0, 100 - sum(weight * count)); weights: CRITICAL=15, HIGH=7, MEDIUM=3, LOW=1, INFO=0; suppressed at half weight`</sub>

---

## 🎯 Executive summary

`detect.py` flagged **83 finding(s)** across **52 unique catalogue rules** in gcp. The corpus deliberately exercises every OWASP Top-10 category, so a clean run is not the goal — these findings are the intended demonstrations.

- 3 CRITICAL — immediate-blast: data exposure, privesc, audit blackout
- 19 HIGH — direct security boundary breach with realistic exploit path
- 39 MEDIUM — defence-in-depth gaps
- 22 LOW — hygiene and style

---

## 🚨 CRITICAL findings

| Rule | Urgency | File:Line | Resource |
|------|---------|-----------|----------|
| `ROB-GCP-LIFECYCLE-001` | CRITICAL | `examples/terragoat/gcp/05_security_misconfiguration.tf`:94 | `google_sql_database_instance.main` |
| `SEC-GCP-SQL-PUBLIC-001` | CRITICAL | `examples/terragoat/gcp/05_security_misconfiguration.tf`:94 | `google_sql_database_instance.main` |
| `STK-GCP-CLOUDSQL-004` | CRITICAL | `examples/terragoat/gcp/05_security_misconfiguration.tf`:94 | `google_sql_database_instance.main` |


## ⚠️ HIGH findings

| Rule | Urgency | File:Line | Resource |
|------|---------|-----------|----------|
| `COST-GCP-RISK-001` | HIGH | `examples/terragoat/gcp/05_security_misconfiguration.tf`:94 | `google_sql_database_instance.main` |
| `MOD-SUPPLY-003` | HIGH | `examples/terragoat/gcp/06_vulnerable_components.tf`:38 | `—` |
| `OPS-GCP-LABELS-001` | HIGH | `examples/terragoat/gcp/05_security_misconfiguration.tf`:94 | `google_sql_database_instance.main` |
| `ROB-GCP-LIFECYCLE-001` | HIGH | `examples/terragoat/gcp/10_ssrf.tf`:42 | `google_sql_database_instance.public_db` |
| `SEC-GCP-CLOUDRUN-001` | HIGH | `examples/terragoat/gcp/10_ssrf.tf`:68 | `google_cloud_run_v2_service.publicly_reachable` |
| `SEC-GCP-COMPUTE-PUBLIC-IP-001` | HIGH | `examples/terragoat/gcp/05_security_misconfiguration.tf`:45 | `google_compute_instance.exposed` |
| `SEC-GCP-COMPUTE-SA-001` | HIGH | `examples/terragoat/gcp/05_security_misconfiguration.tf`:45 | `google_compute_instance.exposed` |
| `SEC-GCP-GKE-NETWORK-POLICY-001` | HIGH | `examples/terragoat/gcp/07_identification_auth.tf`:37 | `google_container_cluster.demo` |
| `SEC-GCP-IAM-002` | HIGH | `examples/terragoat/gcp/01_broken_access_control.tf`:37 | `google_storage_bucket_iam_member.public_objects` |
| `SEC-GCP-NETWORK-001` | HIGH | `examples/terragoat/gcp/05_security_misconfiguration.tf`:67 | `google_compute_firewall.ssh_open` |
| `SEC-GCP-NETWORK-002` | HIGH | `examples/terragoat/gcp/05_security_misconfiguration.tf`:82 | `google_compute_firewall.rdp_open` |
| `SEC-GCP-NETWORK-004` | HIGH | `examples/terragoat/gcp/05_security_misconfiguration.tf`:145 | `google_compute_firewall.open_postgres` |
| `SEC-GCP-SQL-PUBLIC-001` | HIGH | `examples/terragoat/gcp/10_ssrf.tf`:42 | `google_sql_database_instance.public_db` |
| `SEC-PROVISIONER-001` | HIGH | `examples/terragoat/gcp/03_injection.tf`:7 | `—` |
| `STK-GCP-CLOUDSQL-004` | HIGH | `examples/terragoat/gcp/10_ssrf.tf`:42 | `google_sql_database_instance.public_db` |
| _… 4 more_ |  |  |  |


## 🔗 MITRE ATT&CK coverage

Findings carry MITRE ATT&CK technique IDs where the catalogue rule has a confident mapping. Counts are per-finding (a rule mapped to two techniques contributes to both rows).

| Technique | Findings | Example rule |
|-----------|---------:|--------------|
| `T1059` | 2 | `SEC-PROVISIONER-001` (HIGH) |
| `T1552.001` | 2 | `SEC-SENSITIVE-001` (MEDIUM) |
| `T1195.002` | 1 | `MOD-SUPPLY-003` (HIGH) |
| `T1562.008` | 1 | `SEC-GCP-LOGGING-001` (MEDIUM) |


---

## 🛤️  Attack graph

Built by `--attack-graph`. Each resource is a node; edges are IAM/network/dependency references. The critical path is BFS from `INTERNET` to the most-exposed crown jewel.

- **Nodes:** 35 resources, **6 edges**
- **Crown jewels:** 11 (databases, KMS keys, secrets, buckets)
- **Internet-reachable:** 6 entry-point resources
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

### ⚠️ `SEC-GCP-GKE-NETWORK-POLICY-001` — GKE cluster missing network_policy enforcement

**Disruption:** `forces_replacement`  ·  **Resource:** `google_container_cluster.demo`  ·  **Location:** `examples/terragoat/gcp/07_identification_auth.tf`:37

```hcl
resource "google_container_cluster" "example" {
  name     = "example"
  location = "us-central1"
  network_policy {
    enabled  = true
    provider = "CALICO"
  }
  addons_config {
    network_policy_config { disabled = false }
  }
}
```

### ⚠️ `SEC-GCP-COMPUTE-SA-001` — Compute instance uses default Compute Engine service account

**Disruption:** `none`  ·  **Resource:** `google_compute_instance.exposed`  ·  **Location:** `examples/terragoat/gcp/05_security_misconfiguration.tf`:45

```hcl
resource "google_service_account" "vm" {
  account_id = "vm-runtime"
}
resource "google_compute_instance" "example" {
  name         = "example"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params { image = "debian-cloud/debian-11" }
  }
  network_interface { network = "default" }
  service_account {
    email  = google_service_account.vm.email
    scopes = ["cloud-platform"]
  }
}
```

---

## 🔁 Reproduce

```sh
python3 scripts/detect.py --target examples/terragoat/gcp --format json --attack-graph
```

This report file was generated by `scripts/gen_sample_reports.py` on **2026-05-08**.
