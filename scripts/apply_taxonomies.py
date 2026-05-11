#!/usr/bin/env python3
"""Apply NIST CSF / NIST 800-53 / CSA CCM / SLSA tag manifests to the catalogue.

Companion to `apply_mitre.py`. Reads four in-script manifests
(`NIST_CSF_MAPPINGS`, `NIST_800_53_MAPPINGS`, `CSA_CCM_MAPPINGS`,
`SLSA_MAPPINGS`) keyed on rule_id and inserts/updates the
`nist_csf:` / `nist_800_53:` / `csa_ccm:` / `slsa:` blocks in each
YAML. Idempotent — re-running won't duplicate or reorder entries.

Manifest curation principles (mirrors `apply_mitre.py`):
  * Only map where the link is unambiguous; vague mappings hurt rather
    than help. A rule that arguably maps to 5 NIST 800-53 controls and
    obviously to 2 should list the 2.
  * Prefer the most-specific sub-control (AC-6(7) over AC-6 when the
    rule is specifically about least-privilege restriction; AC-6 alone
    when it's about excessive privilege more broadly).
  * CSA CCM uses domain-prefix form (`IAM-09`, not `CCM-IAM-09`).
  * SLSA values are `L1..L4` (level) or `source`/`build`/`deps` (track).
  * Existing taxonomy tags (from Round 30 batch) take precedence — this
    script only writes a field when it is missing.

Run:  python3 scripts/apply_taxonomies.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG = REPO_ROOT / "catalog"


# ─── NIST CSF 2.0 manifest ─────────────────────────────────────────
# Subcategory format: <Function>.<Category>-<N>, e.g. PR.AA-1.
# Functions used: PR (Protect), DE (Detect), ID (Identify), RC (Recover),
# GV (Govern). CSF 2.0 added GV; older 1.1 PR.AC subcategories remain
# valid via the schema regex `^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d+$`.
NIST_CSF_MAPPINGS: dict[str, list[str]] = {
    # --- Encryption at rest ---------------------------------------
    "SEC-AWS-S3-001":                ["PR.DS-1"],
    "SEC-AWS-EBS-001":               ["PR.DS-1"],
    "SEC-AWS-DDB-001":               ["PR.DS-1"],
    "SEC-AWS-DOCDB-001":             ["PR.DS-1"],
    "SEC-AWS-REDSHIFT-001":          ["PR.DS-1"],
    "SEC-AWS-NEPTUNE-001":           ["PR.DS-1"],
    "SEC-AWS-KINESIS-001":           ["PR.DS-1"],
    "SEC-AWS-MSK-001":               ["PR.DS-1"],
    "SEC-AWS-RDS-001":               ["PR.DS-1"],
    "SEC-AWS-RDS-002":               ["PR.DS-1"],
    "SEC-AWS-SQS-001":               ["PR.DS-1"],
    "SEC-AWS-SNS-001":               ["PR.DS-1"],
    "SEC-AWS-SSM-001":               ["PR.DS-1"],
    "SEC-AWS-ATHENA-001":            ["PR.DS-1"],
    "SEC-AWS-ELASTICACHE-001":       ["PR.DS-1"],
    "SEC-AWS-BACKUP-001":            ["PR.DS-1"],
    "SEC-AWS-ES-001":                ["PR.DS-1"],
    "SEC-AWS-ES-002":                ["PR.DS-2"],   # node-to-node TLS
    "SEC-AWS-ES-003":                ["PR.DS-1"],
    "SEC-AWS-KMS-001":               ["PR.DS-1"],
    "SEC-AZURE-SQL-001":             ["PR.DS-1"],
    "SEC-AZURE-KV-001":              ["PR.DS-1"],
    "SEC-AZURE-KV-002":              ["PR.DS-1"],
    "SEC-AZURE-EVENTHUB-001":        ["PR.DS-1"],
    "SEC-AZURE-SERVICEBUS-001":      ["PR.DS-1"],
    "SEC-GCP-BUCKET-002":            ["PR.DS-1"],
    "SEC-GCP-COMPUTE-DISK-001":      ["PR.DS-1"],
    "STK-GCP-ARTIFACT-001":          ["PR.DS-1"],
    "STK-GCP-BIGQUERY-001":          ["PR.DS-1"],
    "STK-GCP-PUBSUB-001":            ["PR.DS-1"],
    "STK-AZURE-SQL-TDE-001":         ["PR.DS-1"],

    # --- Encryption in transit ------------------------------------
    "SEC-AWS-LB-LISTENER-001":       ["PR.DS-2"],
    "SEC-AWS-CLOUDFRONT-001":        ["PR.DS-2"],
    "SEC-AWS-CLOUDFRONT-002":        ["PR.DS-2"],
    "SEC-AWS-MSK-002":               ["PR.DS-2"],
    "SEC-AZURE-STORAGE-001":         ["PR.DS-2"],
    "SEC-AZURE-WEBAPP-002":          ["PR.DS-2"],
    "SEC-AZURE-REDIS-001":           ["PR.DS-2"],
    "STK-AZURE-DB-001":              ["PR.DS-2"],
    "STK-GCP-CLOUDSQL-004":          ["PR.DS-2"],
    "SEC-GCP-REDIS-002":             ["PR.DS-2"],

    # --- Public exposure / improper access ------------------------
    "SEC-AWS-S3-PUBLIC-BLOCK-001":   ["PR.AC-3", "PR.AC-4"],
    "SEC-GCP-BUCKET-001":            ["PR.AC-3", "PR.AC-4"],
    "SEC-AZURE-STORAGE-002":         ["PR.AC-3", "PR.AC-4"],
    "SEC-GCP-SQL-PUBLIC-001":        ["PR.AC-3"],
    "SEC-GCP-COMPUTE-PUBLIC-IP-001": ["PR.AC-3"],
    "SEC-GCP-CLOUDRUN-001":          ["PR.AC-3"],
    "SEC-AZURE-SQL-002":             ["PR.AC-3"],
    "SEC-AZURE-WEBAPP-001":          ["PR.AC-3"],
    "STK-AZURE-AKS-004":             ["PR.AC-3"],
    "STK-AZURE-AKS-005":             ["PR.AC-3"],
    "STK-AZURE-NSG-001":             ["PR.AC-3"],
    "STK-GCP-GKE-001":               ["PR.AC-3"],
    "STK-GCP-GKE-004":               ["PR.AC-3"],
    "SEC-AWS-APIGW-001":             ["PR.AC-3"],
    "SEC-AWS-SG-001":                ["PR.AC-3"],
    "SEC-GCP-NETWORK-001":           ["PR.AC-3"],
    "SEC-GCP-NETWORK-002":           ["PR.AC-3"],
    "SEC-GCP-NETWORK-004":           ["PR.AC-3"],

    # --- IAM / least privilege ------------------------------------
    "SEC-AWS-IAM-001":               ["PR.AC-1", "PR.AC-4"],
    "SEC-AWS-IAM-002":               ["PR.AC-1", "PR.AC-4"],
    "SEC-AWS-IAM-003":               ["PR.AC-4"],
    "SEC-AWS-IAM-JSON-001":          ["PR.AC-4"],
    "SEC-AWS-IAM-JSON-002":          ["PR.AC-4"],
    "SEC-AWS-IAM-JSON-003":          ["PR.AC-4"],
    "SEC-AWS-IAM-JSON-004":          ["PR.AC-4"],
    "SEC-AWS-IAM-POLICY-001":        ["PR.AC-4"],
    "SEC-AWS-IAM-POLICY-002":        ["PR.AC-4"],
    "SEC-AWS-IAM-POLICY-003":        ["PR.AC-4"],
    "SEC-AWS-IAM-POLICY-004":        ["PR.AC-4"],
    "SEC-AWS-IAM-POLICY-005":        ["PR.AC-4"],
    "SEC-AWS-IAM-POLICY-006":        ["PR.AC-4"],
    "SEC-AWS-ACCESSKEY-001":         ["PR.AC-1", "PR.AC-6"],
    "SEC-GCP-IAM-001":               ["PR.AC-4"],
    "SEC-GCP-IAM-002":               ["PR.AC-4"],
    "SEC-GCP-IAM-003":               ["PR.AC-4"],
    "SEC-AZURE-RBAC-001":            ["PR.AC-4"],
    "SEC-AZURE-MI-001":              ["PR.AC-1"],
    "SEC-AZURE-ACR-001":             ["PR.AC-4"],
    "SEC-AZURE-AKS-001":             ["PR.AC-1"],
    "SEC-GCP-COMPUTE-SA-001":        ["PR.AC-4"],
    "SEC-GCP-SA-KEY-001":            ["PR.AC-1", "PR.AC-6"],
    "STK-GCP-GKE-002":               ["PR.AC-4"],
    "STK-GCP-GKE-003":               ["PR.AC-1"],

    # --- Logging / monitoring -------------------------------------
    "SEC-AWS-CLOUDTRAIL-001":        ["DE.CM-1", "DE.AE-3"],
    "SEC-AWS-CLOUDTRAIL-002":        ["DE.CM-1", "DE.AE-3"],
    "SEC-AWS-VPC-FLOWLOGS-001":      ["DE.CM-1"],
    "SEC-AWS-CWL-001":               ["DE.CM-1"],
    "SEC-AWS-S3-LOGGING-001":        ["DE.CM-1"],
    "SEC-AZURE-LOGGING-001":         ["DE.CM-1"],
    "SEC-AZURE-MONITOR-001":         ["DE.CM-1"],
    "SEC-GCP-LOGGING-001":           ["DE.CM-1"],
    "SEC-GCP-NETWORK-003":           ["DE.CM-1"],
    "OPS-AWS-CWL-001":               ["DE.CM-1"],
    "STK-AZURE-NSG-FLOWLOG-001":     ["DE.CM-1"],
    "STK-GCP-GCS-LOGGING-001":       ["DE.CM-1"],
    "SEC-AWS-GUARDDUTY-001":         ["DE.CM-7", "DE.AE-2"],
    "SEC-AWS-SECURITYHUB-001":       ["DE.CM-7", "DE.AE-2"],
    "SEC-AWS-WAF-001":               ["PR.PT-3", "DE.CM-1"],
    "SEC-AWS-LOG-RETENTION-001":     ["PR.PT-1"],

    # --- Recovery / backups / lifecycle ---------------------------
    "ROB-AWS-ALB-001":               ["PR.IP-4"],
    "ROB-AWS-DDB-001":               ["PR.IP-4", "RC.RP-1"],
    "ROB-AWS-DDB-002":               ["RC.RP-1"],
    "ROB-AWS-LIFECYCLE-001":         ["PR.IP-4"],
    "ROB-AWS-LIFECYCLE-002":         ["PR.IP-4"],
    "ROB-AWS-RDS-001":               ["RC.RP-1"],
    "ROB-AWS-RDS-002":               ["RC.RP-1"],
    "ROB-AWS-RDS-003":               ["PR.IP-4"],
    "ROB-AWS-REDSHIFT-001":          ["RC.RP-1"],
    "ROB-AWS-S3-001":                ["PR.IP-4"],
    "ROB-AZURE-LIFECYCLE-001":       ["PR.IP-4"],
    "ROB-AZURE-SQL-001":             ["RC.RP-1"],
    "ROB-AZURE-STORAGE-001":         ["PR.IP-4"],
    "ROB-GCP-LIFECYCLE-001":         ["PR.IP-4"],
    "ROB-GCP-LIFECYCLE-002":         ["PR.IP-4"],
    "ROB-AWS-BACKUP-001":            ["PR.IP-4", "RC.RP-1"],
    "ROB-AWS-SECRETSMANAGER-001":    ["PR.AC-1"],
    "STK-GCP-CLOUDSQL-001":          ["PR.IP-4"],
    "STK-GCP-CLOUDSQL-003":          ["PR.IP-4"],
    "STK-GCP-BUCKET-001":            ["PR.IP-4"],

    # --- Supply chain / module hygiene ----------------------------
    "MOD-PIN-001":                   ["ID.SC-2", "PR.IP-1"],
    "MOD-STALE-001":                 ["ID.SC-2"],
    "MOD-SUPPLY-001":                ["ID.SC-2"],
    "MOD-SUPPLY-002":                ["ID.SC-2"],
    "MOD-SUPPLY-003":                ["ID.SC-2"],
    "MOD-REUSE-AWS-VPC-001":         ["ID.SC-2"],
    "MOD-REUSE-AZURE-AKS-001":       ["ID.SC-2"],
    "MOD-REUSE-GCP-NETWORK-001":     ["ID.SC-2"],
    "ROB-VERSION-001":               ["ID.SC-2", "PR.IP-1"],
    "ROB-VERSION-002":               ["ID.SC-2", "PR.IP-1"],
    "ROB-VERSION-003":               ["ID.SC-2", "PR.IP-1"],
    "STK-GCP-DEPRECATION-001":       ["ID.SC-2"],
    "STK-AZURE-SQL-001":             ["ID.SC-2"],
    "STK-GCP-CLOUDSQL-005":          ["ID.SC-2"],

    # --- Secrets / credentials ------------------------------------
    "SEC-SECRETS-001":               ["PR.DS-5", "PR.AC-1"],
    "SEC-SENSITIVE-001":             ["PR.DS-5"],
    "SEC-SENSITIVE-002":             ["PR.DS-5"],
    "SEC-SENSITIVE-003":             ["PR.DS-5"],
    "SEC-SENSITIVE-PATTERN-001":     ["PR.DS-5"],
    "SEC-PROVIDER-001":              ["PR.DS-5"],
    "SEC-STATE-001":                 ["PR.DS-5"],
    "SEC-AWS-SECRETSMANAGER-001":    ["PR.DS-5"],
    "SEC-AZURE-KV-003":              ["PR.AC-1"],
    "STK-GCP-KMS-001":               ["PR.AC-1"],

    # --- Drift / state hygiene ------------------------------------
    "ROB-DRIFT-001":                 ["PR.IP-3"],
    "ROB-DRIFT-002":                 ["PR.IP-3"],
    "ROB-DRIFT-003":                 ["PR.IP-3"],

    # --- Container / K8s -----------------------------------------
    "SEC-K8S-NETPOL-001":            ["PR.AC-5"],
    "SEC-K8S-RBAC-001":              ["PR.AC-4"],
    "SEC-K8S-PSA-001":               ["PR.PT-3"],
    "SEC-K8S-HELM-001":              ["PR.PT-3"],
    "SEC-K8S-HELM-002":              ["PR.PT-3"],
    "SEC-AWS-ECS-001":               ["PR.AC-4"],
    "SEC-AWS-ECS-002":               ["PR.PT-3"],
    "SEC-GCP-GKE-NETWORK-POLICY-001": ["PR.AC-5"],
    "SEC-GCP-COMPUTE-SHIELDED-001":  ["PR.PT-3"],
    "STK-GCP-GKE-NODEPOOL-001":      ["PR.PT-3"],

    # --- IMDS / metadata-service hardening ------------------------
    "SEC-AWS-EC2-IMDS-001":          ["PR.AC-1"],
    "STK-AWS-LAUNCH-TEMPLATE-001":   ["PR.AC-1"],

    # --- Provisioner / data-source risk ---------------------------
    "SEC-PROVISIONER-001":           ["PR.PT-3"],
    "SEC-DATASOURCE-001":            ["PR.DS-5"],
    "SEC-DATASOURCE-002":            ["PR.PT-3"],

    # --- Authentication / MFA -------------------------------------
    "SEC-AWS-COGNITO-001":           ["PR.AC-7"],
    "SEC-AWS-COGNITO-002":           ["PR.AC-7"],
    "SEC-AZURE-VM-001":              ["PR.AC-7"],
    "SEC-GCP-REDIS-001":             ["PR.AC-7"],
}


# ─── NIST 800-53 Rev. 5 manifest ───────────────────────────────────
# Control IDs are the canonical form (AC-3, AC-6(7), SC-7(3)). The
# catalogue schema regex allows enhancements via parens.
NIST_800_53_MAPPINGS: dict[str, list[str]] = {
    # Encryption at rest → SC-13 (Cryptographic Protection), SC-28 (Protection at rest)
    "SEC-AWS-S3-001":                ["SC-13", "SC-28"],
    "SEC-AWS-EBS-001":               ["SC-13", "SC-28"],
    "SEC-AWS-DDB-001":               ["SC-13", "SC-28"],
    "SEC-AWS-DOCDB-001":             ["SC-13", "SC-28"],
    "SEC-AWS-REDSHIFT-001":          ["SC-13", "SC-28"],
    "SEC-AWS-NEPTUNE-001":           ["SC-13", "SC-28"],
    "SEC-AWS-KINESIS-001":           ["SC-13", "SC-28"],
    "SEC-AWS-MSK-001":               ["SC-13", "SC-28"],
    "SEC-AWS-RDS-001":               ["SC-13", "SC-28"],
    "SEC-AWS-RDS-002":               ["SC-13", "SC-28"],
    "SEC-AWS-SQS-001":               ["SC-13", "SC-28"],
    "SEC-AWS-SNS-001":               ["SC-13", "SC-28"],
    "SEC-AWS-SSM-001":               ["SC-13", "SC-28"],
    "SEC-AWS-ATHENA-001":            ["SC-13", "SC-28"],
    "SEC-AWS-ELASTICACHE-001":       ["SC-13", "SC-28"],
    "SEC-AWS-BACKUP-001":            ["SC-13", "SC-28"],
    "SEC-AWS-ES-001":                ["SC-13", "SC-28"],
    "SEC-AWS-ES-003":                ["SC-13", "SC-28"],
    "SEC-AWS-KMS-001":               ["SC-13", "SC-12"],
    "SEC-AZURE-SQL-001":             ["SC-13", "SC-28"],
    "SEC-AZURE-KV-001":              ["SC-13", "SC-28"],
    "SEC-AZURE-KV-002":              ["SC-13", "SC-28"],
    "SEC-AZURE-EVENTHUB-001":        ["SC-13", "SC-28"],
    "SEC-AZURE-SERVICEBUS-001":      ["SC-13", "SC-28"],
    "SEC-GCP-BUCKET-002":            ["SC-13", "SC-28"],
    "SEC-GCP-COMPUTE-DISK-001":      ["SC-13", "SC-28"],
    "STK-GCP-ARTIFACT-001":          ["SC-13", "SC-28"],
    "STK-GCP-BIGQUERY-001":          ["SC-13", "SC-28"],
    "STK-GCP-PUBSUB-001":            ["SC-13", "SC-28"],
    "STK-AZURE-SQL-TDE-001":         ["SC-13", "SC-28"],

    # Encryption in transit → SC-8 (Transmission Confidentiality)
    "SEC-AWS-LB-LISTENER-001":       ["SC-8", "SC-8(1)"],
    "SEC-AWS-CLOUDFRONT-001":        ["SC-8", "SC-8(1)"],
    "SEC-AWS-CLOUDFRONT-002":        ["SC-8", "SC-8(1)"],
    "SEC-AWS-MSK-002":               ["SC-8", "SC-8(1)"],
    "SEC-AWS-ES-002":                ["SC-8", "SC-8(1)"],
    "SEC-AZURE-STORAGE-001":         ["SC-8", "SC-8(1)"],
    "SEC-AZURE-WEBAPP-002":          ["SC-8", "SC-8(1)"],
    "SEC-AZURE-REDIS-001":           ["SC-8", "SC-8(1)"],
    "STK-AZURE-DB-001":              ["SC-8", "SC-8(1)"],
    "STK-GCP-CLOUDSQL-004":          ["SC-8", "SC-8(1)"],
    "SEC-GCP-REDIS-002":             ["SC-8", "SC-8(1)"],

    # Public exposure → SC-7 (Boundary Protection), AC-3 (Access Enforcement)
    "SEC-AWS-S3-PUBLIC-BLOCK-001":   ["AC-3", "SC-7"],
    "SEC-GCP-BUCKET-001":            ["AC-3", "SC-7"],
    "SEC-AZURE-STORAGE-002":         ["AC-3", "SC-7"],
    "SEC-GCP-SQL-PUBLIC-001":        ["SC-7"],
    "SEC-GCP-COMPUTE-PUBLIC-IP-001": ["SC-7"],
    "SEC-GCP-CLOUDRUN-001":          ["SC-7"],
    "SEC-AZURE-SQL-002":             ["SC-7"],
    "SEC-AZURE-WEBAPP-001":          ["SC-7"],
    "STK-AZURE-AKS-004":             ["SC-7"],
    "STK-AZURE-AKS-005":             ["SC-7"],
    "STK-AZURE-NSG-001":             ["SC-7", "SC-7(3)"],
    "STK-GCP-GKE-001":               ["SC-7"],
    "STK-GCP-GKE-004":               ["SC-7"],
    "SEC-AWS-APIGW-001":             ["SC-7"],
    "SEC-AWS-SG-001":                ["SC-7", "SC-7(3)"],
    "SEC-GCP-NETWORK-001":           ["SC-7", "SC-7(3)"],
    "SEC-GCP-NETWORK-002":           ["SC-7", "SC-7(3)"],
    "SEC-GCP-NETWORK-004":           ["SC-7"],

    # IAM → AC-3 (Access Enforcement), AC-6 (Least Privilege)
    "SEC-AWS-IAM-001":               ["AC-3", "AC-6"],
    "SEC-AWS-IAM-002":               ["AC-3", "AC-6"],
    "SEC-AWS-IAM-003":               ["AC-6"],
    "SEC-AWS-IAM-JSON-001":          ["AC-3", "AC-6"],
    "SEC-AWS-IAM-JSON-002":          ["AC-3", "AC-6"],
    "SEC-AWS-IAM-JSON-003":          ["AC-3", "AC-6"],
    "SEC-AWS-IAM-JSON-004":          ["AC-6"],
    "SEC-AWS-IAM-POLICY-001":        ["AC-3", "AC-6"],
    "SEC-AWS-IAM-POLICY-002":        ["AC-3", "AC-6"],
    "SEC-AWS-IAM-POLICY-003":        ["AC-6"],
    "SEC-AWS-IAM-POLICY-004":        ["AC-6"],
    "SEC-AWS-IAM-POLICY-005":        ["AC-3", "AC-6"],
    "SEC-AWS-IAM-POLICY-006":        ["AC-6"],
    "SEC-AWS-ACCESSKEY-001":         ["IA-5"],
    "SEC-GCP-IAM-001":               ["AC-3", "AC-6"],
    "SEC-GCP-IAM-002":               ["AC-3", "AC-6"],
    "SEC-GCP-IAM-003":               ["AC-6"],
    "SEC-AZURE-RBAC-001":            ["AC-3", "AC-6"],
    "SEC-AZURE-MI-001":              ["AC-3", "IA-2"],
    "SEC-AZURE-ACR-001":             ["AC-6"],
    "SEC-AZURE-AKS-001":             ["IA-2"],
    "SEC-GCP-COMPUTE-SA-001":        ["AC-6"],
    "SEC-GCP-SA-KEY-001":            ["IA-5", "AC-6"],
    "STK-GCP-GKE-002":               ["AC-6"],

    # Logging / audit → AU-2, AU-12, SI-4
    "SEC-AWS-CLOUDTRAIL-001":        ["AU-2", "AU-12"],
    "SEC-AWS-CLOUDTRAIL-002":        ["AU-2", "AU-9"],
    "SEC-AWS-VPC-FLOWLOGS-001":      ["AU-2", "SI-4"],
    "SEC-AWS-CWL-001":               ["AU-2"],
    "SEC-AWS-S3-LOGGING-001":        ["AU-2"],
    "SEC-AZURE-LOGGING-001":         ["AU-2"],
    "SEC-AZURE-MONITOR-001":         ["AU-2"],
    "SEC-GCP-LOGGING-001":           ["AU-2"],
    "SEC-GCP-NETWORK-003":           ["AU-2", "SI-4"],
    "OPS-AWS-CWL-001":               ["AU-11"],
    "STK-AZURE-NSG-FLOWLOG-001":     ["AU-2", "SI-4"],
    "STK-GCP-GCS-LOGGING-001":       ["AU-2"],
    "SEC-AWS-GUARDDUTY-001":         ["SI-4", "SI-4(5)"],
    "SEC-AWS-SECURITYHUB-001":       ["SI-4"],
    "SEC-AWS-WAF-001":               ["SC-7", "SI-4"],
    "SEC-AWS-LOG-RETENTION-001":     ["AU-11"],

    # Recovery / backups → CP-9 (Backups), CP-10 (Recovery)
    "ROB-AWS-ALB-001":               ["CM-3"],
    "ROB-AWS-DDB-001":               ["CP-9"],
    "ROB-AWS-DDB-002":               ["CP-9"],
    "ROB-AWS-LIFECYCLE-001":         ["CM-3"],
    "ROB-AWS-LIFECYCLE-002":         ["CM-3"],
    "ROB-AWS-RDS-001":               ["CP-9"],
    "ROB-AWS-RDS-002":               ["CP-9"],
    "ROB-AWS-RDS-003":               ["CM-3"],
    "ROB-AWS-REDSHIFT-001":          ["CP-9"],
    "ROB-AWS-S3-001":                ["CP-9", "CM-3"],
    "ROB-AZURE-LIFECYCLE-001":       ["CM-3"],
    "ROB-AZURE-SQL-001":             ["CP-9"],
    "ROB-AZURE-STORAGE-001":         ["CP-9"],
    "ROB-GCP-LIFECYCLE-001":         ["CM-3"],
    "ROB-GCP-LIFECYCLE-002":         ["CM-3"],
    "ROB-AWS-BACKUP-001":            ["CP-9"],
    "ROB-AWS-SECRETSMANAGER-001":    ["IA-5"],
    "STK-GCP-CLOUDSQL-001":          ["CP-9"],
    "STK-GCP-CLOUDSQL-003":          ["CM-3"],
    "STK-GCP-BUCKET-001":            ["CP-9"],

    # Supply chain → SR-3, SR-4, CM-2
    "MOD-PIN-001":                   ["SR-3", "CM-2"],
    "MOD-STALE-001":                 ["SR-4"],
    "MOD-SUPPLY-001":                ["SR-3"],
    "MOD-SUPPLY-002":                ["SR-3"],
    "MOD-SUPPLY-003":                ["SR-3"],
    "MOD-REUSE-AWS-VPC-001":         ["SA-15"],
    "MOD-REUSE-AZURE-AKS-001":       ["SA-15"],
    "MOD-REUSE-GCP-NETWORK-001":     ["SA-15"],
    "ROB-VERSION-001":               ["CM-2", "SR-3"],
    "ROB-VERSION-002":               ["CM-2", "SR-3"],
    "ROB-VERSION-003":               ["CM-2", "SR-3"],
    "STK-GCP-DEPRECATION-001":       ["SR-4"],
    "STK-AZURE-SQL-001":             ["SR-4"],
    "STK-GCP-CLOUDSQL-005":          ["SR-4"],

    # Secrets / credentials → SC-12, SC-28, IA-5
    "SEC-SECRETS-001":               ["SC-12", "SC-28"],
    "SEC-SENSITIVE-001":             ["SC-28"],
    "SEC-SENSITIVE-002":             ["SC-28"],
    "SEC-SENSITIVE-003":             ["SC-28"],
    "SEC-SENSITIVE-PATTERN-001":     ["SC-28"],
    "SEC-PROVIDER-001":              ["SC-28"],
    "SEC-STATE-001":                 ["SC-28", "AC-3"],
    "SEC-AWS-SECRETSMANAGER-001":    ["SC-12"],
    "SEC-AZURE-KV-003":              ["IA-5", "SC-12"],
    "STK-GCP-KMS-001":               ["SC-12"],

    # Drift / config integrity → CM-3, CM-6
    "ROB-DRIFT-001":                 ["CM-3", "CM-6"],
    "ROB-DRIFT-002":                 ["CM-3", "CM-6"],
    "ROB-DRIFT-003":                 ["CM-3"],

    # K8s / container → AC-6, SC-7
    "SEC-K8S-NETPOL-001":            ["SC-7"],
    "SEC-K8S-RBAC-001":              ["AC-3", "AC-6"],
    "SEC-K8S-PSA-001":               ["AC-6"],
    "SEC-K8S-HELM-001":              ["AC-6"],
    "SEC-K8S-HELM-002":              ["CM-7"],
    "SEC-AWS-ECS-001":               ["AC-6"],
    "SEC-AWS-ECS-002":               ["AC-6"],
    "SEC-GCP-GKE-NETWORK-POLICY-001": ["SC-7"],
    "SEC-GCP-COMPUTE-SHIELDED-001":  ["SI-7"],
    "STK-GCP-GKE-NODEPOOL-001":      ["SI-7"],

    # IMDS
    "SEC-AWS-EC2-IMDS-001":          ["AC-3"],
    "STK-AWS-LAUNCH-TEMPLATE-001":   ["AC-3"],

    # Provisioner / data-source risk
    "SEC-PROVISIONER-001":           ["SI-10"],
    "SEC-DATASOURCE-001":            ["IA-5"],
    "SEC-DATASOURCE-002":            ["SI-10"],

    # Auth / MFA
    "SEC-AWS-COGNITO-001":           ["IA-2", "IA-2(1)"],
    "SEC-AWS-COGNITO-002":           ["IA-2"],
    "SEC-AZURE-VM-001":              ["IA-5", "AC-7"],
    "SEC-GCP-REDIS-001":             ["IA-2"],
}


# ─── CSA CCM v4 manifest ───────────────────────────────────────────
# Domain-prefix form. Common domains used below:
#   IAM — Identity & Access Management
#   CEK — Cryptography, Encryption & Key Management
#   IVS — Infrastructure & Virtualization Security
#   LOG — Logging & Monitoring
#   BCR — Business Continuity Management & Operational Resilience
#   CCC — Change Control & Configuration Management
#   AIS — Application & Interface Security
#   SEF — Security Incident Management, e-Discovery & Cloud Forensics
#   STA — Supply Chain Management, Transparency & Accountability
#   TVM — Threat & Vulnerability Management
#   DSP — Data Security & Privacy Lifecycle Management
CSA_CCM_MAPPINGS: dict[str, list[str]] = {
    # Encryption at rest → CEK-03 (Encryption at Rest)
    "SEC-AWS-S3-001":                ["CEK-03"],
    "SEC-AWS-EBS-001":               ["CEK-03"],
    "SEC-AWS-DDB-001":               ["CEK-03"],
    "SEC-AWS-DOCDB-001":             ["CEK-03"],
    "SEC-AWS-REDSHIFT-001":          ["CEK-03"],
    "SEC-AWS-NEPTUNE-001":           ["CEK-03"],
    "SEC-AWS-KINESIS-001":           ["CEK-03"],
    "SEC-AWS-MSK-001":               ["CEK-03"],
    "SEC-AWS-RDS-001":               ["CEK-03"],
    "SEC-AWS-RDS-002":               ["CEK-03"],
    "SEC-AWS-SQS-001":               ["CEK-03"],
    "SEC-AWS-SNS-001":               ["CEK-03"],
    "SEC-AWS-SSM-001":               ["CEK-03"],
    "SEC-AWS-ATHENA-001":            ["CEK-03"],
    "SEC-AWS-ELASTICACHE-001":       ["CEK-03"],
    "SEC-AWS-BACKUP-001":            ["CEK-03"],
    "SEC-AWS-ES-001":                ["CEK-03"],
    "SEC-AWS-ES-003":                ["CEK-03"],
    "SEC-AWS-KMS-001":               ["CEK-09"],
    "SEC-AZURE-SQL-001":             ["CEK-03"],
    "SEC-AZURE-KV-001":              ["CEK-03"],
    "SEC-AZURE-KV-002":              ["CEK-03"],
    "SEC-AZURE-EVENTHUB-001":        ["CEK-03"],
    "SEC-AZURE-SERVICEBUS-001":      ["CEK-03"],
    "SEC-GCP-BUCKET-002":            ["CEK-03"],
    "SEC-GCP-COMPUTE-DISK-001":      ["CEK-03"],
    "STK-GCP-ARTIFACT-001":          ["CEK-03"],
    "STK-GCP-BIGQUERY-001":          ["CEK-03"],
    "STK-GCP-PUBSUB-001":            ["CEK-03"],
    "STK-AZURE-SQL-TDE-001":         ["CEK-03"],

    # Encryption in transit → CEK-06
    "SEC-AWS-LB-LISTENER-001":       ["CEK-06"],
    "SEC-AWS-CLOUDFRONT-001":        ["CEK-06"],
    "SEC-AWS-CLOUDFRONT-002":        ["CEK-06"],
    "SEC-AWS-MSK-002":               ["CEK-06"],
    "SEC-AWS-ES-002":                ["CEK-06"],
    "SEC-AZURE-STORAGE-001":         ["CEK-06"],
    "SEC-AZURE-WEBAPP-002":          ["CEK-06"],
    "SEC-AZURE-REDIS-001":           ["CEK-06"],
    "STK-AZURE-DB-001":              ["CEK-06"],
    "STK-GCP-CLOUDSQL-004":          ["CEK-06"],
    "SEC-GCP-REDIS-002":             ["CEK-06"],

    # Public exposure → IVS-04 (Network Architecture), IVS-06 (Network Defense)
    "SEC-AWS-S3-PUBLIC-BLOCK-001":   ["IAM-09", "IVS-04"],
    "SEC-GCP-BUCKET-001":            ["IAM-09", "IVS-04"],
    "SEC-AZURE-STORAGE-002":         ["IAM-09", "IVS-04"],
    "SEC-GCP-SQL-PUBLIC-001":        ["IVS-04"],
    "SEC-GCP-COMPUTE-PUBLIC-IP-001": ["IVS-04"],
    "SEC-GCP-CLOUDRUN-001":          ["IVS-04"],
    "SEC-AZURE-SQL-002":             ["IVS-04"],
    "SEC-AZURE-WEBAPP-001":          ["IVS-04"],
    "STK-AZURE-AKS-004":             ["IVS-04"],
    "STK-AZURE-AKS-005":             ["IVS-04"],
    "STK-AZURE-NSG-001":             ["IVS-04", "IVS-06"],
    "STK-GCP-GKE-001":               ["IVS-04"],
    "STK-GCP-GKE-004":               ["IVS-04"],
    "SEC-AWS-APIGW-001":             ["IVS-04"],
    "SEC-AWS-SG-001":                ["IVS-04", "IVS-06"],
    "SEC-GCP-NETWORK-001":           ["IVS-04", "IVS-06"],
    "SEC-GCP-NETWORK-002":           ["IVS-04", "IVS-06"],
    "SEC-GCP-NETWORK-004":           ["IVS-04"],

    # IAM → IAM-02 (Strong Auth), IAM-09 (Segregation of Duties)
    "SEC-AWS-IAM-001":               ["IAM-09"],
    "SEC-AWS-IAM-002":               ["IAM-09"],
    "SEC-AWS-IAM-003":               ["IAM-09"],
    "SEC-AWS-IAM-JSON-001":          ["IAM-09"],
    "SEC-AWS-IAM-JSON-002":          ["IAM-09"],
    "SEC-AWS-IAM-JSON-003":          ["IAM-09"],
    "SEC-AWS-IAM-JSON-004":          ["IAM-09"],
    "SEC-AWS-IAM-POLICY-001":        ["IAM-09"],
    "SEC-AWS-IAM-POLICY-002":        ["IAM-09"],
    "SEC-AWS-IAM-POLICY-003":        ["IAM-09"],
    "SEC-AWS-IAM-POLICY-004":        ["IAM-09"],
    "SEC-AWS-IAM-POLICY-005":        ["IAM-09"],
    "SEC-AWS-IAM-POLICY-006":        ["IAM-09"],
    "SEC-AWS-ACCESSKEY-001":         ["IAM-04"],
    "SEC-GCP-IAM-001":               ["IAM-09"],
    "SEC-GCP-IAM-002":               ["IAM-09"],
    "SEC-GCP-IAM-003":               ["IAM-09"],
    "SEC-AZURE-RBAC-001":            ["IAM-09"],
    "SEC-AZURE-MI-001":              ["IAM-04"],
    "SEC-AZURE-ACR-001":             ["IAM-09"],
    "SEC-AZURE-AKS-001":             ["IAM-02"],
    "SEC-GCP-COMPUTE-SA-001":        ["IAM-09"],
    "SEC-GCP-SA-KEY-001":            ["IAM-04"],
    "STK-GCP-GKE-002":               ["IAM-09"],

    # Logging / audit → LOG-02 (Audit Logs Generation), LOG-10 (Encryption Monitoring)
    "SEC-AWS-CLOUDTRAIL-001":        ["LOG-02"],
    "SEC-AWS-CLOUDTRAIL-002":        ["LOG-02"],
    "SEC-AWS-VPC-FLOWLOGS-001":      ["LOG-02"],
    "SEC-AWS-CWL-001":               ["LOG-02"],
    "SEC-AWS-S3-LOGGING-001":        ["LOG-02"],
    "SEC-AZURE-LOGGING-001":         ["LOG-02"],
    "SEC-AZURE-MONITOR-001":         ["LOG-02"],
    "SEC-GCP-LOGGING-001":           ["LOG-02"],
    "SEC-GCP-NETWORK-003":           ["LOG-02"],
    "OPS-AWS-CWL-001":               ["LOG-04"],
    "STK-AZURE-NSG-FLOWLOG-001":     ["LOG-02"],
    "STK-GCP-GCS-LOGGING-001":       ["LOG-02"],
    "SEC-AWS-GUARDDUTY-001":         ["TVM-02"],
    "SEC-AWS-SECURITYHUB-001":       ["TVM-02"],
    "SEC-AWS-WAF-001":               ["TVM-02"],
    "SEC-AWS-LOG-RETENTION-001":     ["LOG-04"],

    # Backup / recovery → BCR-08 (Backup), BCR-11 (Equipment Recovery)
    "ROB-AWS-ALB-001":               ["BCR-08"],
    "ROB-AWS-DDB-001":               ["BCR-08"],
    "ROB-AWS-DDB-002":               ["BCR-08"],
    "ROB-AWS-LIFECYCLE-001":         ["BCR-08"],
    "ROB-AWS-LIFECYCLE-002":         ["BCR-08"],
    "ROB-AWS-RDS-001":               ["BCR-08"],
    "ROB-AWS-RDS-002":               ["BCR-08"],
    "ROB-AWS-RDS-003":               ["BCR-08"],
    "ROB-AWS-REDSHIFT-001":          ["BCR-08"],
    "ROB-AWS-S3-001":                ["BCR-08"],
    "ROB-AZURE-LIFECYCLE-001":       ["BCR-08"],
    "ROB-AZURE-SQL-001":             ["BCR-08"],
    "ROB-AZURE-STORAGE-001":         ["BCR-08"],
    "ROB-GCP-LIFECYCLE-001":         ["BCR-08"],
    "ROB-GCP-LIFECYCLE-002":         ["BCR-08"],
    "ROB-AWS-BACKUP-001":            ["BCR-08"],
    "STK-GCP-CLOUDSQL-001":          ["BCR-08"],
    "STK-GCP-CLOUDSQL-003":          ["BCR-08"],
    "STK-GCP-BUCKET-001":            ["BCR-08"],

    # Supply chain → STA-04 (Supplier Risk Assessment), AIS-07 (Application Vulnerability Remediation)
    "MOD-PIN-001":                   ["STA-04", "CCC-05"],
    "MOD-STALE-001":                 ["STA-04", "AIS-07"],
    "MOD-SUPPLY-001":                ["STA-04"],
    "MOD-SUPPLY-002":                ["STA-04"],
    "MOD-SUPPLY-003":                ["STA-04"],
    "MOD-REUSE-AWS-VPC-001":         ["AIS-04"],
    "MOD-REUSE-AZURE-AKS-001":       ["AIS-04"],
    "MOD-REUSE-GCP-NETWORK-001":     ["AIS-04"],
    "ROB-VERSION-001":               ["STA-04", "CCC-05"],
    "ROB-VERSION-002":               ["STA-04", "CCC-05"],
    "ROB-VERSION-003":               ["STA-04", "CCC-05"],
    "STK-GCP-DEPRECATION-001":       ["AIS-07"],
    "STK-AZURE-SQL-001":             ["AIS-07"],
    "STK-GCP-CLOUDSQL-005":          ["AIS-07"],

    # Secrets / credentials → CEK-09, IAM-04
    "SEC-SECRETS-001":               ["CEK-09", "IAM-04"],
    "SEC-SENSITIVE-001":             ["CEK-09"],
    "SEC-SENSITIVE-002":             ["CEK-09"],
    "SEC-SENSITIVE-003":             ["CEK-09"],
    "SEC-SENSITIVE-PATTERN-001":     ["CEK-09"],
    "SEC-PROVIDER-001":              ["CEK-09"],
    "SEC-STATE-001":                 ["CEK-09"],
    "SEC-AWS-SECRETSMANAGER-001":    ["CEK-09"],
    "SEC-AZURE-KV-003":              ["CEK-09"],
    "STK-GCP-KMS-001":               ["CEK-09"],

    # Drift → CCC-02 (Quality Testing), CCC-05 (Production Changes)
    "ROB-DRIFT-001":                 ["CCC-05"],
    "ROB-DRIFT-002":                 ["CCC-05"],
    "ROB-DRIFT-003":                 ["CCC-05"],

    # K8s / container → IVS-04, IAM-09
    "SEC-K8S-NETPOL-001":            ["IVS-04"],
    "SEC-K8S-RBAC-001":              ["IAM-09"],
    "SEC-K8S-PSA-001":               ["IAM-09"],
    "SEC-K8S-HELM-001":              ["IAM-09"],
    "SEC-K8S-HELM-002":              ["AIS-07"],
    "SEC-AWS-ECS-001":               ["IAM-09"],
    "SEC-AWS-ECS-002":               ["IAM-09"],
    "SEC-GCP-GKE-NETWORK-POLICY-001": ["IVS-04"],
    "SEC-GCP-COMPUTE-SHIELDED-001":  ["IVS-03"],
    "STK-GCP-GKE-NODEPOOL-001":      ["IVS-03"],

    # Auth / MFA
    "SEC-AWS-COGNITO-001":           ["IAM-12"],
    "SEC-AWS-COGNITO-002":           ["IAM-02"],
    "SEC-AZURE-VM-001":              ["IAM-12"],
    "SEC-GCP-REDIS-001":             ["IAM-02"],

    # IMDS / metadata
    "SEC-AWS-EC2-IMDS-001":          ["IVS-03"],
    "STK-AWS-LAUNCH-TEMPLATE-001":   ["IVS-03"],

    # Provisioner / data-source
    "SEC-PROVISIONER-001":           ["CCC-05"],
    "SEC-DATASOURCE-001":            ["CEK-09"],
    "SEC-DATASOURCE-002":            ["CCC-05"],
}


# ─── SLSA manifest ─────────────────────────────────────────────────
# Tagging the supply-chain rules; the engine maps `--compliance-framework
# slsa` against these. Values use the schema-allowed token set:
# `L1`/`L2`/`L3`/`L4` (level) or `source`/`build`/`deps` (track).
SLSA_MAPPINGS: dict[str, list[str]] = {
    "MOD-PIN-001":                   ["L2", "deps"],
    "MOD-STALE-001":                 ["deps"],
    "MOD-SUPPLY-001":                ["L2", "deps"],
    "MOD-SUPPLY-002":                ["L2", "deps"],
    "MOD-SUPPLY-003":                ["L2", "deps"],
    "ROB-VERSION-001":               ["L2", "deps"],
    "ROB-VERSION-002":               ["L1", "source"],
    "ROB-VERSION-003":               ["L2", "deps"],
    "STK-DEFAULTS-001":              ["L1", "source"],
    "STK-GCP-DEPRECATION-001":       ["deps"],
    "STK-AZURE-SQL-001":             ["deps"],
    "STK-GCP-CLOUDSQL-005":          ["deps"],
    "ROB-PROVIDER-ALIAS-001":        ["source"],
    "ROB-PROVIDER-ALIAS-002":        ["source"],
    "ROB-BACKEND-001":               ["source"],
    "ROB-REMOTESTATE-001":           ["source"],
    "SEC-STATE-001":                 ["source"],
    "SEC-PROVISIONER-001":           ["build"],
    "SEC-PROVISIONER-002":           ["build"],
    "SEC-DATASOURCE-001":            ["build"],
    "SEC-DATASOURCE-002":            ["build"],
    "SEC-DATASOURCE-003":            ["build"],
    "SEC-AWS-IAM-OIDC-001":          ["L3", "build"],
    "SEC-SUPPLY-001":                ["L2", "deps"],
    "SEC-CICD-001":                  ["L3", "build"],
    "SEC-CICD-002":                  ["L2", "build"],
    "SEC-CICD-003":                  ["L3", "build"],
    "MOD-REUSE-AWS-VPC-001":         ["deps"],
    "MOD-REUSE-AZURE-AKS-001":       ["deps"],
    "MOD-REUSE-GCP-NETWORK-001":     ["deps"],
}


# ─── Insertion logic (mirrors apply_mitre.insert_field) ────────────

def insert_field(text: str, field: str, items: list[str]) -> str:
    """Insert or replace a list-of-strings field in a catalogue YAML.

    Insertion priority for new blocks:
      1. After the last existing of (cis, mitre, cwe, d3fend, soc2_cc,
         pci_dss, owasp_iac, owasp, nist_csf, nist_800_53, csa_ccm,
         slsa, applies_when) — keeps related fields grouped.
      2. After `status:`.
      3. Before `patterns:`.
    """
    if not items:
        return text

    line_start = field + ":"

    # Replace existing block (preserve identical content; idempotent).
    if f"\n{line_start}" in text or text.startswith(line_start):
        # If the existing field already lists every desired item (in any
        # order), leave the file untouched — keeps the diff small on
        # re-runs and respects hand-curated entries from Round 30 batch.
        lines = text.splitlines(keepends=True)
        i = 0
        existing: list[str] = []
        while i < len(lines):
            if lines[i].startswith(line_start):
                i += 1
                while i < len(lines) and (lines[i].startswith(" ") or lines[i].startswith("\t")):
                    s = lines[i].strip()
                    if s.startswith("- "):
                        v = s[2:].strip()
                        if v.startswith('"') and v.endswith('"'):
                            v = v[1:-1]
                        existing.append(v)
                    i += 1
                break
            i += 1
        if set(existing) == set(items):
            return text
        # Replace the block in place.
        lines = text.splitlines(keepends=True)
        out: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith(line_start):
                i += 1
                while i < len(lines) and (lines[i].startswith(" ") or lines[i].startswith("\t")):
                    i += 1
                out.append(f"{field}:\n")
                for it in items:
                    out.append(f'  - "{it}"\n')
                continue
            out.append(line)
            i += 1
        return "".join(out)

    # New block — find an anchor.
    lines = text.splitlines(keepends=True)
    grouping_anchors = (
        "cis:", "mitre:", "cwe:", "d3fend:", "soc2_cc:",
        "pci_dss:", "owasp_iac:", "owasp:",
        "nist_csf:", "nist_800_53:", "csa_ccm:", "slsa:",
        "applies_when:",
    )
    anchor_idx: int | None = None
    for i, line in enumerate(lines):
        if line.startswith(grouping_anchors):
            j = i + 1
            while j < len(lines) and (lines[j].startswith(" ") or lines[j].startswith("\t")):
                j += 1
            anchor_idx = j  # insert before lines[j]
    if anchor_idx is None:
        for i, line in enumerate(lines):
            if line.startswith("status:"):
                anchor_idx = i + 1
                break
    if anchor_idx is None:
        for i, line in enumerate(lines):
            if line.startswith("patterns:"):
                anchor_idx = i
                break
    if anchor_idx is None:
        return text  # give up

    insertion = [f"{field}:\n"] + [f'  - "{it}"\n' for it in items]
    return "".join(lines[:anchor_idx] + insertion + lines[anchor_idx:])


def main() -> int:
    ALL_RULES = sorted(
        set(NIST_CSF_MAPPINGS) | set(NIST_800_53_MAPPINGS)
        | set(CSA_CCM_MAPPINGS) | set(SLSA_MAPPINGS)
    )
    written = 0
    skipped_missing = 0
    for rule_id in ALL_RULES:
        path = CATALOG / f"{rule_id}.yaml"
        if not path.exists():
            print(f"  SKIP (no file): {rule_id}", file=sys.stderr)
            skipped_missing += 1
            continue
        original = path.read_text()
        updated = original
        if rule_id in NIST_CSF_MAPPINGS:
            updated = insert_field(updated, "nist_csf", NIST_CSF_MAPPINGS[rule_id])
        if rule_id in NIST_800_53_MAPPINGS:
            updated = insert_field(updated, "nist_800_53", NIST_800_53_MAPPINGS[rule_id])
        if rule_id in CSA_CCM_MAPPINGS:
            updated = insert_field(updated, "csa_ccm", CSA_CCM_MAPPINGS[rule_id])
        if rule_id in SLSA_MAPPINGS:
            updated = insert_field(updated, "slsa", SLSA_MAPPINGS[rule_id])
        if updated != original:
            path.write_text(updated)
            written += 1
            tags = []
            if rule_id in NIST_CSF_MAPPINGS:
                tags.append(f"nist_csf={NIST_CSF_MAPPINGS[rule_id]}")
            if rule_id in NIST_800_53_MAPPINGS:
                tags.append(f"nist_800_53={NIST_800_53_MAPPINGS[rule_id]}")
            if rule_id in CSA_CCM_MAPPINGS:
                tags.append(f"csa_ccm={CSA_CCM_MAPPINGS[rule_id]}")
            if rule_id in SLSA_MAPPINGS:
                tags.append(f"slsa={SLSA_MAPPINGS[rule_id]}")
            print(f"  UPDATED {rule_id}: {' '.join(tags)}")
    print()
    print(f"Catalogue rules updated: {written}/{len(ALL_RULES)}  "
          f"(missing files: {skipped_missing})")
    print(f"  NIST CSF mappings:    {len(NIST_CSF_MAPPINGS)}")
    print(f"  NIST 800-53 mappings: {len(NIST_800_53_MAPPINGS)}")
    print(f"  CSA CCM mappings:     {len(CSA_CCM_MAPPINGS)}")
    print(f"  SLSA mappings:        {len(SLSA_MAPPINGS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
