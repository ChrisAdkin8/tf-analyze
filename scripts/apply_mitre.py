#!/usr/bin/env python3
"""Apply MITRE ATT&CK + CWE + D3FEND tag manifests to the catalogue.

Reads three in-script manifests (`MITRE_MAPPINGS`, `CWE_MAPPINGS`,
`D3FEND_MAPPINGS`) keyed on rule_id and inserts/updates the
`mitre:` / `cwe:` / `d3fend:` blocks in each YAML. Idempotent —
re-running won't duplicate or reorder existing entries.

Manifest curation principles:
  * Only map where the link is unambiguous; vague mappings hurt rather
    than help. A rule that arguably maps to 3 ATT&CK techniques and
    obviously to 1 should list the 1.
  * Prefer the most-specific sub-technique (T1078.004 over T1078).
  * D3FEND mappings are derived from the rule's MITRE tags via D3FEND's
    own ATT&CK ↔ D3FEND mapping; entries here are the curated subset.

Run:  python3 scripts/apply_mitre.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG = REPO_ROOT / "catalog"

# ─── MITRE ATT&CK technique manifest ───────────────────────────────
# T-IDs come from https://attack.mitre.org/. Pinned against ATT&CK v17
# (April 2025); see scripts/detect.py:MITRE_ATTACK_VERSION.
MITRE_MAPPINGS: dict[str, list[str]] = {
    # ── Existing manifest (preserved verbatim) ────────────────────
    # Credentials, secrets, identity
    "SEC-AWS-IAM-001":             ["T1078.004"],
    "SEC-AWS-IAM-002":             ["T1078.004"],
    "SEC-AWS-IAM-003":             ["T1098.001", "T1078.004"],
    "SEC-AWS-IAM-ACCESSKEY-001":   ["T1552.001", "T1078.004"],
    "SEC-AWS-IAM-USER-001":        ["T1078.004"],
    "SEC-AWS-COGNITO-001":         ["T1556.006"],
    "SEC-CRED-001":                ["T1552.001"],
    "SEC-CRED-002":                ["T1552.001"],
    "SEC-PROVISIONER-001":         ["T1059"],
    "SEC-PROVIDER-PLAINTEXT-001":  ["T1552.001"],
    "SEC-DATASOURCE-001":          ["T1552.001"],
    "SEC-SENSITIVE-001":           ["T1552.001"],
    "SEC-SENSITIVE-002":           ["T1552.001"],
    "SEC-SENSITIVE-003":           ["T1552.001"],

    # Network exposure / public-facing
    "SEC-AWS-LB-LISTENER-001":     ["T1071.001"],
    "SEC-AWS-CLOUDFRONT-001":      ["T1071.001"],
    "SEC-AWS-CLOUDFRONT-002":      ["T1071.001"],
    "SEC-AWS-APIGW-001":           ["T1190"],
    "SEC-AWS-COGNITO-002":         ["T1190"],
    "SEC-AZURE-NSG-001":           ["T1190", "T1133"],
    "SEC-GCP-FW-001":              ["T1190", "T1133"],
    "SEC-GCP-FW-SSH-001":          ["T1133"],
    "SEC-GCP-FW-RDP-001":          ["T1133"],

    # Disabled defenses / impaired logging
    "SEC-AWS-CLOUDTRAIL-001":      ["T1562.008"],
    "SEC-AWS-CLOUDTRAIL-002":      ["T1562.008"],
    "SEC-AWS-VPC-FLOWLOGS-001":    ["T1562.008"],
    "SEC-AWS-CWL-001":             ["T1562.008"],
    "SEC-AWS-S3-LOGGING-001":      ["T1562.008"],
    "SEC-AWS-GUARDDUTY-001":       ["T1562.001"],
    "SEC-AWS-SECURITYHUB-001":     ["T1562.001"],
    "SEC-AWS-WAF-001":             ["T1562.004"],
    "SEC-AZURE-LOGGING-001":       ["T1562.008"],
    "SEC-AZURE-MONITOR-001":       ["T1562.008"],
    "SEC-GCP-LOGGING-001":         ["T1562.008"],

    # Encryption-at-rest / key management
    "SEC-AWS-S3-001":              ["T1530"],
    "SEC-AWS-EBS-001":             ["T1530"],
    "SEC-AWS-RDS-ENCRYPT-001":     ["T1530"],
    "SEC-AWS-DDB-001":             ["T1530"],
    "SEC-AWS-DOCDB-001":           ["T1530"],
    "SEC-AWS-REDSHIFT-001":        ["T1530"],
    "SEC-AWS-KINESIS-001":         ["T1530"],
    "SEC-AWS-NEPTUNE-001":         ["T1530"],
    "SEC-AZURE-SQL-001":           ["T1530"],
    "SEC-AZURE-KV-001":            ["T1530"],
    "SEC-AZURE-KV-002":            ["T1530", "T1133"],
    "SEC-GCP-CMEK-001":            ["T1530"],

    # IMDSv2 / container / metadata
    "SEC-AWS-EC2-IMDS-001":        ["T1552.005"],
    "STK-AWS-LAUNCH-TEMPLATE-001": ["T1552.005"],
    "SEC-AWS-ECS-001":             ["T1552.001"],
    "SEC-AWS-ECS-002":             ["T1611"],

    # Public storage objects
    "SEC-AWS-S3-PUBLIC-BLOCK-001": ["T1530"],
    "SEC-AWS-CLOUDFRONT-S3-001":   ["T1530"],
    "SEC-GCP-BUCKET-PUBLIC-001":   ["T1530"],

    # Provisioning / supply chain / state
    "SEC-STATE-001":               ["T1552.001"],
    "MOD-SUPPLY-001":              ["T1195.002"],
    "MOD-SUPPLY-002":              ["T1195.002"],
    "MOD-SUPPLY-003":              ["T1195.002"],

    # ── Sweep additions: 2026-05-10 (closing the GCP/Azure/robustness gaps) ────

    # Module / supply-chain (was 0/3 module-reuse + several MOD- gaps)
    "MOD-PIN-001":                 ["T1195.002"],
    "MOD-STALE-001":               ["T1195.002"],
    "MOD-REUSE-AWS-VPC-001":       ["T1195.002"],
    "MOD-REUSE-AZURE-AKS-001":     ["T1195.002"],
    "MOD-REUSE-GCP-NETWORK-001":   ["T1195.002"],

    # Cost — relevant to crypto-mining via expensive resources (T1496 Resource Hijacking)
    "COST-AWS-RISK-001":           ["T1496"],
    "COST-GCP-RISK-001":           ["T1496"],

    # Ops — logging-retention / deletion-protection
    "OPS-AWS-CWL-001":             ["T1562.008"],
    "OPS-ENV-001":                 ["T1485"],

    # Robustness — drift / Defense Evasion family
    "ROB-DRIFT-001":               ["T1562.001"],
    "ROB-DRIFT-002":               ["T1562.001"],
    "ROB-DRIFT-003":               ["T1562.001"],

    # Robustness — data destruction (deletion-protection / lifecycle / force_destroy)
    "ROB-AWS-ALB-001":             ["T1485"],
    "ROB-AWS-DDB-001":             ["T1485"],
    "ROB-AWS-LIFECYCLE-001":       ["T1485"],
    "ROB-AWS-LIFECYCLE-002":       ["T1485"],
    "ROB-AWS-RDS-003":             ["T1485"],
    "ROB-AZURE-LIFECYCLE-001":     ["T1485"],
    "ROB-GCP-LIFECYCLE-001":       ["T1485"],
    "ROB-GCP-LIFECYCLE-002":       ["T1485"],

    # Robustness — recovery inhibition (no backups / no PITR / no snapshots / versioning off)
    "ROB-AWS-BACKUP-001":          ["T1490"],
    "ROB-AWS-DDB-002":             ["T1490"],
    "ROB-AWS-RDS-001":             ["T1490"],
    "ROB-AWS-RDS-002":             ["T1490"],
    "ROB-AWS-REDSHIFT-001":        ["T1490"],
    "ROB-AWS-S3-001":              ["T1490"],
    "ROB-AZURE-SQL-001":           ["T1490"],
    "ROB-AZURE-STORAGE-001":       ["T1485", "T1490"],

    # Robustness — credential rotation
    "ROB-AWS-SECRETSMANAGER-001":  ["T1078.004", "T1098.001"],

    # Robustness — provider-version supply chain
    "ROB-VERSION-001":             ["T1195.002"],
    "ROB-VERSION-002":             ["T1195.002"],
    "ROB-VERSION-003":             ["T1195.002"],

    # ── Azure — was 5/34, sweep target ~20 ────────────────────
    "SEC-AZURE-ACR-001":           ["T1078.004"],
    "SEC-AZURE-AKS-001":           ["T1078.004"],
    "SEC-AZURE-AKS-002":           ["T1133", "T1611"],
    "SEC-AZURE-EVENTHUB-001":      ["T1530"],
    "SEC-AZURE-KV-003":            ["T1098.001"],
    "SEC-AZURE-MI-001":            ["T1078.004"],
    "SEC-AZURE-RBAC-001":          ["T1078.004"],
    "SEC-AZURE-REDIS-001":         ["T1040", "T1071.001"],
    "SEC-AZURE-SERVICEBUS-001":    ["T1530"],
    "SEC-AZURE-SQL-002":           ["T1190"],
    "SEC-AZURE-STORAGE-001":       ["T1071.001"],
    "SEC-AZURE-STORAGE-002":       ["T1530"],
    "SEC-AZURE-VM-001":            ["T1110.001"],
    "SEC-AZURE-WEBAPP-001":        ["T1133"],
    "SEC-AZURE-WEBAPP-002":        ["T1071.001"],
    "STK-AZURE-AKS-003":           ["T1078.004"],
    "STK-AZURE-AKS-004":           ["T1190"],
    "STK-AZURE-AKS-005":           ["T1190", "T1133"],
    "STK-AZURE-DB-001":            ["T1040"],
    "STK-AZURE-NSG-FLOWLOG-001":   ["T1562.008"],
    "STK-AZURE-SQL-001":           ["T1195.002"],
    "STK-AZURE-SQL-TDE-001":       ["T1530"],
    "STK-AZURE-STORAGE-001":       ["T1490"],

    # ── GCP — was 1/43, sweep target ~25 ─────────────────────
    "SEC-GCP-BUCKET-001":          ["T1530"],
    "SEC-GCP-BUCKET-002":          ["T1530"],
    "SEC-GCP-CLOUDRUN-001":        ["T1190"],
    "SEC-GCP-COMPUTE-DISK-001":    ["T1530"],
    "SEC-GCP-COMPUTE-PUBLIC-IP-001": ["T1190"],
    "SEC-GCP-COMPUTE-SA-001":      ["T1078.004"],
    "SEC-GCP-COMPUTE-SHIELDED-001": ["T1542.003"],
    "SEC-GCP-GKE-NETWORK-POLICY-001": ["T1611"],
    "SEC-GCP-IAM-001":             ["T1078.004"],
    "SEC-GCP-IAM-002":             ["T1078.004"],
    "SEC-GCP-IAM-003":             ["T1098.001", "T1078.004"],
    "SEC-GCP-NETWORK-001":         ["T1190", "T1133"],
    "SEC-GCP-NETWORK-002":         ["T1190", "T1133"],
    "SEC-GCP-NETWORK-003":         ["T1562.008"],
    "SEC-GCP-NETWORK-004":         ["T1190"],
    "SEC-GCP-REDIS-001":           ["T1078"],
    "SEC-GCP-REDIS-002":           ["T1040"],
    "SEC-GCP-SA-KEY-001":          ["T1098.001", "T1552.001"],
    "SEC-GCP-SQL-PUBLIC-001":      ["T1190"],
    "STK-GCP-ARTIFACT-001":        ["T1530"],
    "STK-GCP-BIGQUERY-001":        ["T1530"],
    "STK-GCP-BUCKET-001":          ["T1490"],
    "STK-GCP-CLOUDSQL-001":        ["T1490"],
    "STK-GCP-CLOUDSQL-003":        ["T1485"],
    "STK-GCP-CLOUDSQL-004":        ["T1040"],
    "STK-GCP-CLOUDSQL-005":        ["T1190", "T1195.002"],
    "STK-GCP-DEPRECATION-001":     ["T1195.002"],
    "STK-GCP-DNS-001":             ["T1583.002"],
    "STK-GCP-GCS-LOGGING-001":     ["T1530", "T1562.008"],
    "STK-GCP-GKE-001":             ["T1190"],
    "STK-GCP-GKE-002":             ["T1078.004"],
    "STK-GCP-GKE-003":             ["T1552.001"],
    "STK-GCP-GKE-004":             ["T1190"],
    "STK-GCP-GKE-NODEPOOL-001":    ["T1542.003"],
    "STK-GCP-KMS-001":             ["T1098.001", "T1552.001"],
    "STK-GCP-PUBSUB-001":          ["T1530"],
}

# ─── CWE manifest ─────────────────────────────────────────────────
# Common Weakness Enumeration. Tags are inserted as "CWE-<digits>"
# (the SARIF taxonomy form). The 2025 CWE Top 25 emphasised cloud /
# API authorisation weaknesses — the bulk-mappable patterns:
CWE_MAPPINGS: dict[str, list[str]] = {
    # IAM wildcard / overly broad role / privilege management (CWE-269 + CWE-732)
    "SEC-AWS-IAM-001":             ["CWE-269", "CWE-732"],
    "SEC-AWS-IAM-002":             ["CWE-269", "CWE-732"],
    "SEC-AWS-IAM-003":             ["CWE-269"],
    "SEC-AWS-IAM-USER-001":        ["CWE-269"],
    "SEC-AWS-IAM-JSON-001":        ["CWE-269", "CWE-732"],
    "SEC-AWS-IAM-JSON-002":        ["CWE-269", "CWE-732"],
    "SEC-AWS-IAM-JSON-003":        ["CWE-269", "CWE-732"],
    "SEC-AWS-IAM-JSON-004":        ["CWE-269"],
    "SEC-AWS-IAM-POLICY-001":      ["CWE-269", "CWE-732"],
    "SEC-AWS-IAM-POLICY-002":      ["CWE-269", "CWE-732"],
    "SEC-AWS-IAM-POLICY-003":      ["CWE-269"],
    "SEC-AWS-IAM-POLICY-004":      ["CWE-269"],
    "SEC-AWS-IAM-POLICY-005":      ["CWE-269", "CWE-732"],
    "SEC-AWS-IAM-POLICY-006":      ["CWE-269"],
    "SEC-GCP-IAM-001":             ["CWE-269", "CWE-732"],
    "SEC-GCP-IAM-002":             ["CWE-284", "CWE-732"],
    "SEC-GCP-IAM-003":             ["CWE-269"],
    "SEC-AZURE-RBAC-001":          ["CWE-269"],

    # Hardcoded credentials / secrets (CWE-798)
    "SEC-CRED-001":                ["CWE-798"],
    "SEC-CRED-002":                ["CWE-798"],
    "SEC-PROVIDER-PLAINTEXT-001":  ["CWE-798"],
    "SEC-SECRETS-001":             ["CWE-798"],
    "SEC-AWS-IAM-ACCESSKEY-001":   ["CWE-798", "CWE-321"],

    # Cleartext storage / missing encryption at rest (CWE-311 + CWE-312)
    "SEC-AWS-S3-001":              ["CWE-311", "CWE-312"],
    "SEC-AWS-EBS-001":             ["CWE-311"],
    "SEC-AWS-RDS-ENCRYPT-001":     ["CWE-311"],
    "SEC-AWS-DDB-001":             ["CWE-311"],
    "SEC-AWS-DOCDB-001":           ["CWE-311"],
    "SEC-AWS-REDSHIFT-001":        ["CWE-311"],
    "SEC-AWS-KINESIS-001":         ["CWE-311"],
    "SEC-AWS-NEPTUNE-001":         ["CWE-311"],
    "SEC-AZURE-SQL-001":           ["CWE-311"],
    "SEC-AZURE-KV-001":            ["CWE-311"],
    "SEC-AZURE-EVENTHUB-001":      ["CWE-311"],
    "SEC-AZURE-SERVICEBUS-001":    ["CWE-311"],
    "SEC-GCP-CMEK-001":            ["CWE-311"],
    "SEC-GCP-COMPUTE-DISK-001":    ["CWE-311"],
    "STK-GCP-ARTIFACT-001":        ["CWE-311"],
    "STK-GCP-BIGQUERY-001":        ["CWE-311"],
    "STK-GCP-PUBSUB-001":          ["CWE-311"],
    "STK-AZURE-SQL-TDE-001":       ["CWE-311"],

    # Cleartext transmission / non-HTTPS (CWE-319)
    "SEC-AZURE-STORAGE-001":       ["CWE-319"],
    "SEC-AZURE-WEBAPP-002":        ["CWE-319"],
    "SEC-AZURE-REDIS-001":         ["CWE-319"],
    "STK-AZURE-DB-001":            ["CWE-319"],
    "STK-GCP-CLOUDSQL-004":        ["CWE-319"],
    "SEC-AWS-LB-LISTENER-001":     ["CWE-319"],
    "SEC-AWS-CLOUDFRONT-001":      ["CWE-319"],
    "SEC-AWS-CLOUDFRONT-002":      ["CWE-319"],
    "SEC-GCP-REDIS-002":           ["CWE-319"],

    # Public storage / improper access control (CWE-732 + CWE-284)
    "SEC-AWS-S3-PUBLIC-BLOCK-001": ["CWE-732", "CWE-284"],
    "SEC-AWS-CLOUDFRONT-S3-001":   ["CWE-732", "CWE-284"],
    "SEC-GCP-BUCKET-PUBLIC-001":   ["CWE-732", "CWE-284"],
    "SEC-GCP-BUCKET-001":          ["CWE-732", "CWE-284"],
    "SEC-GCP-BUCKET-002":          ["CWE-732", "CWE-284"],
    "SEC-AZURE-STORAGE-002":       ["CWE-732", "CWE-284"],

    # Network exposure / 0.0.0.0/0 ingress (CWE-284 + CWE-1327)
    "SEC-AZURE-NSG-001":           ["CWE-284", "CWE-1327"],
    "SEC-GCP-FW-001":              ["CWE-284", "CWE-1327"],
    "SEC-GCP-FW-SSH-001":          ["CWE-284", "CWE-1327"],
    "SEC-GCP-FW-RDP-001":          ["CWE-284", "CWE-1327"],
    "SEC-GCP-NETWORK-001":         ["CWE-284", "CWE-1327"],
    "SEC-GCP-NETWORK-002":         ["CWE-284", "CWE-1327"],
    "SEC-GCP-NETWORK-004":         ["CWE-284", "CWE-1327"],
    "SEC-GCP-CLOUDRUN-001":        ["CWE-284"],
    "SEC-GCP-COMPUTE-PUBLIC-IP-001": ["CWE-284"],
    "SEC-GCP-SQL-PUBLIC-001":      ["CWE-284"],
    "SEC-AZURE-SQL-002":           ["CWE-284"],
    "SEC-AZURE-WEBAPP-001":        ["CWE-284"],
    "STK-AZURE-AKS-004":           ["CWE-284"],
    "STK-AZURE-AKS-005":           ["CWE-284"],
    "STK-AZURE-NSG-001":           ["CWE-284"],
    "STK-GCP-GKE-001":             ["CWE-284"],
    "STK-GCP-GKE-004":             ["CWE-284"],
    "SEC-AWS-APIGW-001":           ["CWE-284"],

    # Missing authentication / weak auth (CWE-306 + CWE-307 + CWE-521)
    "SEC-GCP-REDIS-001":           ["CWE-306"],
    "SEC-AZURE-VM-001":            ["CWE-521", "CWE-307"],
    "SEC-AWS-COGNITO-001":         ["CWE-308"],
    "SEC-AWS-COGNITO-002":         ["CWE-306"],

    # Insufficient logging / disabled logging (CWE-778 + CWE-693)
    "SEC-AWS-CLOUDTRAIL-001":      ["CWE-778"],
    "SEC-AWS-CLOUDTRAIL-002":      ["CWE-778"],
    "SEC-AWS-VPC-FLOWLOGS-001":    ["CWE-778"],
    "SEC-AWS-CWL-001":             ["CWE-778"],
    "SEC-AWS-S3-LOGGING-001":      ["CWE-778"],
    "SEC-AZURE-LOGGING-001":       ["CWE-778"],
    "SEC-AZURE-MONITOR-001":       ["CWE-778"],
    "SEC-GCP-LOGGING-001":         ["CWE-778"],
    "SEC-GCP-NETWORK-003":         ["CWE-778"],
    "SEC-AWS-GUARDDUTY-001":       ["CWE-693"],
    "SEC-AWS-SECURITYHUB-001":     ["CWE-693"],
    "SEC-AWS-WAF-001":             ["CWE-693"],
    "OPS-AWS-CWL-001":             ["CWE-778"],
    "STK-AZURE-NSG-FLOWLOG-001":   ["CWE-778"],
    "STK-GCP-GCS-LOGGING-001":     ["CWE-778"],

    # Excessive privilege / unnecessary privileges (CWE-250)
    "SEC-AZURE-ACR-001":           ["CWE-250"],
    "SEC-GCP-COMPUTE-SA-001":      ["CWE-250"],
    "SEC-AZURE-MI-001":            ["CWE-250"],

    # Files / data accessible to external parties (CWE-552)
    "SEC-AWS-ECS-001":             ["CWE-552", "CWE-522"],
    "STK-GCP-GKE-003":             ["CWE-522"],
    "SEC-DATASOURCE-001":          ["CWE-829"],
    "SEC-DATASOURCE-002":          ["CWE-78"],
    "SEC-PROVISIONER-001":         ["CWE-78"],

    # Information exposure (CWE-200 + CWE-532)
    "SEC-SENSITIVE-001":           ["CWE-200", "CWE-532"],
    "SEC-SENSITIVE-002":           ["CWE-200"],
    "SEC-SENSITIVE-003":           ["CWE-200"],

    # Use of unmaintained / EOL components (CWE-1104 + CWE-1395)
    "STK-GCP-CLOUDSQL-005":        ["CWE-1104"],
    "STK-AZURE-SQL-001":           ["CWE-1104"],
    "STK-GCP-DEPRECATION-001":     ["CWE-1104"],

    # Supply chain / vulnerable dependencies (CWE-1395 + CWE-1357)
    "MOD-PIN-001":                 ["CWE-1357"],
    "MOD-STALE-001":               ["CWE-1395"],
    "MOD-SUPPLY-001":              ["CWE-1357"],
    "MOD-SUPPLY-002":              ["CWE-1357"],
    "MOD-SUPPLY-003":              ["CWE-1357"],
    "ROB-VERSION-001":             ["CWE-1357"],
    "ROB-VERSION-002":             ["CWE-1357"],
    "ROB-VERSION-003":             ["CWE-1357"],

    # Brute force / weak auth attempts (already captured above)
    # Improper protection mechanism (CWE-693) — drift / lifecycle
    "ROB-DRIFT-001":               ["CWE-693"],
    "ROB-DRIFT-002":               ["CWE-693"],
    "ROB-DRIFT-003":               ["CWE-693"],
    "ROB-AWS-LIFECYCLE-001":       ["CWE-693"],
    "ROB-AZURE-LIFECYCLE-001":     ["CWE-693"],
    "ROB-GCP-LIFECYCLE-001":       ["CWE-693"],

    # IMDS / metadata exposure (CWE-668 Exposure of Resource to Wrong Sphere)
    "SEC-AWS-EC2-IMDS-001":        ["CWE-668"],
    "STK-AWS-LAUNCH-TEMPLATE-001": ["CWE-668"],

    # Container escape / shielded VM (CWE-250)
    "SEC-AWS-ECS-002":             ["CWE-250"],
    "SEC-GCP-COMPUTE-SHIELDED-001": ["CWE-1278"],
    "STK-GCP-GKE-NODEPOOL-001":    ["CWE-1278"],

    # Module-reuse advisor — supply chain hygiene
    "MOD-REUSE-AWS-VPC-001":       ["CWE-1357"],
    "MOD-REUSE-AZURE-AKS-001":     ["CWE-1357"],
    "MOD-REUSE-GCP-NETWORK-001":   ["CWE-1357"],
}

# ─── D3FEND manifest ───────────────────────────────────────────────
# D3FEND defensive techniques. Mapping is derived from each rule's
# MITRE tags via D3FEND's own ATT&CK ↔ D3FEND ontology — entries here
# are the curated subset that have a clean defensive narrative for an
# IaC scanner. No comparable OSS scanner emits these today.
#
# Common D3FEND IDs used below:
#   D3-MFA   Multi-factor Authentication
#   D3-SPP   Strong Password Policy
#   D3-AL    Account Locking
#   D3-EAR   Encrypted Sensitive Data (Encryption at Rest)
#   D3-EI    Encrypted Information / Encrypted In Transit
#   D3-IAA   Inbound Application Allow-listing
#   D3-NTA   Network Traffic Analysis
#   D3-FAA   File Access Auditing
#   D3-CH    Credential Hardening
#   D3-SCA   Software Component Analysis
#   D3-PA    Privileged Account Management
D3FEND_MAPPINGS: dict[str, list[str]] = {
    # IAM / identity hardening — credentials, MFA, privilege management
    "SEC-AWS-IAM-001":             ["D3-PA", "D3-MFA"],
    "SEC-AWS-IAM-002":             ["D3-PA", "D3-MFA"],
    "SEC-AWS-IAM-003":             ["D3-PA"],
    "SEC-AWS-IAM-USER-001":        ["D3-PA", "D3-MFA"],
    "SEC-AWS-IAM-ACCESSKEY-001":   ["D3-CH", "D3-AL"],
    "SEC-AWS-COGNITO-001":         ["D3-MFA"],
    "SEC-GCP-IAM-001":             ["D3-PA"],
    "SEC-GCP-IAM-002":             ["D3-PA"],
    "SEC-GCP-IAM-003":             ["D3-PA"],
    "SEC-AZURE-RBAC-001":          ["D3-PA"],
    "SEC-AZURE-MI-001":            ["D3-PA"],
    "SEC-GCP-COMPUTE-SA-001":      ["D3-PA"],

    # Credential hardening — secrets, tokens, plaintext
    "SEC-CRED-001":                ["D3-CH"],
    "SEC-CRED-002":                ["D3-CH"],
    "SEC-SECRETS-001":             ["D3-CH"],
    "SEC-PROVIDER-PLAINTEXT-001":  ["D3-CH"],
    "SEC-SENSITIVE-001":           ["D3-CH"],
    "SEC-SENSITIVE-002":           ["D3-CH"],
    "SEC-SENSITIVE-003":           ["D3-CH"],

    # Encryption at rest
    "SEC-AWS-S3-001":              ["D3-EAR"],
    "SEC-AWS-EBS-001":             ["D3-EAR"],
    "SEC-AWS-RDS-ENCRYPT-001":     ["D3-EAR"],
    "SEC-AWS-DDB-001":             ["D3-EAR"],
    "SEC-AWS-DOCDB-001":           ["D3-EAR"],
    "SEC-AWS-REDSHIFT-001":        ["D3-EAR"],
    "SEC-AWS-KINESIS-001":         ["D3-EAR"],
    "SEC-AWS-NEPTUNE-001":         ["D3-EAR"],
    "SEC-AZURE-SQL-001":           ["D3-EAR"],
    "SEC-AZURE-KV-001":            ["D3-EAR"],
    "SEC-AZURE-EVENTHUB-001":      ["D3-EAR"],
    "SEC-AZURE-SERVICEBUS-001":    ["D3-EAR"],
    "SEC-GCP-CMEK-001":            ["D3-EAR"],
    "SEC-GCP-COMPUTE-DISK-001":    ["D3-EAR"],
    "STK-GCP-ARTIFACT-001":        ["D3-EAR"],
    "STK-GCP-BIGQUERY-001":        ["D3-EAR"],
    "STK-GCP-PUBSUB-001":          ["D3-EAR"],
    "STK-AZURE-SQL-TDE-001":       ["D3-EAR"],

    # Encryption in transit
    "SEC-AZURE-STORAGE-001":       ["D3-EI"],
    "SEC-AZURE-WEBAPP-002":        ["D3-EI"],
    "SEC-AZURE-REDIS-001":         ["D3-EI"],
    "STK-AZURE-DB-001":            ["D3-EI"],
    "STK-GCP-CLOUDSQL-004":        ["D3-EI"],
    "SEC-AWS-LB-LISTENER-001":     ["D3-EI"],
    "SEC-AWS-CLOUDFRONT-001":      ["D3-EI"],
    "SEC-AWS-CLOUDFRONT-002":      ["D3-EI"],
    "SEC-GCP-REDIS-002":           ["D3-EI"],

    # Inbound filtering / network exposure (D3-IAA Inbound Application Allow-listing, D3-NTA Network Traffic Analysis)
    "SEC-AZURE-NSG-001":           ["D3-IAA", "D3-NTA"],
    "SEC-GCP-FW-001":              ["D3-IAA"],
    "SEC-GCP-FW-SSH-001":          ["D3-IAA"],
    "SEC-GCP-FW-RDP-001":          ["D3-IAA"],
    "SEC-GCP-NETWORK-001":         ["D3-IAA"],
    "SEC-GCP-NETWORK-002":         ["D3-IAA"],
    "SEC-GCP-NETWORK-004":         ["D3-IAA"],
    "SEC-GCP-CLOUDRUN-001":        ["D3-IAA"],
    "SEC-GCP-COMPUTE-PUBLIC-IP-001": ["D3-IAA"],
    "SEC-GCP-SQL-PUBLIC-001":      ["D3-IAA"],
    "SEC-AZURE-SQL-002":           ["D3-IAA"],
    "SEC-AZURE-WEBAPP-001":        ["D3-IAA"],
    "STK-AZURE-AKS-004":           ["D3-IAA"],
    "STK-AZURE-AKS-005":           ["D3-IAA"],
    "STK-AZURE-NSG-001":           ["D3-IAA"],
    "STK-GCP-GKE-001":             ["D3-IAA"],
    "STK-GCP-GKE-004":             ["D3-IAA"],
    "SEC-AWS-APIGW-001":           ["D3-IAA"],

    # Logging / audit (D3-FAA File Access Auditing covers cloud logging)
    "SEC-AWS-CLOUDTRAIL-001":      ["D3-FAA"],
    "SEC-AWS-CLOUDTRAIL-002":      ["D3-FAA"],
    "SEC-AWS-VPC-FLOWLOGS-001":    ["D3-NTA"],
    "SEC-AWS-CWL-001":             ["D3-FAA"],
    "SEC-AWS-S3-LOGGING-001":      ["D3-FAA"],
    "SEC-AZURE-LOGGING-001":       ["D3-FAA"],
    "SEC-AZURE-MONITOR-001":       ["D3-FAA"],
    "SEC-GCP-LOGGING-001":         ["D3-FAA"],
    "SEC-GCP-NETWORK-003":         ["D3-NTA"],
    "OPS-AWS-CWL-001":             ["D3-FAA"],
    "STK-AZURE-NSG-FLOWLOG-001":   ["D3-NTA"],
    "STK-GCP-GCS-LOGGING-001":     ["D3-FAA"],

    # Software Component Analysis — supply chain
    "MOD-PIN-001":                 ["D3-SCA"],
    "MOD-STALE-001":               ["D3-SCA"],
    "MOD-SUPPLY-001":              ["D3-SCA"],
    "MOD-SUPPLY-002":              ["D3-SCA"],
    "MOD-SUPPLY-003":              ["D3-SCA"],
    "ROB-VERSION-001":             ["D3-SCA"],
    "ROB-VERSION-002":             ["D3-SCA"],
    "ROB-VERSION-003":             ["D3-SCA"],
    "MOD-REUSE-AWS-VPC-001":       ["D3-SCA"],
    "MOD-REUSE-AZURE-AKS-001":     ["D3-SCA"],
    "MOD-REUSE-GCP-NETWORK-001":   ["D3-SCA"],
    "STK-GCP-CLOUDSQL-005":        ["D3-SCA"],
    "STK-AZURE-SQL-001":           ["D3-SCA"],
    "STK-GCP-DEPRECATION-001":     ["D3-SCA"],

    # Account Locking — brute force defenses
    "SEC-AZURE-VM-001":            ["D3-AL", "D3-MFA"],
    "SEC-GCP-REDIS-001":           ["D3-AL"],

    # Credential rotation
    "ROB-AWS-SECRETSMANAGER-001":  ["D3-CH"],
    "STK-GCP-KMS-001":             ["D3-CH"],
    "SEC-AZURE-KV-003":            ["D3-CH"],

    # Process / VM hardening (D3FEND Harden tactic)
    "SEC-AWS-EC2-IMDS-001":        ["D3-CH"],
    "STK-AWS-LAUNCH-TEMPLATE-001": ["D3-CH"],
    "SEC-GCP-COMPUTE-SHIELDED-001": ["D3-PSH"],   # Process Spawn Analysis / shielded boot
    "STK-GCP-GKE-NODEPOOL-001":    ["D3-PSH"],
}


# ─── Insertion logic ───────────────────────────────────────────────

def insert_field(text: str, field: str, items: list[str]) -> str:
    """Insert or replace a list-of-strings field in a catalogue YAML.

    `field` must be a top-level field name like 'mitre', 'cwe', 'd3fend'.
    `items` are the literal string values; will be quoted with double-quotes.

    Insertion priority for new blocks:
      1. After the last existing of (cis, mitre, cwe, d3fend, soc2_cc,
         pci_dss, owasp_iac, applies_when) — keeps related fields grouped.
      2. After `status:`.
      3. Before `patterns:`.
    """
    if not items:
        return text

    line_start = field + ":"

    # Replace existing block.
    if f"\n{line_start}" in text or text.startswith(line_start):
        lines = text.splitlines(keepends=True)
        out = []
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
    grouping_anchors = ("cis:", "mitre:", "cwe:", "d3fend:", "soc2_cc:",
                        "pci_dss:", "owasp_iac:", "applies_when:")
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
    ALL_RULES = sorted(set(MITRE_MAPPINGS) | set(CWE_MAPPINGS) | set(D3FEND_MAPPINGS))
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
        if rule_id in MITRE_MAPPINGS:
            updated = insert_field(updated, "mitre", MITRE_MAPPINGS[rule_id])
        if rule_id in CWE_MAPPINGS:
            updated = insert_field(updated, "cwe", CWE_MAPPINGS[rule_id])
        if rule_id in D3FEND_MAPPINGS:
            updated = insert_field(updated, "d3fend", D3FEND_MAPPINGS[rule_id])
        if updated != original:
            path.write_text(updated)
            written += 1
            tags = []
            if rule_id in MITRE_MAPPINGS: tags.append(f"mitre={MITRE_MAPPINGS[rule_id]}")
            if rule_id in CWE_MAPPINGS: tags.append(f"cwe={CWE_MAPPINGS[rule_id]}")
            if rule_id in D3FEND_MAPPINGS: tags.append(f"d3fend={D3FEND_MAPPINGS[rule_id]}")
            print(f"  UPDATED {rule_id}: {' '.join(tags)}")
    print()
    print(f"Catalogue rules updated: {written}/{len(ALL_RULES)}  "
          f"(missing files: {skipped_missing})")
    print(f"  MITRE mappings:  {len(MITRE_MAPPINGS)}")
    print(f"  CWE mappings:    {len(CWE_MAPPINGS)}")
    print(f"  D3FEND mappings: {len(D3FEND_MAPPINGS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
