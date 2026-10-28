"""Severity follows docs/severity-calibration.md.

HIGH means "direct security boundary breach with realistic exploit path".
Robustness rules (data loss on delete, plan/apply correctness) are at most
MEDIUM, and a minimal, secure module passes `--fail-on HIGH`: before this
calibration a private, versioned bucket with a public access block still
failed the gate on two HIGH findings.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DETECT = REPO / "scripts" / "detect.py"

SECURE_BUCKET = """terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "acme-data"
  tags   = { team = "data" }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}
"""

SECURE_DB = """resource "aws_db_instance" "db" {
  engine                  = "postgres"
  engine_version          = "16.4"
  instance_class          = "db.t4g.micro"
  storage_encrypted       = true
  publicly_accessible     = false
  backup_retention_period = 7
  deletion_protection     = true
  tags                    = { team = "data" }
}
"""


@pytest.mark.parametrize("hcl", [SECURE_BUCKET, SECURE_DB], ids=["bucket", "rds"])
def test_a_secure_module_passes_the_high_gate(tmp_path, hcl) -> None:
    (tmp_path / "main.tf").write_text(hcl)
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(tmp_path), "--fail-on", "HIGH",
         "--format", "text"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_robustness_rules_are_at_most_medium() -> None:
    sys.path.insert(0, str(REPO / "scripts"))
    from _catalog import load_catalog

    too_high = sorted(
        e["id"] for e in load_catalog(REPO / "catalog")
        if e.get("section") == "robustness" and e.get("default_urgency") in ("HIGH", "CRITICAL")
    )
    assert not too_high, f"robustness rules above MEDIUM (see docs/severity-calibration.md): {too_high}"


# Secure-but-not-gold-plated workload modules, one per cloud. Before the
# security/stack sweep each failed `--fail-on HIGH`: AWS on SQS default
# encryption, VPC flow logs and a GuardDuty detector the module does not
# own; Azure on Key Vault network ACL and diagnostic settings; GCP on a
# private bucket without `public_access_prevention = "enforced"`.
AWS_WORKLOAD = """resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags       = { team = "app" }
}

resource "aws_sqs_queue" "jobs" {
  name = "jobs"
  tags = { team = "app" }
}

resource "aws_iam_role" "fn" {
  name = "fn"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_lambda_function" "fn" {
  function_name = "worker"
  role          = aws_iam_role.fn.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  filename      = "app.zip"
  tags          = { team = "app" }
}
"""

AZURE_WORKLOAD = """resource "azurerm_storage_account" "data" {
  name                            = "acmedata"
  resource_group_name             = "rg"
  location                        = "uksouth"
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = { team = "data" }
}

resource "azurerm_key_vault" "kv" {
  name                       = "acme-kv"
  resource_group_name        = "rg"
  location                   = "uksouth"
  tenant_id                  = "00000000-0000-0000-0000-000000000000"
  sku_name                   = "standard"
  purge_protection_enabled   = true
  soft_delete_retention_days = 90
  enable_rbac_authorization  = true
  tags                       = { team = "data" }
}
"""

GCP_WORKLOAD = """resource "google_storage_bucket" "data" {
  name                        = "acme-data"
  location                    = "EU"
  uniform_bucket_level_access = true
  versioning {
    enabled = true
  }
  labels = { team = "data" }
}

resource "google_service_account" "run" {
  account_id = "api"
}

resource "google_cloud_run_v2_service" "api" {
  name     = "api"
  location = "europe-west2"
  template {
    service_account = google_service_account.run.email
    containers {
      image = "europe-docker.pkg.dev/acme/api/api@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  }
}
"""


@pytest.mark.parametrize(
    "hcl", [AWS_WORKLOAD, AZURE_WORKLOAD, GCP_WORKLOAD], ids=["aws", "azure", "gcp"]
)
def test_a_secure_workload_passes_the_high_gate_on_each_cloud(tmp_path, hcl) -> None:
    (tmp_path / "main.tf").write_text(hcl)
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(tmp_path), "--fail-on", "HIGH",
         "--format", "text"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_hygiene_and_eol_rules_are_not_high() -> None:
    """Classes the sweep put below HIGH stay there: end-of-life runtimes,
    network/flow-log telemetry, key rotation, and network policies."""
    sys.path.insert(0, str(REPO / "scripts"))
    from _catalog import load_catalog

    pinned = {
        "STK-AWS-LAMBDA-001", "STK-AWS-RDS-004", "STK-AZURE-FUNCTION-001",
        "STK-AZURE-WEBAPP-RUNTIME-001", "STK-GCP-FUNCTIONS-001", "STK-GCP-CLOUDSQL-005",
        "STK-K8S-VERSION-001", "SEC-AWS-VPC-FLOWLOGS-001", "SEC-GCP-NETWORK-003",
        "STK-AZURE-NSG-FLOWLOG-001", "SEC-AWS-KMS-001", "STK-GCP-KMS-001",
        "SEC-K8S-NETPOL-001", "SEC-GCP-GKE-NETWORK-POLICY-001", "SEC-AZURE-AKS-002",
    }
    too_high = sorted(
        e["id"] for e in load_catalog(REPO / "catalog")
        if e["id"] in pinned and e.get("default_urgency") in ("HIGH", "CRITICAL")
    )
    assert not too_high, f"see docs/severity-calibration.md: {too_high}"
