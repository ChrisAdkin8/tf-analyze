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
