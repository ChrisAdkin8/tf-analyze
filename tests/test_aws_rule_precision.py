"""AWS rules fire on the insecure shape and stay quiet on the secure one.

Each case is a pair from the critical review's false-positive list: the
secure variant used to draw a HIGH or CRITICAL, the insecure one must
still fire.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _fired(tmp_path: Path, hcl: str, rule: str) -> set[str]:
    (tmp_path / "main.tf").write_text(hcl)
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "json",
            "--show-info",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return {
        f.get("resource", "")
        for f in json.loads(proc.stdout)["findings"]
        if f["id"] == rule
    }


def _policy(name: str, effect: str, actions: str) -> str:
    return f"""
resource "aws_iam_policy" "{name}" {{
  name = "{name}"
  policy = jsonencode({{
    Version   = "2012-10-17"
    Statement = [{{ Effect = "{effect}", Action = [{actions}], Resource = "*" }}]
  }})
}}
"""


def test_iam_json_wildcard_resource_skips_deny_and_unscopable_reads(tmp_path) -> None:
    hcl = (
        _policy("write", "Allow", '"s3:PutObject"')
        + _policy("describe", "Allow", '"ec2:DescribeInstances", "s3:ListAllMyBuckets"')
        + _policy("deny", "Deny", '"s3:*"')
    )
    assert _fired(tmp_path, hcl, "SEC-AWS-IAM-001") == {"aws_iam_policy.write"}


def test_iam_document_deny_with_public_principal_is_not_a_public_grant(
    tmp_path,
) -> None:
    hcl = """
data "aws_iam_policy_document" "tls_only" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}
data "aws_iam_policy_document" "public" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}
"""
    assert _fired(tmp_path, hcl, "SEC-AWS-IAM-002") == set()
    assert _fired(tmp_path, hcl, "SEC-AWS-IAM-POLICY-004") == {
        "data.aws_iam_policy_document.public"
    }
    assert _fired(tmp_path, hcl, "SEC-AWS-IAM-POLICY-003") == set()


@pytest.mark.parametrize(
    ("line", "fires"),
    [
        ("use_lockfile = true", False),
        ('dynamodb_table = "locks"', False),
        ("use_lockfile = false", True),
        ('# dynamodb_table = "locks"', True),
        ("", True),
    ],
)
def test_s3_backend_locking(tmp_path, line: str, fires: bool) -> None:
    hcl = f'terraform {{\n  backend "s3" {{\n    bucket = "b"\n    key    = "k"\n    {line}\n  }}\n}}\n'
    assert bool(_fired(tmp_path, hcl, "ROB-AWS-BACKEND-001")) is fires


def test_kms_rotation_only_for_rotatable_keys(tmp_path) -> None:
    hcl = """
resource "aws_kms_key" "symmetric" {}
resource "aws_kms_key" "explicit_symmetric" {
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
}
resource "aws_kms_key" "signing" {
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
}
resource "aws_kms_key" "hmac" {
  key_usage                = "GENERATE_VERIFY_MAC"
  customer_master_key_spec = "HMAC_256"
  enable_key_rotation      = false
}
"""
    assert _fired(tmp_path, hcl, "SEC-AWS-KMS-001") == {
        "aws_kms_key.symmetric",
        "aws_kms_key.explicit_symmetric",
    }


def test_lb_http_redirect_exemption_reads_the_value_not_the_text(tmp_path) -> None:
    hcl = """
resource "aws_lb_listener" "redirect" {
  load_balancer_arn = "x"
  protocol          = "HTTP"
  default_action {
    type  = "redirect"
    order = 1
  }
}
resource "aws_lb_listener" "forward" {
  load_balancer_arn = "x"
  protocol          = "HTTP"
  # type = "redirect"
  default_action {
    type             = "forward"
    target_group_arn = "tg"
  }
}
"""
    assert _fired(tmp_path, hcl, "SEC-AWS-LB-LISTENER-001") == {
        "aws_lb_listener.forward"
    }


def test_s3_companions_through_for_each(tmp_path) -> None:
    hcl = """
resource "aws_s3_bucket" "many" {
  for_each = toset(["a", "b"])
  bucket   = each.value
}
resource "aws_s3_bucket_public_access_block" "many" {
  for_each                = aws_s3_bucket.many
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket" "lonely" {
  bucket = "lonely"
}
"""
    assert _fired(tmp_path, hcl, "SEC-AWS-S3-PUBLIC-BLOCK-001") == {
        "aws_s3_bucket.lonely"
    }


def test_ssm_plain_parameters_split_by_whether_they_look_secret(tmp_path) -> None:
    hcl = """
resource "aws_ssm_parameter" "ami" {
  name  = "/platform/base-ami-id"
  type  = "String"
  value = "ami-0123"
}
resource "aws_ssm_parameter" "db_password" {
  name  = "/app/db"
  type  = "String"
  value = "x"
}
resource "aws_ssm_parameter" "token" {
  name  = "/app/token"
  type  = "SecureString"
  value = "x"
}
"""
    assert _fired(tmp_path, hcl, "SEC-SECRETS-002") == {"aws_ssm_parameter.db_password"}
    assert _fired(tmp_path, hcl, "SEC-AWS-SSM-001") == {"aws_ssm_parameter.ami"}


def test_kms_unresolved_key_spec_still_fires(tmp_path) -> None:
    hcl = """
variable "key_spec" {
  type = string
}
resource "aws_kms_key" "unresolved" {
  customer_master_key_spec = var.key_spec
}
"""
    assert _fired(tmp_path, hcl, "SEC-AWS-KMS-001") == {"aws_kms_key.unresolved"}
