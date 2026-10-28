"""S3 rules check what a setting says, not only that it is there.

SEC-AWS-S3-PUBLIC-001 (public ACLs and grants), SEC-AWS-S3-PUBLIC-BLOCK-001
(public access block missing or switched off) and ROB-AWS-S3-001
(versioning off). Each case is a small module scanned end to end.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

DETECT = Path(__file__).resolve().parents[1] / "scripts" / "detect.py"

BUCKET = 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'
FULL_BLOCK = """resource "aws_s3_bucket_public_access_block" "b" {
  bucket                  = aws_s3_bucket.b.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""
ACCOUNT_BLOCK = """resource "aws_s3_account_public_access_block" "a" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""


def _findings(tmp_path: Path, hcl: str, rule: str) -> list[str]:
    (tmp_path / "main.tf").write_text(hcl)
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(tmp_path), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return sorted(
        f["resource"] for f in json.loads(proc.stdout)["findings"] if f["id"] == rule
    )


@pytest.mark.parametrize(
    "acl", ["public-read", "public-read-write", "authenticated-read"]
)
def test_public_canned_acl_is_flagged(tmp_path, acl) -> None:
    hcl = (
        BUCKET
        + f'resource "aws_s3_bucket_acl" "b" {{\n  bucket = aws_s3_bucket.b.id\n  acl = "{acl}"\n}}\n'
    )
    assert _findings(tmp_path, hcl, "SEC-AWS-S3-PUBLIC-001") == ["aws_s3_bucket_acl.b"]


def test_public_acl_through_a_variable_is_flagged(tmp_path) -> None:
    hcl = BUCKET + (
        'variable "acl" {\n  default = "public-read"\n}\n'
        'resource "aws_s3_bucket_acl" "b" {\n  bucket = aws_s3_bucket.b.id\n  acl = var.acl\n}\n'
    )
    assert _findings(tmp_path, hcl, "SEC-AWS-S3-PUBLIC-001") == ["aws_s3_bucket_acl.b"]


@pytest.mark.parametrize(
    "acl", ["private", "log-delivery-write", "bucket-owner-full-control"]
)
def test_private_acls_are_not_flagged(tmp_path, acl) -> None:
    hcl = (
        BUCKET
        + f'resource "aws_s3_bucket_acl" "b" {{\n  bucket = aws_s3_bucket.b.id\n  acl = "{acl}"\n}}\n'
    )
    assert _findings(tmp_path, hcl, "SEC-AWS-S3-PUBLIC-001") == []


def test_a_bucket_counted_out_is_not_flagged(tmp_path) -> None:
    hcl = 'resource "aws_s3_bucket" "b" {\n  count = 0\n  acl   = "public-read"\n}\n'
    assert _findings(tmp_path, hcl, "SEC-AWS-S3-PUBLIC-001") == []


def test_full_public_access_block_passes(tmp_path) -> None:
    assert _findings(tmp_path, BUCKET + FULL_BLOCK, "SEC-AWS-S3-PUBLIC-BLOCK-001") == []


@pytest.mark.parametrize(
    "flag",
    [
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    ],
)
def test_each_flag_switched_off_or_left_out_is_flagged(tmp_path, flag) -> None:
    off = re.sub(rf"({flag}\s*=\s*)true", r"\1false", FULL_BLOCK)
    assert off != FULL_BLOCK
    assert _findings(tmp_path, BUCKET + off, "SEC-AWS-S3-PUBLIC-BLOCK-001") == [
        "aws_s3_bucket_public_access_block.b"
    ]
    left_out = (
        "\n".join(line for line in FULL_BLOCK.splitlines() if flag not in line) + "\n"
    )
    assert _findings(tmp_path, BUCKET + left_out, "SEC-AWS-S3-PUBLIC-BLOCK-001") == [
        "aws_s3_bucket_public_access_block.b"
    ]


def test_account_level_block_covers_buckets(tmp_path) -> None:
    assert _findings(tmp_path, BUCKET, "SEC-AWS-S3-PUBLIC-BLOCK-001") == [
        "aws_s3_bucket.b"
    ]
    assert (
        _findings(tmp_path, BUCKET + ACCOUNT_BLOCK, "SEC-AWS-S3-PUBLIC-BLOCK-001") == []
    )


def test_account_level_block_switched_off_is_flagged(tmp_path) -> None:
    off = ACCOUNT_BLOCK.replace(
        "block_public_policy     = true", "block_public_policy     = false"
    )
    assert _findings(tmp_path, BUCKET + off, "SEC-AWS-S3-PUBLIC-BLOCK-001") == [
        "aws_s3_account_public_access_block.a"
    ]


def test_legacy_versioning_value_is_read(tmp_path) -> None:
    off = (
        'resource "aws_s3_bucket" "b" {\n  versioning {\n    enabled = false\n  }\n}\n'
    )
    on = 'resource "aws_s3_bucket" "b" {\n  versioning {\n    enabled = true\n  }\n}\n'
    assert _findings(tmp_path, off, "ROB-AWS-S3-001") == ["aws_s3_bucket.b"]
    assert _findings(tmp_path, on, "ROB-AWS-S3-001") == []
