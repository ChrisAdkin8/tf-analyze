"""`resource_missing_companion`: per-resource companion checks. With the
old repo-wide `resource_absent`, one public access block anywhere passed
every bucket; now each bucket needs its own."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

BUCKET = 'resource "aws_s3_bucket" "%s" {\n  bucket = "%s"\n}\n'
PAB = """resource "aws_s3_bucket_public_access_block" "%s" {
  bucket                  = %s
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""
LOGGING = """resource "aws_s3_bucket_logging" "%s" {
  bucket        = %s
  target_bucket = %s
  target_prefix = "log/"
}
"""


def _findings(target: Path, rule: str) -> set[str]:
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        f["resource"] for f in json.loads(out.stdout)["findings"] if f["id"] == rule
    }


def test_one_public_access_block_no_longer_covers_every_bucket(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(
        BUCKET % ("a", "bucket-a")
        + BUCKET % ("b", "bucket-b")
        + PAB % ("a", "aws_s3_bucket.a.id")
    )
    assert _findings(tmp_path, "SEC-AWS-S3-PUBLIC-BLOCK-001") == {"aws_s3_bucket.b"}


def test_companion_in_another_file_and_by_literal_name(tmp_path) -> None:
    (tmp_path / "buckets.tf").write_text(
        BUCKET % ("a", "bucket-a") + BUCKET % ("b", "bucket-b")
    )
    (tmp_path / "blocks.tf").write_text(
        PAB % ("a", "aws_s3_bucket.a.id") + PAB % ("b", '"bucket-b"')
    )
    assert _findings(tmp_path, "SEC-AWS-S3-PUBLIC-BLOCK-001") == set()


def test_companion_in_another_module_does_not_count(tmp_path) -> None:
    (tmp_path / "child").mkdir()
    (tmp_path / "child" / "main.tf").write_text(BUCKET % ("a", "bucket-a"))
    # Same address text, different module: not this bucket.
    (tmp_path / "main.tf").write_text(PAB % ("a", "aws_s3_bucket.a.id"))
    assert _findings(tmp_path, "SEC-AWS-S3-PUBLIC-BLOCK-001") == {"aws_s3_bucket.a"}


def test_log_target_bucket_is_exempt_from_access_logging(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(
        BUCKET % ("app", "my-app")
        + BUCKET % ("logs", "my-app-logs")
        + BUCKET % ("other", "my-other")
        + LOGGING % ("app", "aws_s3_bucket.app.id", "aws_s3_bucket.logs.id")
    )
    assert _findings(tmp_path, "SEC-AWS-S3-LOGGING-001") == {"aws_s3_bucket.other"}


def test_list_valued_via_and_count_zero(tmp_path) -> None:
    (tmp_path / "main.tf").write_text("""
resource "azurerm_network_security_group" "old" {
  name = "old"
}
resource "azurerm_network_security_group" "new" {
  name = "new"
}
resource "azurerm_network_security_group" "off" {
  count = 0
  name  = "off"
}
resource "azurerm_network_security_group" "bare" {
  name = "bare"
}
resource "azurerm_network_watcher_flow_log" "old" {
  network_security_group_id = azurerm_network_security_group.old.id
}
resource "azurerm_network_watcher_flow_log" "new" {
  target_resource_id = azurerm_network_security_group.new.id
}
""")
    assert _findings(tmp_path, "STK-AZURE-NSG-FLOWLOG-001") == {
        "azurerm_network_security_group.bare"
    }


def test_diagnostic_setting_for_one_target_does_not_cover_another(tmp_path) -> None:
    (tmp_path / "main.tf").write_text("""
resource "azurerm_key_vault" "kv" {
  name = "kv"
}
resource "azurerm_lb" "lb" {
  name = "lb"
}
resource "azurerm_monitor_diagnostic_setting" "kv" {
  name               = "kv"
  target_resource_id = azurerm_key_vault.kv.id
}
""")
    assert _findings(tmp_path, "SEC-AZURE-LOGGING-001") == set()
    assert _findings(tmp_path, "STK-AZURE-LB-001") == {"azurerm_lb.lb"}
