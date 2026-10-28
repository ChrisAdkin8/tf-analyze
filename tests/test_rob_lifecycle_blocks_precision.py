"""Lifecycle / block robustness rules read code, not comments or heredoc
text, and see the forms ``terraform fmt`` writes: a commented-out
``assert`` or ``validation`` block does not satisfy a rule, a comment
inside ``ignore_changes`` is not an attribute, a multi-line
``ignore_changes = [tags,]`` is caught, and ``prevent_destroy = false``
is the same as leaving it out."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _ids(tmp_path: Path, text: str) -> list[str]:
    (tmp_path / "main.tf").write_text(text)
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return [f["id"] for f in json.loads(out.stdout)["findings"]]


# ---- ROB-CHECK-001 (check_block_missing_assert) -------------------------------


def test_assert_in_block_comment_does_not_count(tmp_path) -> None:
    text = (
        'check "c" {\n'
        "  /*\n"
        "  assert {\n"
        "    condition     = true\n"
        '    error_message = "x"\n'
        "  }\n"
        "  */\n"
        "}\n"
    )
    assert "ROB-CHECK-001" in _ids(tmp_path, text)


# ---- ROB-VALIDATION-001 (variable_missing_validation) -------------------------


def test_validation_in_block_comment_does_not_count(tmp_path) -> None:
    text = (
        'variable "region" {\n'
        "  type = string\n"
        "  /*\n"
        "  validation {\n"
        "    condition = true\n"
        "  }\n"
        "  */\n"
        "}\n"
    )
    assert "ROB-VALIDATION-001" in _ids(tmp_path, text)


def test_validation_in_heredoc_does_not_count(tmp_path) -> None:
    text = (
        'variable "region" {\n'
        "  type        = string\n"
        "  description = <<EOT\n"
        "validation {\n"
        "EOT\n"
        "}\n"
    )
    assert "ROB-VALIDATION-001" in _ids(tmp_path, text)


def test_real_validation_still_counts(tmp_path) -> None:
    text = (
        'variable "region" {\n'
        "  type = string\n"
        "  validation {\n"
        "    condition     = length(var.region) > 0\n"
        '    error_message = "region must be set"\n'
        "  }\n"
        "}\n"
    )
    assert "ROB-VALIDATION-001" not in _ids(tmp_path, text)


# ---- ROB-DRIFT-003 (ignore_changes_overuse) -----------------------------------


def test_comment_inside_ignore_changes_is_not_an_attribute(tmp_path) -> None:
    text = (
        'resource "aws_instance" "a" {\n'
        "  lifecycle {\n"
        "    ignore_changes = [\n"
        "      ami, # was: tags, user_data, subnet_id, key_name, iam_instance_profile\n"
        "    ]\n"
        "  }\n"
        "}\n"
    )
    assert "ROB-DRIFT-003" not in _ids(tmp_path, text)


# ---- ROB-DRIFT-002 (grep) -----------------------------------------------------


def test_ignore_changes_tags_with_trailing_comma(tmp_path) -> None:
    text = (
        'resource "aws_instance" "a" {\n'
        "  lifecycle {\n"
        "    ignore_changes = [\n"
        "      tags,\n"
        "    ]\n"
        "  }\n"
        "}\n"
    )
    assert "ROB-DRIFT-002" in _ids(tmp_path, text)


# ---- ROB-*-LIFECYCLE-001 (prevent_destroy) -------------------------------------


def test_prevent_destroy_false_is_not_protection(tmp_path) -> None:
    text = (
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  lifecycle {\n    prevent_destroy = false\n  }\n}\n'
        'resource "azurerm_key_vault" "k" {\n  name = "x"\n  lifecycle {\n    prevent_destroy = false\n  }\n}\n'
        'resource "google_compute_disk" "d" {\n  name = "x"\n  lifecycle {\n    prevent_destroy = false\n  }\n}\n'
    )
    ids = _ids(tmp_path, text)
    assert "ROB-AWS-LIFECYCLE-001" in ids
    assert "ROB-AZURE-LIFECYCLE-001" in ids
    assert "ROB-GCP-LIFECYCLE-001" in ids


def test_prevent_destroy_true_passes(tmp_path) -> None:
    text = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  lifecycle {\n    prevent_destroy = true\n  }\n}\n'
    assert "ROB-AWS-LIFECYCLE-001" not in _ids(tmp_path, text)
