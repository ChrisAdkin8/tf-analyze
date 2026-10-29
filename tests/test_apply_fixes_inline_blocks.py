"""`--apply-fixes` on blocks whose braces share a line with other code.

Fixes insert before the line holding the block's closing `}`, so for
`resource "x" "y" {}` they landed *above* the header, outside the block,
the file stopped parsing, and every re-run added the lines again
(critical review). The block is now split onto its own lines first.

Also: rules whose `fix_hcl` values are examples (a sample IP range, an
`example` resource reference, a runtime or engine version for another
language) are marked `fix_hcl_example: true`, so they aren't pasted.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from _apply_fixes import _apply_pattern
from _catalog import load_yaml
from _hcl import _parse_tf_cached

REPO = Path(__file__).resolve().parents[1]
RULE = "SEC-AWS-RDS-002"  # aws_db_instance storage_encrypted (missing or false)


def _detect(target: Path, *args: str) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--format",
            "json",
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return proc


INLINE = {
    "empty": 'resource "aws_db_instance" "db" {}\n',
    "empty_no_final_newline": 'resource "aws_db_instance" "db" {}',
    "one_line": 'resource "aws_db_instance" "db" { engine = "mysql" }\n',
    "nested_close_on_last_line": (
        'resource "aws_db_instance" "db" {\n'
        '  engine = "mysql"\n'
        "  timeouts {\n"
        '    create = "1h" } }\n'
    ),
    "comment_after_open": 'resource "aws_db_instance" "db" { # keep\n  engine = "mysql" }\n',
}


@pytest.mark.parametrize("case", sorted(INLINE))
def test_inline_block_gets_the_fix_inside_it(tmp_path, case) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text(INLINE[case])
    _detect(tmp_path, "--apply-fixes", "apply")
    once = tf.read_text()
    _detect(tmp_path, "--apply-fixes", "apply")
    assert tf.read_text() == once, "a second run changed the file again"
    assert once.startswith('resource "aws_db_instance" "db" {'), once
    assert once.count("storage_encrypted") == 1, once
    _parse_tf_cached(once)
    findings = json.loads(_detect(tmp_path).stdout)["findings"]
    assert not any(f["id"] == RULE for f in findings), once


def test_comment_after_open_brace_stays_on_the_header() -> None:
    lines = INLINE["comment_after_open"].splitlines(keepends=True)
    assert _apply_pattern(
        lines,
        0,
        "resource_missing_arg",
        "storage_encrypted",
        "storage_encrypted = true\n",
        "\n",
    )
    assert lines[0] == 'resource "aws_db_instance" "db" { # keep\n'
    assert lines[-1] == "}\n"


def test_inline_block_is_left_alone_when_no_fix_applies() -> None:
    lines = ['resource "aws_db_instance" "db" { engine = "mysql" }\n']
    assert not _apply_pattern(
        lines, 0, "resource_arg", "missing_arg", "missing_arg = 1\n", "\n"
    )
    assert lines == ['resource "aws_db_instance" "db" { engine = "mysql" }\n']


EXAMPLE_FIXES = [
    "SEC-AZURE-SQL-002",
    "SEC-AZURE-FED-IDENTITY-001",
    "SEC-AZURE-RBAC-001",
    "SEC-GCP-IAM-001",
    "SEC-GCP-IAM-002",
    "STK-AWS-LAMBDA-001",
    "STK-GCP-FUNCTIONS-001",
    "STK-AZURE-MYSQL-EOL-001",
    "STK-AWS-RDS-004",
]


@pytest.mark.parametrize("rule", EXAMPLE_FIXES)
def test_example_valued_fixes_are_marked(rule) -> None:
    data = load_yaml((REPO / "catalog" / f"{rule}.yaml").read_text())
    assert data.get("fix_hcl_example") is True


def test_sql_firewall_fix_is_not_pasted(tmp_path) -> None:
    # The fix only replaced start_ip_address with 203.0.113.10, leaving
    # end_ip_address = 255.255.255.255: still open, and not the user's IP.
    src = REPO / "fixtures" / "azure_sql_open_firewall"
    shutil.copytree(src, tmp_path / "t")
    _detect(
        tmp_path / "t", "--apply-fixes", "apply", "--apply-fixes-max-disruption", "none"
    )
    text = "".join(p.read_text() for p in (tmp_path / "t").glob("*.tf"))
    assert "203.0.113" not in text
    assert 'start_ip_address = "0.0.0.0"' in text
