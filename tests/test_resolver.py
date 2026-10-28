"""One resolver for variable and local values (`_hcl.resolve_value_text`).

Before, `detect._resolve_var_ref` went one level deep (`local.enc = var.enc`
stayed the text "var.enc") and split a ternary on its first `:`
(`var.prod ? "aws:kms" : "AES256"` folded to `aws`), while `_network.resolve`
was a second resolver with different rules.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from _hcl import resolve_value_text

DETECT = Path(__file__).resolve().parents[1] / "scripts" / "detect.py"

VD = {
    "prod": "true",
    "enc": "true",
    "arn": "arn:aws:kms:eu-west-2:111122223333:key/abc",
    "__local__enc": "var.enc",
    "__local__deep": "local.enc",
    "__local__a": "local.b",
    "__local__b": "local.a",
}


@pytest.mark.parametrize(("expr", "want"), [
    ("local.enc", "true"),
    ("${local.deep}", "true"),
    ('var.prod ? "aws:kms" : "AES256"', "aws:kms"),
    ('!var.prod ? "a" : "b"', '!var.prod ? "a" : "b"'),  # not a plain bool: left alone
    ('var.prod ? var.arn : "none"', VD["arn"]),
    ('false ? "x:1" : "y:2"', "y:2"),
    ('var.prod ? (var.prod ? "in:1" : "in:2") : "out"', "in:1"),
    ('var.prod ? var.prod ? "n:1" : "n:2" : "o"', "n:1"),
    ('var.prod ? "a?b" : "c"', "a?b"),
    ("local.a", "local.a"),  # a cycle is left as written
    ("var.missing", "var.missing"),
    ("var.enc == true", "var.enc == true"),
    ("data.aws_kms_key.k.arn", "data.aws_kms_key.k.arn"),
])
def test_resolve_value_text(expr, want) -> None:
    assert resolve_value_text(expr, VD) == want


def _ids(tmp_path: Path, hcl: str) -> set[str]:
    (tmp_path / "main.tf").write_text(hcl)
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(tmp_path), "--format", "json"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return {f["id"] for f in json.loads(proc.stdout)["findings"]}


def test_a_local_that_names_a_variable_is_followed(tmp_path) -> None:
    hcl = ('variable "enc" {\n  default = true\n}\nlocals {\n  enc = var.enc\n}\n'
           'resource "aws_redshift_cluster" "c" {\n  cluster_identifier = "c"\n'
           "  encrypted          = local.enc\n}\n")
    assert "SEC-AWS-REDSHIFT-001" not in _ids(tmp_path, hcl)
    assert "SEC-AWS-REDSHIFT-001" in _ids(tmp_path, hcl.replace("default = true", "default = false"))


def _urgency(tmp_path: Path, hcl: str, rule: str) -> list[str]:
    (tmp_path / "main.tf").write_text(hcl)
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(tmp_path), "--format", "json"],
        capture_output=True, text=True, check=False,
    )
    return [f["urgency"] for f in json.loads(proc.stdout)["findings"] if f["id"] == rule]


def test_network_rules_fold_a_ternary(tmp_path) -> None:
    """The port comes from a ternary: SSH when `admin`, HTTPS otherwise."""
    hcl = ('variable "admin" {\n  default = true\n}\n'
           'resource "aws_security_group" "s" {\n  ingress {\n'
           "    from_port   = var.admin ? 22 : 443\n    to_port     = var.admin ? 22 : 443\n"
           '    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
    assert _urgency(tmp_path, hcl, "SEC-AWS-SG-001") == ["CRITICAL"]
    assert _urgency(tmp_path, hcl.replace("default = true", "default = false"), "SEC-AWS-SG-001") == ["HIGH"]


# A ternary that picks a list. Inside an expression python-hcl2 prints the
# list in Python's repr (`['0.0.0.0/0']`), which the HCL list reader left
# quoted, so the rule never saw an open range.
_LIST_TERNARY = {
    "SEC-AWS-SG-001": (
        'resource "aws_security_group" "s" {\n  ingress {\n'
        '    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n'
        '    cidr_blocks = var.open ? ["0.0.0.0/0"] : ["10.0.0.0/8"]\n  }\n}\n'
    ),
    "SEC-GCP-NETWORK-001": (
        'resource "google_compute_firewall" "f" {\n  name    = "f"\n  network = "n"\n'
        '  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n'
        '  source_ranges = var.open ? ["0.0.0.0/0"] : ["10.0.0.0/8"]\n}\n'
    ),
}


@pytest.mark.parametrize("rule", sorted(_LIST_TERNARY))
def test_network_rules_fold_a_ternary_that_picks_a_list(tmp_path, rule) -> None:
    hcl = 'variable "open" {\n  default = true\n}\n' + _LIST_TERNARY[rule]
    assert _urgency(tmp_path, hcl, rule) == ["CRITICAL"]
    assert _urgency(tmp_path, hcl.replace("default = true", "default = false"), rule) == []


def test_a_list_ternary_with_an_unknown_condition_is_not_guessed(tmp_path) -> None:
    hcl = 'variable "open" {}\n' + _LIST_TERNARY["SEC-AWS-SG-001"]
    assert _urgency(tmp_path, hcl, "SEC-AWS-SG-001") == []


def test_parse_literal_reads_both_list_forms() -> None:
    from _network import parse_literal

    assert parse_literal("['0.0.0.0/0', \"it's\"]") == ["0.0.0.0/0", "it's"]
    assert parse_literal('["10.0.0.0/8", "::/0"]') == ["10.0.0.0/8", "::/0"]
    # Not Python literals: still read the HCL way.
    assert parse_literal("[var.a, true]") == ["var.a", True]
