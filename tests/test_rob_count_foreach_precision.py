"""count / for_each robustness rules read the resource's own arguments
(parse tree first, top-level-only regex fallback), not raw file text: a
commented-out line, a nested block's ``count`` or a ``dynamic`` block's
``for_each`` no longer decides a finding, and a guard or ternary split
over several lines is still seen."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

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


@pytest.fixture
def real_parser(monkeypatch):
    # Multi-line values are only read whole from the parse tree; the
    # forced-fallback CI job would route this through the text path.
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)


COUNTED = 'resource "aws_instance" "a" {\n  count = 2\n}\n'

# Cloud Armor: `count` inside a nested block is a rate limit, not meta-count.
ARMOR = """resource "google_compute_security_policy" "p" {
  rule {
    rate_limit_options {
      rate_limit_threshold {
        count = 100
      }
    }
  }
}
"""

FOREACH_BUCKET = """resource "aws_s3_bucket" "b" {
  for_each = toset(["a"])
  bucket   = each.key
}
"""


# ---- ROB-COUNTREF-001 (count_index_ref) -------------------------------------


def test_countref_ignores_block_comment(tmp_path) -> None:
    text = COUNTED + '/*\noutput "o" {\n  value = aws_instance.a[0].id\n}\n*/\n'
    assert "ROB-COUNTREF-001" not in _ids(tmp_path, text)


def test_countref_question_mark_in_comment_is_no_guard(tmp_path) -> None:
    text = COUNTED + 'output "o" {\n  value = aws_instance.a[0].id # ok?\n}\n'
    assert "ROB-COUNTREF-001" in _ids(tmp_path, text)


def test_countref_multiline_ternary_is_guarded(tmp_path) -> None:
    text = COUNTED + (
        'output "o" {\n'
        "  value = length(aws_instance.a) > 0 ? (\n"
        "    aws_instance.a[0].id\n"
        "  ) : null\n"
        "}\n"
    )
    assert "ROB-COUNTREF-001" not in _ids(tmp_path, text)


def test_countref_unguarded_still_fires(tmp_path) -> None:
    text = COUNTED + 'output "o" {\n  value = aws_instance.a[0].id\n}\n'
    assert "ROB-COUNTREF-001" in _ids(tmp_path, text)


# ---- ROB-COUNTNAME-001 (count_index_in_name) ---------------------------------


def test_countname_ignores_commented_name(tmp_path) -> None:
    text = (
        'resource "aws_s3_bucket" "b" {\n'
        "  count = 2\n"
        '  # bucket = "logs-${count.index}"\n'
        '  bucket_prefix = "logs"\n'
        "}\n"
    )
    assert "ROB-COUNTNAME-001" not in _ids(tmp_path, text)


def test_countname_multiline_name(tmp_path, real_parser) -> None:
    text = (
        'resource "aws_s3_bucket" "b" {\n'
        "  count = 2\n"
        "  bucket = format(\n"
        '    "logs-%d",\n'
        "    count.index,\n"
        "  )\n"
        "}\n"
    )
    assert "ROB-COUNTNAME-001" in _ids(tmp_path, text)


# ---- ROB-COUNT-001 (count_bool_pattern) --------------------------------------


def test_count_bool_with_trailing_comment(tmp_path) -> None:
    text = 'resource "aws_s3_bucket" "b" {\n  count = var.on ? 1 : 0 # toggle\n}\n'
    assert "ROB-COUNT-001" in _ids(tmp_path, text)


def test_count_bool_split_over_lines(tmp_path) -> None:
    text = (
        'resource "aws_s3_bucket" "b" {\n'
        "  count = (\n"
        "    var.on\n"
        "    ? 1\n"
        "    : 0\n"
        "  )\n"
        "}\n"
    )
    assert "ROB-COUNT-001" in _ids(tmp_path, text)


# ---- ROB-COUNT-002 (count_foreach_mix) ---------------------------------------


def test_count_mix_ignores_nested_count(tmp_path) -> None:
    assert "ROB-COUNT-002" not in _ids(tmp_path, ARMOR + FOREACH_BUCKET)


def test_count_mix_ignores_dynamic_for_each(tmp_path) -> None:
    text = 'resource "aws_s3_bucket" "a" {\n  count = 2\n}\n' + (
        'resource "aws_security_group" "g" {\n'
        '  dynamic "ingress" {\n'
        "    for_each = var.rules\n"
        "    content {\n"
        "      from_port = ingress.value\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    assert "ROB-COUNT-002" not in _ids(tmp_path, text)


def test_count_mix_still_fires(tmp_path) -> None:
    text = 'resource "aws_s3_bucket" "a" {\n  count = 2\n}\n' + FOREACH_BUCKET
    assert "ROB-COUNT-002" in _ids(tmp_path, text)


# ---- ROB-COUNTREF-002 (count_length_unguarded) -------------------------------


def test_count_length_ignores_commented_ref(tmp_path) -> None:
    text = (
        'resource "aws_instance" "a" {\n  count = length(var.l)\n}\n'
        "# see aws_instance.a[0].id\n"
    )
    assert "ROB-COUNTREF-002" not in _ids(tmp_path, text)


def test_count_length_ignores_nested_count(tmp_path) -> None:
    text = (
        'resource "google_compute_security_policy" "p" {\n'
        "  rule {\n"
        "    rate_limit_threshold {\n"
        "      count = length(var.l)\n"
        "    }\n"
        "  }\n"
        "}\n"
        'output "o" {\n  value = google_compute_security_policy.p[0].id\n}\n'
    )
    assert "ROB-COUNTREF-002" not in _ids(tmp_path, text)


# ---- ROB-FOREACH-001 / -002 ---------------------------------------------------


def test_foreach_list_ignores_dynamic_block(tmp_path) -> None:
    text = (
        'resource "aws_security_group" "g" {\n'
        '  dynamic "ingress" {\n'
        "    for_each = [80, 443]\n"
        "    content {\n"
        "      from_port = ingress.value\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    assert "ROB-FOREACH-001" not in _ids(tmp_path, text)


def test_foreach_keyset_ignores_dynamic_block(tmp_path) -> None:
    text = (
        'resource "aws_security_group" "g" {\n'
        '  dynamic "ingress" {\n'
        "    for_each = aws_subnet.s[*].cidr_block\n"
        "    content {\n"
        "      cidr_blocks = [ingress.value]\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    assert "ROB-FOREACH-002" not in _ids(tmp_path, text)


def test_foreach_rules_still_fire(tmp_path) -> None:
    text = (
        'resource "aws_route" "r" {\n  for_each = toset(aws_subnet.s[*].id)\n}\n'
        'resource "aws_s3_bucket" "b" {\n  for_each = tolist(var.x)\n}\n'
    )
    ids = _ids(tmp_path, text)
    assert "ROB-FOREACH-001" in ids
    assert "ROB-FOREACH-002" in ids
