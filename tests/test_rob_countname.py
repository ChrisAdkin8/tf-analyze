"""Tests for ROB-COUNTNAME-001 — resource name embeds ``count.index``.

The rule fires on resources that simultaneously:
  * Declare ``count = ...``
  * Have a name-like attribute (``name``, ``bucket``, ``Name`` tag, etc.)
    that interpolates ``count.index``.

It must *not* fire when:
  * The resource uses ``for_each`` (positional index isn't an issue).
  * The name attribute uses ``count.index`` but the resource doesn't
    have ``count`` (would be a syntax error in real Terraform, but
    the engine shouldn't false-positive on it).
  * ``count.index`` is used in non-name attributes only.
"""
from __future__ import annotations

import subprocess
import sys
import json
from pathlib import Path

from helpers import REPO_ROOT


def _scan(target: Path) -> list[dict]:
    out = subprocess.run(
        [
            sys.executable, str(REPO_ROOT / "scripts" / "detect.py"),
            "--target", str(target),
            "--catalog", str(REPO_ROOT / "catalog"),
            "--format", "json",
        ],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)["findings"]


def _countname_hits(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f["id"] == "ROB-COUNTNAME-001"]


def test_dirty_fixture_fires_three_times() -> None:
    """3 resources × 3 name-like attrs interpolating count.index = 3 hits."""
    hits = _countname_hits(_scan(REPO_ROOT / "fixtures" / "rob_countname"))
    resources = {h["resource"] for h in hits}
    assert resources == {
        "aws_instance.web",     # Name tag
        "aws_s3_bucket.data",   # bucket attr
        "aws_iam_user.service", # name attr
    }


def test_clean_fixture_does_not_fire() -> None:
    """for_each migration + count.index used in non-name attr should pass."""
    hits = _countname_hits(_scan(REPO_ROOT / "fixtures" / "rob_countname_clean"))
    assert hits == []


def test_finding_carries_resource_address(tmp_path: Path) -> None:
    """Sanity check the per-finding shape — file, line, resource present."""
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "web" {\n'
        '  count = 2\n'
        '  ami   = "ami-x"\n'
        '  tags  = { Name = "web-${count.index}" }\n'
        '}\n'
    )
    hits = _countname_hits(_scan(tmp_path))
    assert len(hits) == 1
    assert hits[0]["resource"] == "aws_instance.web"
    assert hits[0]["file"].endswith("main.tf")
    assert hits[0]["line"] > 0


def test_resource_without_count_does_not_fire(tmp_path: Path) -> None:
    """count.index in a non-counted resource is dead code, not a renumber risk."""
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "web" {\n'
        '  ami  = "ami-x"\n'
        '  tags = { Name = "web-${count.index}" }\n'  # invalid but engine shouldn't flag
        '}\n'
    )
    hits = _countname_hits(_scan(tmp_path))
    assert hits == []


def test_foreach_migration_does_not_fire(tmp_path: Path) -> None:
    """for_each + each.key in the name is the fix — must not be flagged."""
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "web" {\n'
        '  for_each = toset(["a", "b"])\n'
        '  ami      = "ami-x"\n'
        '  tags     = { Name = "web-${each.key}" }\n'
        '}\n'
    )
    hits = _countname_hits(_scan(tmp_path))
    assert hits == []
