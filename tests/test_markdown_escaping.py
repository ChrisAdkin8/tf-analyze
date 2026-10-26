"""Values from the scanned repository (file paths, resource names) stay
inert in Markdown output: a crafted file name must not break out of its
code span or table cell in a PR comment (critical review)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from _attack_graph import _mermaid_label
from _output import _md_code

REPO = Path(__file__).resolve().parents[1]
PAYLOAD = "a` | ![x](https://e.vil/x.png) @octocat `"
# A file name cannot contain "/", so the image URL is relative.
FILE_PAYLOAD = "a` | ![x](evil.png) @octocat `"

SSH_OPEN = """resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def _cells(row: str) -> list[str]:
    """Table cells split on unescaped `|` (GitHub's rule, code spans too)."""
    return [c.strip() for c in re.split(r"(?<!\\)\|", row.strip())[1:-1]]


def _is_one_code_span(cell: str) -> bool:
    m = re.fullmatch(r"(`+)(.*)\1", cell, re.DOTALL)
    if not m:
        return False
    fence, inner = m.groups()
    return all(len(run) != len(fence) for run in re.findall(r"`+", inner))


def test_md_code_contains_any_value() -> None:
    for value in ("main.tf:3", PAYLOAD, "`x`", "a|b", "``", "line\nbreak"):
        span = _md_code(value)
        assert _is_one_code_span(span), span
        assert "\n" not in span
        assert len(_cells(f"| {span} |")) == 1, span


def test_pr_summary_keeps_a_hostile_file_name_inert(tmp_path) -> None:
    (tmp_path / f"{FILE_PAYLOAD}.tf").write_text(SSH_OPEN)
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "pr-summary",
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    rows = [ln for ln in out.splitlines() if "evil.png" in ln]
    assert rows, out
    for row in rows:
        cells = _cells(row)
        assert len(cells) == 3, row  # Urgency | Rule | Location
        assert _is_one_code_span(cells[2]), row


def test_pr_summary_shows_the_escalated_urgency(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(SSH_OPEN)
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "pr-summary",
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    row = next(
        ln for ln in out.splitlines() if "SEC-AWS-SG-001" in ln and ln.startswith("|")
    )
    assert "**CRITICAL**" in row, row  # escalated from the catalogue's HIGH


def test_fleet_report_escapes_targets_and_resource_names() -> None:
    from _modes import render_fleet_report

    finding = {"id": "R-1", "resource": f"aws_s3_bucket.{PAYLOAD}", "file": "main.tf"}
    result = {
        "by_target": {f"/repos/{PAYLOAD}": [finding]},
        "fleet_wide": [{**finding, "fleet_count": 2, "fleet_repos": ["a", "b"]}],
        "summary": {f"/repos/{PAYLOAD}": 1},
    }
    out = render_fleet_report(result, "text")
    rows = [ln for ln in out.splitlines() if ln.startswith("|") and "e.vil" in ln]
    assert len(rows) >= 2, out  # the per-repo summary and the fleet-wide table
    for row in rows:
        assert any(_is_one_code_span(c) and "e.vil" in c for c in _cells(row)), row
        assert not any("e.vil" in c and not _is_one_code_span(c) for c in _cells(row)), row


def test_mermaid_labels_cannot_carry_html_or_end_the_fence() -> None:
    label = _mermaid_label('x"<img src=x onerror=alert(1)>\n```')
    assert (
        "<" not in label and ">" not in label and "\n" not in label and '"' not in label
    )
