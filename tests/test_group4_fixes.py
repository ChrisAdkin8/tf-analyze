"""`--mode verify-fixed`, per-finding SARIF severity, and line lookup in
large files (critical review)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from _hcl import _line_at
from _verify import parse_markdown_report

REPO = Path(__file__).resolve().parents[1]

SSH_OPEN = (
    'resource "aws_security_group" "sg" {\n  ingress {\n    from_port   = 22\n'
    '    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
)


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _prior(path: Path, rows: list[str]) -> Path:
    path.write_text(
        "# tf-analysis report\n\n| ID | Urgency | Location | Resource |\n"
        "|----|---------|----------|----------|\n" + "".join(f"{r}\n" for r in rows)
    )
    return path


# ---- verify-fixed --------------------------------------------------------------


def test_report_rows_with_digits_and_custom_ids_are_parsed(tmp_path) -> None:
    prior = _prior(
        tmp_path / "prior.md",
        [
            "| SEC-AWS-S3-001 | HIGH | main.tf:3 | aws_s3_bucket.b |",
            "| SEC-K8S-RBAC-001 | CRITICAL | k8s.tf:7 | x |",
            "| CUSTOM-OWNER-001 | MEDIUM | main.tf:1 | y |",
        ],
    )
    assert [r["id"] for r in parse_markdown_report(prior)] == [
        "SEC-AWS-S3-001",
        "SEC-K8S-RBAC-001",
        "CUSTOM-OWNER-001",
    ]


def _verify(target: Path, prior: Path) -> dict:
    res = _run(
        "--mode",
        "verify-fixed",
        "--target",
        str(target),
        "--prior-report",
        str(prior),
        "--format",
        "json",
    )
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


def test_a_finding_still_there_is_still_present_not_moved(tmp_path) -> None:
    target = tmp_path / "tf"
    target.mkdir()
    (target / "main.tf").write_text(SSH_OPEN)
    prior = _prior(
        tmp_path / "prior.md",
        ["| SEC-AWS-SG-001 | HIGH | main.tf:1 | aws_security_group.sg |"],
    )
    results = _verify(target, prior)["results"]
    assert len(results["STILL-PRESENT"]) == 1, results
    assert not results["MOVED"]


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
def test_a_broken_symlink_is_reported_not_a_crash(tmp_path) -> None:
    target = tmp_path / "tf"
    target.mkdir()
    (target / "main.tf").write_text("locals {\n  x = 1\n}\n")
    os.symlink(tmp_path / "gone.tf", target / "net.tf")
    prior = _prior(
        tmp_path / "prior.md",
        ["| SEC-AWS-SG-001 | HIGH | net.tf:1 | aws_security_group.sg |"],
    )
    results = _verify(target, prior)["results"]
    assert len(results["BROKEN-SYMLINK"]) == 1, results


# ---- SARIF ---------------------------------------------------------------------


def test_sarif_result_carries_the_findings_own_severity(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(
        SSH_OPEN
    )  # SEC-AWS-SG-001: HIGH, escalated CRITICAL
    sarif = json.loads(_run("--target", str(tmp_path), "--format", "sarif").stdout)
    run = sarif["runs"][0]
    rule = next(
        r for r in run["tool"]["driver"]["rules"] if r["id"] == "SEC-AWS-SG-001"
    )
    result = next(r for r in run["results"] if r["ruleId"] == "SEC-AWS-SG-001")
    assert rule["properties"]["security-severity"] == "7.5"
    assert result["properties"]["security-severity"] == "9.5"
    assert result["level"] == "error"


# ---- line lookup ---------------------------------------------------------------


def test_line_at_matches_counting_newlines() -> None:
    text = "a\nbb\n\nccc\n" * 50
    for pos in (0, 1, 2, 3, 5, 6, len(text) - 1, len(text)):
        assert _line_at(text, pos) == text.count("\n", 0, pos) + 1
