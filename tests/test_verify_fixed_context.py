"""`--mode verify-fixed` re-probes in the same context as a scan.

It re-ran each rule on the file without the folder's variable values or
the module's other resources, so a finding on `publicly_accessible =
var.public` could never fire again: an unfixed finding came out RESOLVED
and passed the gate (critical review).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DETECT = REPO / "scripts" / "detect.py"

RDS = (
    'variable "public" {\n  default = %s\n}\n'
    'resource "aws_db_instance" "db" {\n'
    '  engine              = "postgres"\n'
    "  publicly_accessible = var.public\n"
    "  storage_encrypted   = true\n"
    "}\n"
)
RULE = "SEC-AWS-RDS-001"


def _run(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(DETECT), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(cwd),
    )


def _verify(tmp_path: Path, public: str) -> tuple[set[str], int]:
    target = tmp_path / "t"
    target.mkdir()
    (target / "main.tf").write_text(RDS % "true")
    prior = _run(tmp_path, "--target", "t", "--format", "json")
    (tmp_path / "prior.json").write_text(prior.stdout)
    assert RULE in {f["id"] for f in json.loads(prior.stdout)["findings"]}
    (target / "main.tf").write_text(RDS % public)
    res = _run(
        tmp_path,
        "--target",
        "t",
        "--mode",
        "verify-fixed",
        "--prior-report",
        "prior.json",
        "--format",
        "json",
        "--fail-on",
        "HIGH",
    )
    results = json.loads(res.stdout)["results"]
    states = {
        state for state, rows in results.items() if any(r["id"] == RULE for r in rows)
    }
    return states, res.returncode


def test_unfixed_variable_driven_finding_is_still_present(tmp_path) -> None:
    states, code = _verify(tmp_path, "true")
    assert states == {"STILL-PRESENT"}
    assert code == 1


def test_fixed_variable_driven_finding_is_resolved(tmp_path) -> None:
    states, _code = _verify(tmp_path, "false")
    assert states == {"RESOLVED"}
