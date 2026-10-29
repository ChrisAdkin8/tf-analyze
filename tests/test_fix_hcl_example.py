"""`--apply-fixes` never pastes a fix whose values are examples.

The tag / label rules' `fix_hcl` holds made-up values (`Owner =
"platform-team"`, `Environment = "prod"`) and `fix_disruption: none`, so the
auto-remediation bot pasted them into real resources, which also made those
resources look like production to other rules. `fix_hcl_example: true`
keeps the snippet in reports but out of `--apply-fixes`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DETECT = REPO / "scripts" / "detect.py"
sys.path.insert(0, str(REPO / "integrations" / "github-action-bot"))

UNTAGGED = {
    "OPS-AWS-TAGS-001": 'resource "aws_instance" "a" {\n  ami           = "ami-1"\n  instance_type = "t3.micro"\n}\n',
    "OPS-GCP-LABELS-001": 'resource "google_compute_instance" "vm" {\n  name         = "vm"\n  machine_type = "e2-small"\n}\n',
    "OPS-AZURE-TAGS-001": 'resource "azurerm_resource_group" "rg" {\n  name     = "rg"\n  location = "westeurope"\n}\n',
}


@pytest.mark.parametrize("rule", sorted(UNTAGGED))
def test_example_values_are_not_pasted(tmp_path, rule) -> None:
    (tmp_path / "main.tf").write_text(UNTAGGED[rule])
    before = json.loads(subprocess.run(
        [sys.executable, str(DETECT), "--target", str(tmp_path), "--format", "json"],
        capture_output=True, text=True, check=False).stdout)
    hit = [f for f in before["findings"] if f["id"] == rule]
    assert hit and hit[0].get("fix_hcl_example") is True
    subprocess.run(
        [sys.executable, str(DETECT), "--target", str(tmp_path), "--apply-fixes", "apply",
         "--apply-fixes-max-disruption", "none", "--format", "json"],
        capture_output=True, text=True, check=False,
    )
    text = (tmp_path / "main.tf").read_text()
    assert "platform-team" not in text and "my-project" not in text


def test_the_bot_pr_body_does_not_count_them() -> None:
    from render_pr_body import compose_body

    scan = {"summary": {}, "findings": [
        {"id": "OPS-AWS-TAGS-001", "file": "main.tf", "line": 1, "fix_disruption": "none", "fix_hcl_example": True},
        {"id": "SEC-AWS-S3-001", "file": "main.tf", "line": 1, "fix_disruption": "none"},
    ]}
    body = compose_body(scan, "# apply-fixes: applied 1 fix(es) across 1 file(s)")
    assert "`SEC-AWS-S3-*`" in body and "OPS-AWS-TAGS" not in body


def test_flag_must_be_boolean() -> None:
    sys.path.insert(0, str(REPO / "scripts"))
    from _catalog import validate_catalog_entry

    base = {"id": "CUSTOM-X-001", "title": "t", "section": "ops", "default_urgency": "LOW",
            "status": "active", "patterns": [{"kind": "resource_present", "resource": "x"}],
            "recommendation": "r", "verification": "v"}
    assert not any("fix_hcl_example" in e for e in validate_catalog_entry({**base, "fix_hcl_example": True}, "x"))
    assert any("fix_hcl_example" in e for e in validate_catalog_entry({**base, "fix_hcl_example": "yes"}, "x"))
