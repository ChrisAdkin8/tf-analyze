"""`--mode verify-fixed` may say RESOLVED only when it looked and found nothing.

It re-probed `.tf` files alone, and "no hit, file exists" meant RESOLVED, so
a secret in `prod.auto.tfvars` came out fixed with nothing changed, and exit 0.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DETECT = REPO / "scripts" / "detect.py"
sys.path.insert(0, str(REPO / "scripts"))

from _verify import parse_prior_report, reprobe_finding

SECRET = 'db_password = "SuperSecret123!"\n'
VARIABLES = 'variable "db_password" {\n  type      = string\n  sensitive = true\n}\n'
WORKFLOW = (
    "on: push\njobs:\n  d:\n    steps:\n      - run: terraform apply -auto-approve\n"
)


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(DETECT), "--no-threat-intel", *args],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def target(tmp_path: Path) -> Path:
    t = tmp_path / "t"
    t.mkdir()
    (t / "variables.tf").write_text(VARIABLES)
    (t / "prod.auto.tfvars").write_text(SECRET)
    return t


def _report(target: Path, tmp_path: Path, fmt: str = "json") -> Path:
    out = tmp_path / f"prior.{fmt}"
    out.write_text(_run("--target", str(target), "--format", fmt).stdout)
    return out


def _verify(target: Path, prior: Path, *flags: str) -> tuple[int, dict]:
    res = _run(
        "--target",
        str(target),
        "--mode",
        "verify-fixed",
        "--prior-report",
        str(prior),
        "--format",
        "json",
        *flags,
    )
    return res.returncode, json.loads(res.stdout)["results"]


def _ids(rows: list[dict]) -> set[str]:
    return {r["id"] for r in rows}


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_a_tfvars_secret_nobody_touched_is_still_present(target, tmp_path, fmt) -> None:
    code, results = _verify(target, _report(target, tmp_path, fmt), "--fail-on", "HIGH")
    assert "SEC-SECRETS-001" in _ids(results["STILL-PRESENT"])
    assert "SEC-SECRETS-001" not in _ids(results["RESOLVED"])
    assert code == 1


def test_a_tfvars_secret_really_removed_is_resolved(target, tmp_path) -> None:
    prior = _report(target, tmp_path)
    (target / "prod.auto.tfvars").write_text('region = "eu-west-1"\n')
    code, results = _verify(target, prior, "--fail-on", "HIGH")
    assert "SEC-SECRETS-001" in _ids(results["RESOLVED"])
    assert code == 0


def test_a_workflow_finding_is_re_probed(tmp_path) -> None:
    t = tmp_path / "t"
    (t / ".github" / "workflows").mkdir(parents=True)
    (t / "main.tf").write_text('variable "x" {\n  type = string\n}\n')
    wf = t / ".github" / "workflows" / "d.yml"
    wf.write_text(WORKFLOW)
    prior = _report(t, tmp_path)
    assert any(
        f["file"].endswith("d.yml") for f in json.loads(prior.read_text())["findings"]
    )
    code, results = _verify(t, prior, "--fail-on", "HIGH")
    assert code == 1
    assert "SEC-CICD-003" in _ids(results["STILL-PRESENT"])
    wf.write_text("on: push\njobs: {}\n")
    code, results = _verify(t, prior, "--fail-on", "HIGH")
    assert code == 0 and "SEC-CICD-003" in _ids(results["RESOLVED"])


def test_a_markdown_report_keeps_rows_for_non_terraform_files(tmp_path) -> None:
    md = tmp_path / "prior.md"
    md.write_text(
        "| ID | Urgency | Location | Resource |\n|---|---|---|---|\n"
        "| SEC-SECRETS-001 | CRITICAL | prod.auto.tfvars:1 | - |\n"
        "| SEC-CICD-001 | HIGH | `.github/workflows/d.yml:5` | - |\n"
        "| SEC-AWS-SG-001 | HIGH | <plan>:0 | aws_security_group.x |\n"
    )
    assert [r["file"] for r in parse_prior_report(md)] == [
        "prod.auto.tfvars",
        ".github/workflows/d.yml",
        "<plan>",
    ]


def test_a_plan_finding_can_not_be_called_fixed(tmp_path) -> None:
    t = tmp_path / "t"
    t.mkdir()
    (t / "main.tf").write_text('variable "x" {\n  type = string\n}\n')
    prior = tmp_path / "prior.json"
    prior.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "SEC-AWS-SG-001",
                        "file": "<plan>",
                        "line": 0,
                        "urgency": "CRITICAL",
                        "resource": "aws_security_group.ssh",
                    },
                    {
                        "id": "SEC-AWS-RDS-002",
                        "file": "<state>",
                        "line": 0,
                        "urgency": "HIGH",
                        "resource": "aws_db_instance.d",
                    },
                ]
            }
        )
    )
    code, results = _verify(t, prior, "--fail-on", "HIGH")
    assert _ids(results["UNVERIFIABLE"]) == {"SEC-AWS-SG-001", "SEC-AWS-RDS-002"}
    assert not results["RESOLVED"] and not results["STALE-LOCATION"]
    assert code == 1


def test_a_file_hidden_by_ignore_paths_is_not_fixed(target, tmp_path) -> None:
    (target / "sub").mkdir()
    (target / "sub" / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
    )
    prior = _report(target, tmp_path)
    (target / ".tf-analyze.yaml").write_text("ignore_paths:\n  - sub\n")
    code, results = _verify(target, prior)
    gone = [r for r in results["RESOLVED"] if "/sub/" in r["file"]]
    assert not gone
    assert any("/sub/" in r["file"] for r in results["UNVERIFIABLE"])


def _probe(finding, entry, tmp_path, **kw) -> str:
    return reprobe_finding(
        finding,
        {entry["id"]: entry},
        kw.pop("files", {}),
        detect_in_file=lambda *a: [],
        detect_corpus=lambda *a: [],
        target=tmp_path,
        **kw,
    )


def test_a_rule_with_no_offline_check_is_not_fixed(tmp_path) -> None:
    """MOD-STALE-001 fires only with --check-registry, which this mode can't run."""
    fp = tmp_path / "main.tf"
    fp.write_text("# x\n")
    finding = {"id": "MOD-STALE-001", "file": str(fp), "line": 1}
    entry = {"id": "MOD-STALE-001", "patterns": [{"kind": "registry_check"}]}
    assert _probe(finding, entry, tmp_path, files={fp: "# x\n"}) == "UNVERIFIABLE"


def test_a_rule_with_no_patterns_is_not_fixed(tmp_path) -> None:
    fp = tmp_path / "main.tf"
    fp.write_text("# x\n")
    assert (
        _probe(
            {"id": "X-Y-001", "file": str(fp), "line": 1},
            {"id": "X-Y-001", "patterns": []},
            tmp_path,
            files={fp: "# x\n"},
        )
        == "UNVERIFIABLE"
    )


def test_a_rule_that_timed_out_is_not_fixed(tmp_path) -> None:
    fp = tmp_path / "main.tf"
    fp.write_text("# x\n")
    entry = {"id": "X-Y-001", "patterns": [{"kind": "grep"}]}
    finding = {"id": "X-Y-001", "file": str(fp), "line": 1}
    assert (
        _probe(
            finding,
            entry,
            tmp_path,
            files={fp: "# x\n"},
            rule_timeouts=[{"rule": "X-Y-001", "file": str(fp)}],
        )
        == "UNVERIFIABLE"
    )
    assert _probe(finding, entry, tmp_path, files={fp: "# x\n"}) == "RESOLVED"


def test_a_file_outside_the_corpus_is_not_fixed(tmp_path) -> None:
    fp = tmp_path / "other.txt"
    fp.write_text("x\n")
    entry = {"id": "X-Y-001", "patterns": [{"kind": "grep"}]}
    assert (
        _probe({"id": "X-Y-001", "file": str(fp), "line": 1}, entry, tmp_path)
        == "UNVERIFIABLE"
    )


def test_a_repository_level_finding_can_still_clear(tmp_path) -> None:
    """`resource_absent` files its finding against the target folder."""
    entry = {"id": "X-Y-001", "patterns": [{"kind": "resource_absent"}]}
    assert (
        _probe({"id": "X-Y-001", "file": str(tmp_path), "line": 0}, entry, tmp_path)
        == "RESOLVED"
    )


def test_the_report_shows_the_new_state(target, tmp_path) -> None:
    prior = tmp_path / "prior.json"
    prior.write_text(
        json.dumps(
            {
                "findings": [
                    {"id": "SEC-AWS-SG-001", "file": "<plan>", "line": 0},
                ]
            }
        )
    )
    res = _run(
        "--target",
        str(target),
        "--mode",
        "verify-fixed",
        "--prior-report",
        str(prior),
        "--reports-dir",
        str(tmp_path / "r"),
    )
    assert "# UNVERIFIABLE: 1" in res.stdout
