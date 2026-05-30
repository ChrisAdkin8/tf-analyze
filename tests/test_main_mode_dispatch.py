"""Characterization tests for main()'s early-exit mode dispatch.

These pin the *externally-observable* contract of the `--init`, `--mode fleet`,
`--mode trend`, and `--mode verify-fixed` paths (exit code + the stderr progress
markers + side effects) so the ongoing extraction of those bodies out of
`main()` into module-level `_cmd_*` / `_mode_*` helpers stays
behaviour-preserving. They run the real `detect.py` as a subprocess — the
dispatch path had no end-to-end coverage before this file.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"


def _run(*argv: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(DETECT_PY), "--no-hcl2", *argv],
        capture_output=True, text=True, timeout=120,
        cwd=str(cwd) if cwd else None,
    )


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), check=True,
                   capture_output=True, text=True)


def test_init_creates_scaffold(tmp_path: Path) -> None:
    res = _run("--init", "--target", str(tmp_path))
    assert res.returncode == 0, res.stderr
    cfg = tmp_path / ".tf-analyze.yaml"
    rule = tmp_path / ".tf-analyze-rules" / "CUSTOM-EXAMPLE-001.yaml"
    assert cfg.exists()
    assert rule.exists()
    assert "id: CUSTOM-EXAMPLE-001" in rule.read_text()


def test_fleet_mode_runs(tmp_path: Path) -> None:
    d1 = tmp_path / "repo1"; d1.mkdir()
    d2 = tmp_path / "repo2"; d2.mkdir()
    for d in (d1, d2):
        (d / "main.tf").write_text(
            'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
        )
    res = _run("--mode", "fleet", "--target", str(d1), "--target", str(d2),
               "--format", "json")
    assert res.returncode == 0, res.stderr
    assert "# fleet:" in res.stderr
    assert res.stdout.strip()  # a report was emitted


def test_trend_mode_runs(tmp_path: Path) -> None:
    repo = tmp_path / "gitrepo"; repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.test")
    _git(repo, "config", "user.name", "t")
    (repo / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "first")
    (repo / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl = "public-read"\n}\n'
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "second")

    res = _run("--mode", "trend", "--target", str(repo), "--lookback", "3650")
    assert res.returncode == 0, res.stderr
    assert "# trend:" in res.stderr


def test_verify_fixed_no_prior_report_errors(tmp_path: Path) -> None:
    target = tmp_path / "tf"; target.mkdir()
    (target / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n')
    empty_reports = tmp_path / "reports"; empty_reports.mkdir()
    res = _run("--mode", "verify-fixed", "--target", str(target),
               "--reports-dir", str(empty_reports))
    assert res.returncode == 2
    assert "no prior report" in res.stderr.lower()


def test_verify_fixed_json_happy_path(tmp_path: Path) -> None:
    target = tmp_path / "tf"; target.mkdir()
    (target / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n')
    # A regex-matching but synthetic ID re-probes to AMBIGUOUS (not in the
    # catalogue), so the fixture doesn't couple to real catalogue IDs.
    prior = tmp_path / "prior.md"
    prior.write_text(
        "# tf-analysis report\n\n"
        "| ID | Urgency | Location | Resource |\n"
        "|----|---------|----------|----------|\n"
        "| FOO-BAR-001 | HIGH | main.tf:2 | aws_s3_bucket.b |\n"
    )
    res = _run("--mode", "verify-fixed", "--target", str(target),
               "--prior-report", str(prior), "--format", "json")
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["total_prior"] == 1
    assert set(data["results"]) == {
        "STILL-PRESENT", "RESOLVED", "MOVED", "STALE-LOCATION", "AMBIGUOUS"
    }


def test_auto_stub_propose_creates_yaml(tmp_path: Path) -> None:
    target = tmp_path / "tf"; target.mkdir()
    (target / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n')
    stub_dir = tmp_path / "stubs"
    res = _run("--target", str(target), "--auto-stub", str(stub_dir),
               "--propose-stub", "FOO-BAR-001")
    # auto-stub runs mid-scan and falls through to normal reporting (exit 0,
    # or 1 only if --fail-on were set, which it isn't here).
    assert res.returncode in (0, 1), res.stderr
    assert "auto-stubs created" in res.stderr
    assert (stub_dir / "FOO-BAR-001.yaml").exists()
