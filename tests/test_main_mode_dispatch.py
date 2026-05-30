"""Characterization tests for main()'s early-exit mode dispatch.

These pin the *externally-observable* contract of the `--init`, `--mode fleet`,
and `--mode trend` paths (exit code + the stderr progress markers + side
effects) so the ongoing extraction of those bodies out of `main()` into
module-level `_cmd_*` / `_mode_*` helpers stays behaviour-preserving. They run
the real `detect.py` as a subprocess — the dispatch path had no end-to-end
coverage before this file.
"""
from __future__ import annotations

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
