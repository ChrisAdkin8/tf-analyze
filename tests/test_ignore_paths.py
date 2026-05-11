"""`.tf-analyze.yaml` `ignore_paths` feature tests.

Added in R30.16 so the public scanner at tfanalyze.com/scan/<owner>/<repo>
doesn't include this repo's deliberately-vulnerable `examples/` and
`fixtures/` directories when grading the repo against itself. The
feature is generally useful for any static-analyzer-style repo that
ships negative fixtures and wants a public score badge that reflects
production code, not test corpora.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DETECT = REPO_ROOT / "scripts" / "detect.py"


def _run(target: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(target), "--format", "json"],
        capture_output=True, text=True,
    )
    assert proc.returncode in (0, 1), f"detect.py crashed: {proc.stderr}"
    return json.loads(proc.stdout)


def test_ignore_paths_skips_listed_dirs(tmp_path: Path) -> None:
    """A directory listed in `ignore_paths` is skipped during the .tf walk."""
    (tmp_path / "main.tf").write_text(textwrap.dedent("""
        resource "aws_s3_bucket" "good" {
          bucket = "ok"
        }
    """).strip())
    excl = tmp_path / "fixtures"
    excl.mkdir()
    (excl / "bad.tf").write_text(textwrap.dedent("""
        resource "aws_s3_bucket" "noisy" {
          bucket = "missing-everything"
        }
    """).strip())
    (tmp_path / ".tf-analyze.yaml").write_text("ignore_paths:\n  - fixtures/\n")
    out = _run(tmp_path)
    files_in_findings = {f["file"] for f in out["findings"]}
    assert not any("fixtures" in str(f) for f in files_in_findings), (
        f"ignored directory still surfaced findings: {files_in_findings}"
    )


def test_ignore_paths_absent_means_no_filtering(tmp_path: Path) -> None:
    """No `.tf-analyze.yaml` → both dirs are scanned (opt-in feature)."""
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "good" { bucket = "ok" }'
    )
    excl = tmp_path / "fixtures"
    excl.mkdir()
    (excl / "bad.tf").write_text(
        'resource "aws_s3_bucket" "noisy" { bucket = "missing-everything" }'
    )
    out = _run(tmp_path)
    files_in_findings = {f["file"] for f in out["findings"]}
    assert any("fixtures" in str(f) for f in files_in_findings), (
        "without ignore_paths, the engine should scan the whole tree, "
        f"but no fixtures/ file appeared in findings: {files_in_findings}"
    )


def test_ignore_paths_does_not_match_string_prefix_accidentally(tmp_path: Path) -> None:
    """`fixtures/` must NOT match a sibling named `fixtures-clean/` — the
    matcher is component-prefix, not string-prefix."""
    sibling = tmp_path / "fixtures-clean"
    sibling.mkdir()
    (sibling / "main.tf").write_text(
        'resource "aws_s3_bucket" "in_sibling" { bucket = "missing-everything" }'
    )
    excluded = tmp_path / "fixtures"
    excluded.mkdir()
    (excluded / "main.tf").write_text(
        'resource "aws_s3_bucket" "in_excluded" { bucket = "missing-everything" }'
    )
    (tmp_path / ".tf-analyze.yaml").write_text("ignore_paths:\n  - fixtures/\n")
    out = _run(tmp_path)
    files = {f["file"] for f in out["findings"]}
    assert any("fixtures-clean" in str(f) for f in files), (
        "fixtures-clean/ should NOT be filtered by ignore_paths: fixtures/ "
        "(component-prefix match, not string-prefix)"
    )
    assert not any(
        str(f).endswith("fixtures/main.tf") or "fixtures/main.tf" in str(f)
        for f in files
    ), f"fixtures/ should have been filtered: {files}"


def test_ignore_paths_nested_dir_pattern(tmp_path: Path) -> None:
    """A multi-component pattern like `vendor/aws-modules/` skips only that
    nested path, not the parent."""
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "main.tf").write_text(
        'resource "aws_s3_bucket" "vendor_root" { bucket = "missing-everything" }'
    )
    (tmp_path / "vendor" / "aws-modules").mkdir()
    (tmp_path / "vendor" / "aws-modules" / "main.tf").write_text(
        'resource "aws_s3_bucket" "vendored" { bucket = "missing-everything" }'
    )
    (tmp_path / ".tf-analyze.yaml").write_text(
        "ignore_paths:\n  - vendor/aws-modules/\n"
    )
    out = _run(tmp_path)
    files = {f["file"] for f in out["findings"]}
    assert any("vendor/main.tf" in str(f) for f in files), (
        "vendor/main.tf should NOT have been filtered — pattern was nested"
    )
    assert not any("vendor/aws-modules" in str(f) for f in files), (
        f"vendor/aws-modules/ should have been filtered: {files}"
    )
