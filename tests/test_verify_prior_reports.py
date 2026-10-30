"""A prior report must really be read before anything is called verified.

A report that parsed to no rows (its own verification report, a
`--format pr-summary` file, an empty file) used to mean nothing to verify:
exit 0 under `--fail-on` on a repository full of CRITICALs.
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

from _diff import find_latest_prior
from _verify import parse_prior_report

SECRET = 'db_password = "SuperSecret123!"\n'


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
    (t / "prod.auto.tfvars").write_text(SECRET)
    (t / "variables.tf").write_text('variable "db_password" {\n  type = string\n}\n')
    return t


def _verify(target: Path, prior: Path, *flags: str) -> subprocess.CompletedProcess:
    return _run(
        "--target",
        str(target),
        "--mode",
        "verify-fixed",
        "--prior-report",
        str(prior),
        *flags,
    )


def test_a_verification_report_is_not_a_prior_report(tmp_path) -> None:
    (tmp_path / "tf-analysis-2026-01-01.md").write_text("old")
    verify = tmp_path / "tf-analysis-verify-2026-01-02.md"
    verify.write_text("newer")
    assert find_latest_prior(tmp_path).name == "tf-analysis-2026-01-01.md"


def test_a_retry_stays_red(target, tmp_path) -> None:
    """`verify-fixed` writes a report; a re-run must not pick it up as the
    prior report, see nothing to verify and go green."""
    reports = tmp_path / "reports"
    reports.mkdir()
    report = reports / "tf-analysis-2026-01-01.md"
    report.write_text(
        "| ID | Urgency | Location | Resource |\n|---|---|---|---|\n"
        "| SEC-SECRETS-001 | CRITICAL | prod.auto.tfvars:1 | - |\n"
    )
    args = (
        "--target",
        str(target),
        "--mode",
        "verify-fixed",
        "--reports-dir",
        str(reports),
        "--fail-on",
        "HIGH",
    )
    assert _run(*args).returncode == 1
    assert list(reports.glob("tf-analysis-verify-*.md"))
    assert _run(*args).returncode == 1


@pytest.mark.parametrize("fmt", ["pr-summary", "mitre", "compliance"])
def test_a_format_with_no_rows_is_refused(target, tmp_path, fmt) -> None:
    prior = tmp_path / f"prior.{fmt}"
    prior.write_text(_run("--target", str(target), "--format", fmt).stdout)
    res = _verify(target, prior, "--fail-on", "HIGH", "--format", "json")
    assert res.returncode == 2, res.stdout + res.stderr


def test_an_empty_file_is_refused(target, tmp_path) -> None:
    prior = tmp_path / "prior.md"
    prior.write_text("")
    assert (
        _verify(target, prior, "--fail-on", "HIGH", "--format", "json").returncode == 2
    )


def test_dev_null_is_refused(target) -> None:
    assert (
        _verify(
            target, Path("/dev/null"), "--fail-on", "HIGH", "--format", "json"
        ).returncode
        == 2
    )


def test_a_text_report_with_a_line_before_its_header_is_read(target, tmp_path) -> None:
    prior = tmp_path / "prior.txt"
    report = _run("--target", str(target), "--format", "text").stdout
    prior.write_text("WARN: something on stderr\n" + report)
    res = _verify(target, prior, "--fail-on", "HIGH", "--format", "json")
    assert res.returncode == 1
    assert json.loads(res.stdout)["total_prior"] > 0


def test_a_truncated_text_report_fails(target, tmp_path) -> None:
    lines = _run("--target", str(target), "--format", "text").stdout.splitlines()
    assert len(lines) >= 3
    prior = tmp_path / "prior.txt"
    prior.write_text(lines[0] + "\n")
    res = _verify(target, prior, "--fail-on", "HIGH", "--format", "json")
    assert res.returncode == 1
    assert "could not be read" in res.stderr


def test_a_clean_report_still_verifies(tmp_path) -> None:
    t = tmp_path / "t"
    t.mkdir()
    (t / "main.tf").write_text('terraform {\n  required_version = ">= 1.5"\n}\n')
    for fmt, name in (("json", "p.json"), ("text", "p.txt")):
        report = _run(
            "--target", str(t), "--format", fmt, "--ignore-file", "/dev/null"
        ).stdout
        prior = tmp_path / name
        clean = (
            json.dumps(
                {
                    "summary": {
                        "counts": {
                            "CRITICAL": 0,
                            "HIGH": 0,
                            "MEDIUM": 0,
                            "LOW": 0,
                            "INFO": 2,
                        }
                    },
                    "findings": [],
                }
            )
            if fmt == "json"
            else "# tf-analyze: 100 (A) · 0 CRITICAL · 0 HIGH · 0 MEDIUM · 0 LOW · 0 INFO\n"
        )
        prior.write_text(clean)
        assert report  # the real formats exist; the clean forms above mirror them
        res = _verify(t, prior, "--fail-on", "HIGH", "--format", "json")
        assert res.returncode == 0, res.stderr
        assert json.loads(res.stdout)["total_prior"] == 0


def test_a_clean_markdown_report_still_verifies(tmp_path) -> None:
    prior = tmp_path / "p.md"
    prior.write_text("# Terraform analysis\n\nNo findings.\n")
    assert parse_prior_report(prior) == []


def test_json_with_counts_but_no_rows_is_refused(tmp_path) -> None:
    prior = tmp_path / "p.json"
    prior.write_text(
        json.dumps({"summary": {"counts": {"CRITICAL": 7}}, "findings": []})
    )
    with pytest.raises(ValueError):
        parse_prior_report(prior)


def test_bare_empty_json_is_refused(tmp_path) -> None:
    prior = tmp_path / "p.json"
    prior.write_text("[]")
    with pytest.raises(ValueError):
        parse_prior_report(prior)


@pytest.mark.parametrize(
    "line, file, lineno, resource",
    [
        ("SEC-X-001 main.tf:3 aws_x.y", "main.tf", 3, "aws_x.y"),
        ("🔥 KEV SEC-X-001 main.tf:3 aws_x.y", "main.tf", 3, "aws_x.y"),
        ("SEC-X-001 my dir/main.tf:3 aws_x.y", "my dir/main.tf", 3, "aws_x.y"),
        ("SEC-X-001 /repo:0 <absent: aws_x>", "/repo", 0, "<absent: aws_x>"),
        ("SEC-X-001 <plan>:0 aws_x.y", "<plan>", 0, "aws_x.y"),
    ],
)
def test_text_rows(tmp_path, line, file, lineno, resource) -> None:
    prior = tmp_path / "p.txt"
    prior.write_text(f"# tf-analyze: 93 (A)\n{line}\n")
    assert parse_prior_report(prior) == [
        {"id": "SEC-X-001", "file": file, "line": lineno, "resource": resource},
    ]


@pytest.mark.parametrize(
    "cell, file, lineno",
    [
        ("main.tf:3", "main.tf", 3),
        ("`main.tf:3`", "main.tf", 3),
        ("`main.tf`:3", "main.tf", 3),
        ("my dir/main.tf:3", "my dir/main.tf", 3),
        ("a+b/main.tf:3", "a+b/main.tf", 3),
        (".:0", ".", 0),
        ("modules/x:0", "modules/x", 0),
        ("prod.auto.tfvars", "prod.auto.tfvars", 0),
        ("main.tf.json:9", "main.tf.json", 9),
        ("<plan>:0", "<plan>", 0),
    ],
)
def test_markdown_rows(tmp_path, cell, file, lineno) -> None:
    prior = tmp_path / "p.md"
    prior.write_text(
        f"| ID | Urgency | Location | Res |\n|---|---|---|---|\n| SEC-X-001 | HIGH | {cell} | r |\n"
    )
    rows = parse_prior_report(prior)
    assert [(r["file"], r["line"]) for r in rows] == [(file, lineno)]
    assert "unparsed" not in rows[0]


def test_an_unreadable_row_is_kept_counted_and_fails_the_gate(target, tmp_path) -> None:
    prior = tmp_path / "p.md"
    prior.write_text(
        "| ID | Urgency | Location | Res |\n|---|---|---|---|\n"
        "| SEC-SECRETS-001 | LOW | see the wiki | r |\n"
    )
    res = _verify(target, prior, "--fail-on", "CRITICAL", "--format", "json")
    data = json.loads(res.stdout)
    assert data["unparsed_rows"] == 1
    assert [r["id"] for r in data["results"]["UNVERIFIABLE"]] == ["SEC-SECRETS-001"]
    assert res.returncode == 1
    assert "could not be read" in res.stderr


def test_an_unreadable_row_only_warns_without_a_gate(target, tmp_path) -> None:
    prior = tmp_path / "p.md"
    prior.write_text("| SEC-SECRETS-001 | LOW | see the wiki | r |\n")
    res = _verify(target, prior, "--format", "json")
    assert res.returncode == 0
    assert "WARN" in res.stderr and "could not be read" in res.stderr


def test_a_json_row_with_no_id_is_counted(tmp_path) -> None:
    prior = tmp_path / "p.json"
    prior.write_text(json.dumps({"findings": [{"file": "main.tf"}]}))
    assert parse_prior_report(prior)[0]["unparsed"]
