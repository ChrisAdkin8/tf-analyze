"""Every scan mode gates like a static scan.

Each mode used to carry its own copy of "read → detect → suppress →
baseline → gate", and the copies drifted. Each test here pins a case
where a mode passed (or failed) when a static scan of the same input
would not have:

- ``--plan-json`` / ``--state-json``: a broken or wrong-kind file printed
  ERROR, returned no findings, and passed ``--fail-on``.
- ``--mode verify-fixed``: always exited 0; unreadable files came out
  RESOLVED; the CLI's own JSON and text reports parsed to zero findings.
- ``--mode fleet``: skipped suppressions, ``ignore_rules``, the
  empty-target check and ``--fail-on-parse-error``.
- ``--mode pr-review``: posted and gated before ``--baseline`` applied.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DETECT = REPO / "scripts" / "detect.py"

# SEC-AWS-SG-001: SSH open to the world is CRITICAL.
SG = """\
resource "aws_security_group" "sg" {%(comment)s
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

POSIX_NON_ROOT = pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permissions and a non-root user",
)


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(DETECT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _sg(dest: Path, comment: str = "") -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "main.tf").write_text(SG % {"comment": comment})
    return dest


# ---- --plan-json / --state-json ---------------------------------------------

STATE = {
    "format_version": "1.0",
    "values": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_db_instance.d",
                    "mode": "managed",
                    "type": "aws_db_instance",
                    "name": "d",
                    "values": {"publicly_accessible": True},
                }
            ]
        }
    },
}


def test_truncated_plan_fails_instead_of_passing(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text('{"format_version": "1.0", "planned_values": {"root_mod')
    proc = _run("--target", str(tmp_path), "--plan-json", str(plan), "--fail-on", "LOW")
    assert proc.returncode == 2
    assert "malformed" in proc.stderr


def test_state_passed_as_plan_is_refused(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    state.write_text(json.dumps(STATE))
    proc = _run(
        "--target", str(tmp_path), "--plan-json", str(state), "--fail-on", "LOW"
    )
    assert proc.returncode == 2
    assert "use --state-json" in proc.stderr
    # The same file through the right flag is a real scan.
    assert (
        _run(
            "--target", str(tmp_path), "--state-json", str(state), "--fail-on", "LOW"
        ).returncode
        == 1
    )


def test_plan_passed_as_state_is_refused(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps({"format_version": "1.0", "planned_values": STATE["values"]})
    )
    proc = _run(
        "--target", str(tmp_path), "--state-json", str(plan), "--fail-on", "LOW"
    )
    assert proc.returncode == 2
    assert "use --plan-json" in proc.stderr


# ---- --mode verify-fixed ------------------------------------------------------


def _verify(
    target: Path, prior: Path, tmp_path: Path, *extra: str
) -> subprocess.CompletedProcess:
    return _run(
        "--mode",
        "verify-fixed",
        "--target",
        str(target),
        "--prior-report",
        str(prior),
        "--reports-dir",
        str(tmp_path / "reports"),
        "--format",
        "json",
        *extra,
    )


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_verify_fixed_reads_the_clis_own_reports_and_gates(
    tmp_path: Path, fmt: str
) -> None:
    target = _sg(tmp_path / "t")
    prior = tmp_path / f"prior.{fmt}"
    prior.write_text(_run("--target", str(target), "--format", fmt).stdout)

    proc = _verify(target, prior, tmp_path, "--fail-on", "HIGH")
    data = json.loads(proc.stdout)
    assert data["total_prior"] > 0, "the report parsed to no findings"
    assert any(r["id"] == "SEC-AWS-SG-001" for r in data["results"]["STILL-PRESENT"])
    assert proc.returncode == 1
    # Ungated, the same run passes.
    assert _verify(target, prior, tmp_path).returncode == 0


def test_verify_fixed_passes_once_the_finding_is_fixed(tmp_path: Path) -> None:
    target = _sg(tmp_path / "t")
    prior = tmp_path / "prior.json"
    prior.write_text(_run("--target", str(target), "--format", "json").stdout)
    (target / "main.tf").write_text(
        (target / "main.tf").read_text().replace("0.0.0.0/0", "10.0.0.0/8")
    )

    proc = _verify(target, prior, tmp_path, "--fail-on", "HIGH")
    data = json.loads(proc.stdout)
    assert any(r["id"] == "SEC-AWS-SG-001" for r in data["results"]["RESOLVED"])
    assert proc.returncode == 0, proc.stderr


def test_verify_fixed_refuses_a_report_it_cannot_read(tmp_path: Path) -> None:
    target = _sg(tmp_path / "t")
    prior = tmp_path / "prior.html"
    prior.write_text(_run("--target", str(target), "--format", "html").stdout)
    proc = _verify(target, prior, tmp_path)
    assert proc.returncode == 2
    assert "cannot read prior report" in proc.stderr


@POSIX_NON_ROOT
def test_verify_fixed_unreadable_file_is_not_resolved(tmp_path: Path) -> None:
    target = _sg(tmp_path / "t")
    prior = tmp_path / "prior.json"
    prior.write_text(_run("--target", str(target), "--format", "json").stdout)
    tf = target / "main.tf"
    tf.chmod(0)
    try:
        proc = _verify(target, prior, tmp_path, "--fail-on", "CRITICAL")
    finally:
        tf.chmod(0o644)
    results = json.loads(proc.stdout)["results"]
    assert not results["RESOLVED"]
    assert any(r["id"] == "SEC-AWS-SG-001" for r in results["UNREADABLE"])
    assert proc.returncode == 1


# ---- --mode fleet -----------------------------------------------------------


def _fleet(*targets: Path, extra: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
    args = ["--mode", "fleet", "--format", "json"]
    for t in targets:
        args += ["--target", str(t)]
    return _run(*args, *extra)


def test_fleet_honours_inline_suppressions(tmp_path: Path) -> None:
    a = _sg(tmp_path / "a", comment=" # tf-analyze:ignore SEC-AWS-SG-001 bastion")
    b = _sg(tmp_path / "b", comment=" # tf-analyze:ignore SEC-AWS-SG-001 bastion")
    # Static and fleet agree.
    assert _run("--target", str(a), "--fail-on", "CRITICAL").returncode == 0
    proc = _fleet(a, b, extra=("--fail-on", "CRITICAL"))
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["suppressed_count"] == 2
    assert not any(
        f["id"] == "SEC-AWS-SG-001" for fs in data["by_target"].values() for f in fs
    )


def test_fleet_reads_each_targets_project_config(tmp_path: Path) -> None:
    a = _sg(tmp_path / "a")
    b = _sg(tmp_path / "b")
    (b / ".tf-analyze.yaml").write_text("ignore_rules:\n  - SEC-AWS-SG-001\n")
    data = json.loads(_fleet(a, b).stdout)
    ids = {Path(t).name: {f["id"] for f in fs} for t, fs in data["by_target"].items()}
    assert "SEC-AWS-SG-001" in ids["a"]
    assert "SEC-AWS-SG-001" not in ids["b"]
    # --no-project-config turns it off, as in a static scan.
    data = json.loads(_fleet(a, b, extra=("--no-project-config",)).stdout)
    assert all(
        "SEC-AWS-SG-001" in {f["id"] for f in fs} for fs in data["by_target"].values()
    )


def test_fleet_with_an_empty_target_fails_when_gated(tmp_path: Path) -> None:
    a = _sg(tmp_path / "a")
    empty = tmp_path / "empty"
    empty.mkdir()
    proc = _fleet(a, empty, extra=("--fail-on", "LOW"))
    assert proc.returncode == 2
    assert "nothing was checked" in proc.stderr


def test_fleet_honours_fail_on_parse_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Needs the real parser: the forced-fallback CI job reports no parse
    # failures at all.
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)
    a = tmp_path / "a"
    a.mkdir()
    (a / "main.tf").write_text("locals {\n  a = \n}\n")
    assert _fleet(a).returncode == 0
    proc = _fleet(a, extra=("--fail-on-parse-error",))
    assert proc.returncode == 1
    assert "--fail-on-parse-error" in proc.stderr


def test_fleet_refuses_inputs_it_would_ignore(tmp_path: Path) -> None:
    a = _sg(tmp_path / "a")
    proc = _fleet(a, extra=("--targets-file", str(tmp_path / "missing.txt")))
    assert proc.returncode == 2
    assert "--targets-file not found" in proc.stderr
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"planned_values": {}}))
    proc = _fleet(a, extra=("--plan-json", str(plan)))
    assert proc.returncode == 2
    assert "not supported with --mode fleet" in proc.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
def test_fleet_does_not_follow_symlinks_out_of_a_target(tmp_path: Path) -> None:
    outside = _sg(tmp_path / "outside")
    a = tmp_path / "a"
    a.mkdir()
    (a / "linked.tf").symlink_to(outside / "main.tf")
    data = json.loads(_fleet(a).stdout)
    assert not any(
        f["id"] == "SEC-AWS-SG-001" for fs in data["by_target"].values() for f in fs
    )


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
def test_fleet_does_not_read_extra_files_through_symlinks(tmp_path: Path) -> None:
    """Fleet now scans workflow YAML / tfvars too; a symlinked one must
    not pull a file from outside the target into the scan."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "other.yml"
    # SEC-CICD-001: `terraform apply` with no `environment:` gate.
    secret.write_text("jobs:\n  deploy:\n    steps:\n      - run: terraform apply\n")
    a = _sg(tmp_path / "a")
    workflows = a / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").symlink_to(secret)
    assert "ci.yml" not in _fleet(a).stdout
    # A real copy is scanned, so it is the guard that skips the symlink.
    (workflows / "ci.yml").unlink()
    (workflows / "ci.yml").write_text(secret.read_text())
    assert "ci.yml" in _fleet(a).stdout


# ---- --mode pr-review -------------------------------------------------------


def test_pr_review_applies_the_baseline_before_posting_and_gating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import detect  # type: ignore

    target = _sg(tmp_path / "t")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(_run("--target", str(target), "--format", "json").stdout)

    posted: list[list[dict]] = []
    monkeypatch.setattr(
        detect,
        "_pr_review_mode",
        lambda args, findings, entries: posted.append(findings),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "detect.py",
            "--mode",
            "pr-review",
            "--target",
            str(target),
            "--baseline",
            str(baseline),
            "--fail-on",
            "LOW",
            "--repo",
            "o/r",
            "--pr-number",
            "1",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        detect.main()
    assert posted == [[]], "baselined findings were posted"
    assert exc.value.code == 0
