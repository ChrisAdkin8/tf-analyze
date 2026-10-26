"""Fail-open gate regressions (critical review, 2026-10-26).

Each test pins a path where a scan that should fail ``--fail-on`` used to
exit 0, or where scanning an untrusted repo could write outside it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import _baseline
import pytest

REPO = Path(__file__).resolve().parents[1]

# SEC-AWS-SG-001 is HIGH by default; SSH open to the world escalates it to
# CRITICAL.
SG_TEMPLATE = """\
resource "aws_security_group" "sg" {
  ingress {
    from_port   = %(port)d
    to_port     = %(port)d
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--format",
            "json",
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _sg(dest: Path, port: int = 22) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "main.tf").write_text(SG_TEMPLATE % {"port": port})
    return dest


def _sg_urgency(proc: subprocess.CompletedProcess) -> str:
    findings = json.loads(proc.stdout)["findings"]
    return next(f["urgency"] for f in findings if f["id"] == "SEC-AWS-SG-001")


# ---- --attack-graph ------------------------------------------------------------


def test_attack_graph_keeps_an_escalated_finding(tmp_path) -> None:
    target = _sg(tmp_path / "sg")
    plain = _run("--target", str(target), "--fail-on", "CRITICAL")
    graph = _run("--target", str(target), "--fail-on", "CRITICAL", "--attack-graph")
    assert _sg_urgency(plain) == "CRITICAL"
    assert _sg_urgency(graph) == "CRITICAL"
    assert plain.returncode == graph.returncode == 1


def test_reachability_tiers_move_from_current_urgency() -> None:
    from _attack_graph import _apply_reachability_urgency

    entries = {"R-1": {"default_urgency": "HIGH"}}
    graph = {"critical_path": ["a.crit"], "nodes": [{"id": "a.open", "internet_reachable": True}]}
    plain_unreachable = {"id": "R-1", "resource": "a.hidden"}
    escalated_unreachable = {"id": "R-1", "resource": "a.hidden", "urgency": "CRITICAL"}
    escalated_reachable = {"id": "R-1", "resource": "a.open", "urgency": "CRITICAL"}
    on_path = {"id": "R-1", "resource": "a.crit"}
    findings = [plain_unreachable, escalated_unreachable, escalated_reachable, on_path]
    _apply_reachability_urgency(findings, graph, entries)
    assert plain_unreachable["urgency"] == "MEDIUM"  # demoted from the default
    assert escalated_unreachable["urgency"] == "CRITICAL"  # escalation is kept
    assert escalated_reachable["urgency"] == "CRITICAL"
    assert on_path["urgency"] == "CRITICAL"  # promoted


# ---- --baseline ----------------------------------------------------------------


def test_baseline_does_not_hide_a_finding_that_got_worse(tmp_path) -> None:
    target = _sg(tmp_path / "sg", port=443)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(_run("--target", str(target)).stdout)
    _sg(target, port=22)
    proc = _run(
        "--target", str(target), "--baseline", str(baseline), "--fail-on", "CRITICAL"
    )
    assert proc.returncode == 1
    assert _sg_urgency(proc) == "CRITICAL"


def test_baseline_still_suppresses_an_unchanged_finding(tmp_path) -> None:
    target = _sg(tmp_path / "sg", port=22)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(_run("--target", str(target)).stdout)
    proc = _run(
        "--target", str(target), "--baseline", str(baseline), "--fail-on", "LOW"
    )
    assert proc.returncode == 0


def test_baseline_without_urgency_still_suppresses(tmp_path) -> None:
    # Reports from before findings carried `urgency` must keep working.
    prior = [{"id": "R-1", "file": "main.tf", "resource": "a.b", "line": 1}]
    path = tmp_path / "old.json"
    path.write_text(json.dumps(prior))
    current = [
        {
            "id": "R-1",
            "file": "main.tf",
            "resource": "a.b",
            "line": 1,
            "urgency": "HIGH",
        }
    ]
    retained, suppressed = _baseline.apply_baseline(current, path)
    assert retained == [] and suppressed == current


# ---- .tf-analyze.yaml ----------------------------------------------------------


def test_no_project_config_ignores_a_repo_that_disables_the_gate(tmp_path) -> None:
    target = _sg(tmp_path / "sg")
    (target / ".tf-analyze.yaml").write_text("ignore_rules:\n  - SEC-AWS-SG-001\n")
    assert _run("--target", str(target), "--fail-on", "CRITICAL").returncode == 0
    proc = _run("--target", str(target), "--fail-on", "CRITICAL", "--no-project-config")
    assert proc.returncode == 1


# ---- --mode fleet --------------------------------------------------------------


def test_fleet_mode_honours_fail_on(tmp_path) -> None:
    a = _sg(tmp_path / "a")
    b = _sg(tmp_path / "b", port=443)
    base = ("--mode", "fleet", "--target", str(a), "--target", str(b))
    assert _run(*base, "--fail-on", "CRITICAL").returncode == 1
    assert _run(*base).returncode == 0


# ---- unreadable input ----------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permissions and a non-root user",
)
def test_unreadable_tf_file_fails_the_gate(tmp_path) -> None:
    target = tmp_path / "t"
    target.mkdir()
    tf = target / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "b" {}\n')
    tf.chmod(0)
    try:
        proc = _run("--target", str(target), "--fail-on", "CRITICAL")
    finally:
        tf.chmod(0o644)
    assert proc.returncode == 1
    assert "could not be read" in proc.stderr


# ---- --cache -------------------------------------------------------------------


def test_cache_does_not_replay_plan_findings(tmp_path) -> None:
    target = tmp_path / "t"
    target.mkdir()
    (target / "main.tf").write_text(
        'resource "aws_db_instance" "demo" {\n  engine = "postgres"\n}\n'
    )
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "format_version": "1.0",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": "aws_db_instance.demo",
                                "mode": "managed",
                                "type": "aws_db_instance",
                                "name": "demo",
                                "values": {
                                    "storage_encrypted": False,
                                    "engine": "postgres",
                                },
                            }
                        ]
                    }
                },
            }
        )
    )
    cache = tmp_path / "cache.json"
    fresh = json.loads(_run("--target", str(target)).stdout)["findings"]
    with_plan = json.loads(
        _run(
            "--target",
            str(target),
            "--cache",
            "--cache-file",
            str(cache),
            "--plan-json",
            str(plan),
        ).stdout
    )["findings"]
    assert len(with_plan) > len(fresh)  # the plan added findings
    cached = _run("--target", str(target), "--cache", "--cache-file", str(cache))
    assert "cache hit" in cached.stderr
    assert len(json.loads(cached.stdout)["findings"]) == len(fresh)


# ---- --apply-fixes -------------------------------------------------------------


def test_apply_fixes_does_not_write_through_a_symlinked_bak(tmp_path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    source = 'resource "aws_db_instance" "db" {\n  engine = "postgres"\n}\n'
    (target / "main.tf").write_text(source)
    victim = tmp_path / "victim.txt"
    victim.write_text("precious\n")
    (target / "main.tf.bak").symlink_to(victim)
    proc = _run("--target", str(target), "--apply-fixes", "apply")
    assert victim.read_text() == "precious\n"
    assert (target / "main.tf").read_text() == source
    assert "symlink" in proc.stderr


def test_apply_fixes_does_not_patch_a_symlinked_source(tmp_path) -> None:
    outside = tmp_path / "outside.tf"
    source = 'resource "aws_db_instance" "db" {\n  engine = "postgres"\n}\n'
    outside.write_text(source)
    target = tmp_path / "repo"
    target.mkdir()
    (target / "main.tf").symlink_to(outside)
    _run("--target", str(target), "--apply-fixes", "apply")
    assert outside.read_text() == source
    assert not (target / "main.tf.bak").exists()
