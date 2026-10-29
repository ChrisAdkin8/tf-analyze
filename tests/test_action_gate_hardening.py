"""The GitHub Action's gate must fail when the scan says it should.

Each test pins a path where `action.yml` passed a PR it should have failed
(critical review, 2026-10-29): `--attack-graph` demoting a hard-coded
secret, fleet / trend output the gate couldn't read, an unreadable file,
a baseline taken from the PR, flags the engine doesn't accept, and report
writes that a committed symlink could redirect. The step scripts are run
for real, with `docker` replaced by a stub where a scan is needed.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from test_action_trusted_config import OPEN_SG, _repo, _run_trusted

REPO_ROOT = Path(__file__).parent.parent
DETECT = REPO_ROOT / "scripts" / "detect.py"
ACTION = yaml.safe_load((REPO_ROOT / "action.yml").read_text())

DEMOTE_TF = """\
resource "aws_db_instance" "db" {
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  username          = "admin"
  password          = "SuperSecret123!"
  storage_encrypted = true
}
"""


def _step(name: str) -> dict:
    return next(s for s in ACTION["runs"]["steps"] if s.get("name") == name)


def _detect(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(DETECT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _gate(
    tmp_path: Path, report, fail_on: str = "CRITICAL"
) -> subprocess.CompletedProcess:
    """Run the action's "Apply fail-on threshold" step on `report`."""
    path = tmp_path / "report.json"
    path.write_text(report if isinstance(report, str) else json.dumps(report))
    return subprocess.run(
        ["bash", "-c", _step("Apply fail-on threshold")["run"]],
        env={**os.environ, "TFA_FAIL_ON": fail_on, "TFA_JSON_REPORT": str(path)},
        capture_output=True,
        text=True,
        check=False,
    )


# ---- 1. --attack-graph keeps a credential finding's urgency --------------------


def test_attack_graph_does_not_demote_a_hardcoded_secret(tmp_path: Path) -> None:
    # A private database is "unreachable", but its hard-coded password is
    # read from the source, not over the network.
    (tmp_path / "main.tf").write_text(DEMOTE_TF)
    proc = _detect(
        "--target",
        str(tmp_path),
        "--format",
        "json",
        "--attack-graph",
        "--fail-on",
        "CRITICAL",
        "--no-project-config",
    )
    urgency = {f["id"]: f["urgency"] for f in json.loads(proc.stdout)["findings"]}
    assert urgency["SEC-SECRETS-001"] == "CRITICAL"
    assert proc.returncode == 1
    # A network finding on the same unreachable database is still demoted.
    plain = _detect(
        "--target", str(tmp_path), "--format", "json", "--no-project-config"
    )
    before = {f["id"]: f["urgency"] for f in json.loads(plain.stdout)["findings"]}
    assert before["ROB-AWS-RDS-001"] == "MEDIUM" and urgency["ROB-AWS-RDS-001"] == "LOW"


def test_reach_independent_rules_keep_their_urgency() -> None:
    from _attack_graph import _apply_reachability_urgency, _reach_independent

    entries = {
        "CRED": {"default_urgency": "HIGH", "cwe": ["CWE-798"]},
        "ATTCK": {"default_urgency": "HIGH", "mitre": ["T1552.001"]},
        "NET": {"default_urgency": "HIGH", "cwe": ["CWE-284"]},
    }
    assert _reach_independent(entries["CRED"]) and _reach_independent(entries["ATTCK"])
    assert not _reach_independent(entries["NET"])
    graph = {
        "critical_path": [],
        "nodes": [
            {"id": "a.db", "internet_reachable": False, "exposure_modelled": True}
        ],
    }
    findings = [{"id": rid, "resource": "a.db"} for rid in entries]
    _apply_reachability_urgency(findings, graph, entries)
    assert [f["urgency"] for f in findings] == ["HIGH", "HIGH", "MEDIUM"]


# ---- 2. fleet and trend output -------------------------------------------------


def _fleet_report(tmp_path: Path, fmt: str = "json") -> subprocess.CompletedProcess:
    for name, port in (("a", 22), ("b", 443)):
        d = tmp_path / name
        d.mkdir(exist_ok=True)
        (d / "main.tf").write_text(OPEN_SG.replace("22", str(port)))
    return _detect(
        "--mode",
        "fleet",
        "--target",
        str(tmp_path / "a"),
        "--target",
        str(tmp_path / "b"),
        "--format",
        fmt,
    )


def test_gate_fails_on_a_fleet_report(tmp_path: Path) -> None:
    proc = _fleet_report(tmp_path)
    data = json.loads(proc.stdout)
    assert "findings" not in data and "by_target" in data
    gate = _gate(tmp_path, proc.stdout, "CRITICAL")
    assert gate.returncode == 1, gate.stderr
    assert "at or above CRITICAL" in gate.stderr


def test_fleet_findings_carry_their_urgency(tmp_path: Path) -> None:
    # Only escalated findings had `urgency`; a CRITICAL-by-default rule
    # (here a wildcard IAM policy) passed the gate.
    d = tmp_path / "a"
    d.mkdir()
    (d / "main.tf").write_text(
        'resource "aws_iam_policy" "admin" {\n'
        '  name = "admin"\n'
        "  policy = jsonencode({\n"
        '    Version   = "2012-10-17"\n'
        '    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]\n'
        "  })\n"
        "}\n"
    )
    proc = _detect("--mode", "fleet", "--target", str(d), "--format", "json")
    data = json.loads(proc.stdout)
    findings = [f for fs in data["by_target"].values() for f in fs]
    assert all(f.get("urgency") for f in findings)
    gate = _gate(tmp_path, proc.stdout, "CRITICAL")
    assert gate.returncode == 1, gate.stderr


def test_gate_fails_on_fleet_unreadable_files(tmp_path: Path) -> None:
    report = {
        "by_target": {"/a": []},
        "fleet_wide": [],
        "summary": {"/a": 0},
        "unreadable_files": ["/a/x.tf"],
    }
    gate = _gate(tmp_path, report, "CRITICAL")
    assert gate.returncode == 1 and "could not be read" in gate.stderr


def test_fleet_sarif_is_sarif(tmp_path: Path) -> None:
    proc = _fleet_report(tmp_path, "sarif")
    sarif = json.loads(proc.stdout)  # it used to be the Markdown report
    assert sarif["version"] == "2.1.0"
    ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "SEC-AWS-SG-001" in ids


def test_gate_fails_on_a_report_that_is_not_a_findings_report(tmp_path: Path) -> None:
    # --mode trend emits a list of per-commit rows.
    gate = _gate(tmp_path, [{"date": "2026-10-29", "sha": "abc", "total": 3}])
    assert gate.returncode == 1


def _resolve_mode(
    tmp_path: Path, mode: str, plan_json: str = ""
) -> tuple[int, str, str]:
    gh_out = tmp_path / "gh_output"
    gh_out.write_text("")
    proc = subprocess.run(
        ["bash", "-c", _step("Resolve mode")["run"]],
        env={
            **os.environ,
            "TFA_MODE_IN": mode,
            "TFA_EVENT": "push",
            "TFA_PLAN_JSON": plan_json,
            "GITHUB_OUTPUT": str(gh_out),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout, gh_out.read_text()


def test_mode_trend_is_rejected_with_a_reason(tmp_path: Path) -> None:
    rc, stdout, _ = _resolve_mode(tmp_path, "trend")
    assert rc == 1 and "history report" in stdout


def test_mode_plan_needs_plan_json_and_runs_static(tmp_path: Path) -> None:
    rc, stdout, _ = _resolve_mode(tmp_path, "plan")
    assert rc == 1 and "plan-json" in stdout
    rc, _, out = _resolve_mode(tmp_path, "plan", "plan.json")
    assert rc == 0 and "mode=static" in out


# ---- 3. unreadable files -------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permissions and a non-root user",
)
def test_gate_fails_on_an_unreadable_file(tmp_path: Path) -> None:
    target = tmp_path / "t"
    target.mkdir()
    (target / "ok.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    bad = target / "bad.tf"
    bad.write_text(DEMOTE_TF)
    bad.chmod(0)
    try:
        proc = _detect("--target", str(target), "--format", "json")
    finally:
        bad.chmod(0o644)
    summary = json.loads(proc.stdout)["summary"]
    assert summary["unreadable_files"] == [str(bad)]
    gate = _gate(tmp_path, proc.stdout, "CRITICAL")
    assert gate.returncode == 1 and "could not be read" in gate.stderr


# ---- 4. baseline from the base branch ------------------------------------------


def _baseline_report(findings: list[dict]) -> str:
    return json.dumps({"findings": findings})


def _args_step(tmp_path: Path, **env: str) -> list[str]:
    args_file = tmp_path / "base-args"
    script = _step("Build detect.py args")["run"].replace(
        "/tmp/tf-analyze-base-args", str(args_file)
    )
    full = {
        **os.environ,
        "TFA_TARGET": ".",
        "TFA_MODE_OUT": "static",
        "GITHUB_OUTPUT": str(tmp_path / "o"),
        "TFA_TRUSTED_DIR": "",
        "TFA_TRUSTED_CONFIG": "",
        "TFA_TRUSTED_IGNORE": "",
        "TFA_TRUSTED_BASELINE": "",
        **env,
    }
    subprocess.run(["bash", "-c", script], env=full, check=True, capture_output=True)
    return args_file.read_text().splitlines()


def _trusted(monkeypatch, repo: Path, tmp_path: Path, baseline: str) -> dict[str, str]:
    """Run the base-branch config step with the `baseline` input set."""
    monkeypatch.setenv("TFA_BASELINE", baseline)
    return _run_trusted(repo, tmp_path)


def test_pr_cannot_baseline_its_own_findings(tmp_path: Path, monkeypatch) -> None:
    base_baseline = _baseline_report([])
    pr_baseline = _baseline_report(
        [
            {
                "id": "SEC-AWS-SG-001",
                "file": "main.tf",
                "resource": "aws_security_group.open",
            }
        ]
    )
    repo = _repo(
        tmp_path,
        base={"main.tf": "", "ci/baseline.json": base_baseline},
        pr={"main.tf": OPEN_SG, "ci/baseline.json": pr_baseline},
    )
    env_out = _trusted(monkeypatch, repo, tmp_path, "ci/baseline.json")
    assert env_out["baseline"] == "/trusted/ci/baseline.json"
    copied = Path(env_out["dir"]) / "ci" / "baseline.json"
    assert copied.read_text() == base_baseline
    args = _args_step(
        tmp_path,
        TFA_BASELINE="ci/baseline.json",
        TFA_TRUSTED_DIR=env_out["dir"],
        TFA_TRUSTED_BASELINE=env_out["baseline"],
    )
    assert args[args.index("--baseline") + 1] == "/trusted/ci/baseline.json"


def test_baseline_missing_on_base_scans_without_one(tmp_path: Path, monkeypatch) -> None:
    repo = _repo(tmp_path, base={"main.tf": OPEN_SG}, pr={"ci/baseline.json": "{}"})
    env_out = _trusted(monkeypatch, repo, tmp_path, "ci/baseline.json")
    assert "baseline" not in env_out
    args = _args_step(
        tmp_path,
        TFA_BASELINE="ci/baseline.json",
        TFA_TRUSTED_DIR=env_out["dir"],
    )
    assert "--baseline" not in args


def test_baseline_path_cannot_leave_the_repo(tmp_path: Path, monkeypatch) -> None:
    repo = _repo(tmp_path, base={"main.tf": OPEN_SG}, pr={})
    env_out = _trusted(monkeypatch, repo, tmp_path, "../outside.json")
    assert "baseline" not in env_out


def test_baseline_outside_a_pr_is_the_workspace_copy(tmp_path: Path) -> None:
    args = _args_step(tmp_path, TFA_BASELINE="ci/baseline.json")
    assert args[args.index("--baseline") + 1] == "/workspace/ci/baseline.json"



def test_baseline_entry_without_urgency_cannot_hide_an_escalation(
    tmp_path: Path,
) -> None:
    import _baseline

    path = tmp_path / "old.json"
    path.write_text(
        json.dumps([{"id": "R-1", "file": "main.tf", "resource": "a.b", "line": 1}])
    )

    def current(urgency: str) -> list[dict]:
        return [
            {
                "id": "R-1",
                "file": "main.tf",
                "resource": "a.b",
                "line": 1,
                "urgency": urgency,
            }
        ]

    defaults = {"R-1": "HIGH"}
    # At the rule's default urgency: an old baseline still suppresses it.
    assert _baseline.apply_baseline(current("HIGH"), path, None, defaults)[0] == []
    # Escalated above the default: kept.
    assert _baseline.apply_baseline(current("CRITICAL"), path, None, defaults)[0] != []
    # Unknown rule: the missing urgency counts as the lowest tier.
    assert _baseline.apply_baseline(current("LOW"), path)[0] != []
    assert _baseline.apply_baseline(current("INFO"), path)[0] == []


# ---- 5. every flag the action passes is one the engine accepts -----------------


def test_engine_accepts_every_flag_the_action_passes(tmp_path: Path) -> None:
    import detect

    args = _args_step(
        tmp_path,
        TFA_MODE_OUT="diff",
        TFA_DIFF_BASE="origin/main",
        TFA_SECTION="security",
        TFA_PLAN_JSON="plan.json",
        TFA_ATTACK_GRAPH="true",
        TFA_BASELINE="baseline.json",
        TFA_COMPLIANCE_FW="cis",
        TFA_TRUSTED_DIR="/rt/tf-analyze-trusted",
        TFA_TRUSTED_CONFIG="/trusted/.tf-analyze.yaml",
        TFA_TRUSTED_IGNORE="/trusted/none",
        TFA_TRUSTED_BASELINE="/trusted/baseline.json",
    )
    # Every optional input is set, so every branch added its flag.
    for flag in (
        "--focus",
        "--plan-json",
        "--attack-graph",
        "--baseline",
        "--compliance-framework",
        "--diff-base",
        "--config",
        "--ignore-file",
    ):
        assert flag in args, flag
    # The scan step appends these to every run.
    scan = _step("Run tf-analyze (JSON)")["run"]
    assert '--format "$fmt" --cache --cache-file /tmp/tf-analyze-cache.json' in scan
    for fmt in ("json", "sarif", "html", "pr-summary"):
        ns = detect._build_parser().parse_args(
            [*args, "--format", fmt, "--cache", "--cache-file", "/tmp/c.json"]
        )
        assert ns.focus == "security" and ns.mode == "diff"
    # And each mode the action can hand the engine is an engine mode.
    mode_choices = next(
        a.choices
        for a in detect._build_parser()._actions
        if "--mode" in a.option_strings
    )
    for mode in ("static", "diff", "fleet", "pr-review"):
        assert mode in mode_choices


# ---- 6. reports are not written into the PR's checkout -------------------------


def test_scan_writes_reports_outside_the_workspace(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched\n")
    # A PR commits the report names as symlinks pointing outside the workspace.
    for name in (
        "tf-analyze-findings.json",
        "tf-analyze.sarif",
        "tf-analyze-report.html",
        "tf-analyze-pr-summary.md",
        "tf-analyze-json-stderr.txt",
    ):
        (ws / name).symlink_to(victim)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'echo \'{"summary": {"counts": {"CRITICAL": 1}}, '
        '"findings": [{"id": "X", "urgency": "CRITICAL"}]}\'\n'
        "echo engine-stderr >&2\n"
    )
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    args_file = tmp_path / "base-args"
    args_file.write_text("--target\n/workspace/.\n")
    runner_temp = tmp_path / "rt"
    runner_temp.mkdir()
    gh_out = tmp_path / "gh_output"
    gh_out.write_text("")
    script = (
        _step("Run tf-analyze (JSON)")["run"]
        .replace("${{ github.workspace }}", str(ws))
        .replace("/tmp/tf-analyze-base-args", str(args_file))
    )
    proc = subprocess.run(
        ["bash", "-c", script],
        cwd=ws,
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "TFA_IMAGE": "img",
            "TFA_TRUSTED_DIR": "",
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_OUTPUT": str(gh_out),
            "GITHUB_WORKSPACE": str(ws),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert victim.read_text() == "untouched\n"
    outputs = dict(line.split("=", 1) for line in gh_out.read_text().splitlines())
    report = Path(outputs["json-report-path"])
    assert report.parent.parent == runner_temp
    assert json.loads(report.read_text())["findings"][0]["id"] == "X"
    assert outputs["total"] == "1" and outputs["critical"] == "1"
    for key in ("sarif-report-path", "html-report-path", "pr-summary-path"):
        assert Path(outputs[key]).parent == report.parent
    # Every later step reads the reports through these outputs.
    text = (REPO_ROOT / "action.yml").read_text()
    after_scan = text[text.index("- name: Upload SARIF to Code Scanning") :]
    assert (
        "github.workspace" not in after_scan
        and "GITHUB_WORKSPACE"
        not in after_scan.replace("runner-side GITHUB_WORKSPACE", "")
    )
    # The gate reads it too, and fails on the CRITICAL.
    gate = subprocess.run(
        ["bash", "-c", _step("Apply fail-on threshold")["run"]],
        env={**os.environ, "TFA_FAIL_ON": "HIGH", "TFA_JSON_REPORT": str(report)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert gate.returncode == 1
