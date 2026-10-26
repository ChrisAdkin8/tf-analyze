"""CI gating must fail closed: a bad target, a failed diff, an unparseable
file or a mode switch must never turn into "no findings, exit 0"."""

from __future__ import annotations

import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import _diff
import detect
import pytest

REPO = Path(__file__).resolve().parents[1]
OPEN_SG = REPO / "fixtures" / "aws_sg_open"  # SEC-AWS-SG-001, HIGH


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


def _copy_open_sg(dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    for tf in OPEN_SG.glob("*.tf"):
        (dest / tf.name).write_text(tf.read_text())
    return dest


# ---- --target ------------------------------------------------------------------


def test_missing_target_is_an_error(tmp_path) -> None:
    proc = _run("--target", str(tmp_path / "nope"), "--fail-on", "LOW")
    assert proc.returncode == 2
    assert "does not exist" in proc.stderr


def test_file_target_is_an_error(tmp_path) -> None:
    src = _copy_open_sg(tmp_path / "crit")
    proc = _run("--target", str(next(src.glob("*.tf"))), "--fail-on", "LOW")
    assert proc.returncode == 2
    assert "is not a directory" in proc.stderr


def test_second_target_is_not_silently_ignored(tmp_path) -> None:
    a = _copy_open_sg(tmp_path / "a")
    proc = _run("--target", str(tmp_path), "--target", str(a))
    assert proc.returncode == 2
    assert "more than one --target" in proc.stderr


def test_empty_target_warns(tmp_path) -> None:
    proc = _run("--target", str(tmp_path))
    assert proc.returncode == 0
    assert "no .tf / .tf.json files found" in proc.stderr


def test_fleet_missing_target_is_an_error(tmp_path) -> None:
    proc = _run("--mode", "fleet", "--target", str(tmp_path / "nope"))
    assert proc.returncode == 2
    assert "not a directory" in proc.stderr


# ---- --diff-base -----------------------------------------------------------------


def test_failed_diff_returns_none_not_empty(tmp_path) -> None:
    assert _diff.get_diff_files(tmp_path, "origin/main") is None  # not a repo


def test_failed_diff_falls_back_to_full_scan(tmp_path) -> None:
    target = _copy_open_sg(tmp_path / "crit")
    proc = _run(
        "--target", str(target), "--diff-base", "origin/main", "--fail-on", "HIGH"
    )
    assert proc.returncode == 1, proc.stderr
    assert "scanning all files" in proc.stderr


# ---- parse failures ------------------------------------------------------------


def test_parse_fallback_fails_only_with_flag(tmp_path, monkeypatch) -> None:
    # Needs the real parser: the forced-fallback CI job reports no parse
    # failures at all.
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)
    (tmp_path / "main.tf").write_text("locals {\n  a = \n}\n")
    assert _run("--target", str(tmp_path)).returncode == 0
    proc = _run("--target", str(tmp_path), "--fail-on-parse-error")
    assert proc.returncode == 1
    assert "--fail-on-parse-error" in proc.stderr


# ---- the gate itself -----------------------------------------------------------


def _args(**kw) -> Namespace:
    return Namespace(**{"fail_on": None, "fail_on_parse_error": False, **kw})


def test_fail_on_info_sees_info_findings() -> None:
    entries = [{"id": "X-INFO-001", "default_urgency": "INFO"}]
    findings = [{"id": "X-INFO-001"}]
    assert detect._gate_exit_code(_args(fail_on="INFO"), findings, entries, []) == 1
    assert detect._gate_exit_code(_args(fail_on="LOW"), findings, entries, []) == 0


def test_finding_without_catalogue_entry_is_gated_on_its_urgency() -> None:
    findings = [{"id": "PLAN-ONLY-001", "urgency": "HIGH"}]
    assert detect._gate_exit_code(_args(fail_on="HIGH"), findings, [], []) == 1


def test_fail_on_info_end_to_end_without_show_info(tmp_path, monkeypatch) -> None:
    """INFO findings are hidden from output by default, but must still
    reach the gate."""
    seen: dict = {}
    real = detect._gate_exit_code

    def spy(args, findings, entries, parse_fallback_files, *rest):
        seen["ids"] = {f["id"] for f in findings}
        return real(args, findings, entries, parse_fallback_files, *rest)

    monkeypatch.setattr(detect, "_gate_exit_code", spy)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "detect.py",
            "--target",
            str(REPO / "fixtures" / "mod_reuse_aws_vpc"),
            "--format",
            "json",
            "--output",
            str(tmp_path / "out.json"),
            "--fail-on",
            "INFO",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        detect.main()
    assert exc.value.code == 1
    assert "MOD-REUSE-AWS-VPC-001" in seen["ids"]


def test_pr_review_mode_honours_fail_on(tmp_path, monkeypatch) -> None:
    target = _copy_open_sg(tmp_path / "crit")
    monkeypatch.setattr(detect, "_pr_review_mode", lambda *a, **k: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "detect.py",
            "--target",
            str(target),
            "--mode",
            "pr-review",
            "--fail-on",
            "HIGH",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        detect.main()
    assert exc.value.code == 1
