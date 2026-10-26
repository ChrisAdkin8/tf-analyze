"""`--baseline` and `--compare` pair findings by rule, target-relative
file and resource — never the line — so code moving or the repo being
checked out elsewhere does not turn known findings into new ones."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from _baseline import apply_baseline, compare_reports

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "examples" / "terragoat" / "aws"


def _f(id_: str, file: str, line: int, resource: str = "aws_x.a") -> dict:
    return {"id": id_, "file": file, "line": line, "resource": resource}


def _write(path: Path, findings: list[dict], target: str | None = None) -> Path:
    data: dict = {"findings": findings}
    if target is not None:
        data["target"] = target
    path.write_text(json.dumps(data))
    return path


# ---- pairing rules -------------------------------------------------------------------


def test_moved_line_still_pairs(tmp_path) -> None:
    base = _write(tmp_path / "b.json", [_f("R-1", "/repo/main.tf", 10)], "/repo")
    retained, suppressed = apply_baseline(
        [_f("R-1", "/repo/main.tf", 12)], base, Path("/repo")
    )
    assert (retained, len(suppressed)) == ([], 1)


def test_repo_checked_out_elsewhere(tmp_path) -> None:
    base = _write(tmp_path / "b.json", [_f("R-1", "/old/ci/main.tf", 3)], "/old/ci")
    retained, _ = apply_baseline(
        [_f("R-1", "/home/me/repo/main.tf", 3)], base, Path("/home/me/repo")
    )
    assert retained == []


def test_old_report_without_target_pairs_by_path_ending(tmp_path) -> None:
    base = _write(tmp_path / "b.json", [_f("R-1", "/old/ci/infra/main.tf", 3)])
    retained, _ = apply_baseline(
        [_f("R-1", "/home/me/repo/infra/main.tf", 9)], base, Path("/home/me/repo")
    )
    assert retained == []


def test_same_rule_in_another_file_is_still_new(tmp_path) -> None:
    base = _write(tmp_path / "b.json", [_f("R-1", "/repo/a.tf", 3)], "/repo")
    retained, _ = apply_baseline([_f("R-1", "/repo/b.tf", 3)], base, Path("/repo"))
    assert len(retained) == 1


def test_duplicates_pair_by_nearest_line(tmp_path) -> None:
    prior = [_f("R-1", "/repo/main.tf", 10, ""), _f("R-1", "/repo/main.tf", 50, "")]
    base = _write(tmp_path / "b.json", prior, "/repo")
    delta = compare_reports([_f("R-1", "/repo/main.tf", 53, "")], base, Path("/repo"))
    assert [f["line"] for f in delta["resolved"]] == [10]  # the far one went
    assert [f["line"] for f in delta["unchanged"]] == [53]
    assert delta["new"] == []


def test_module_named_findings_ignore_the_folder_name(tmp_path) -> None:
    base = _write(
        tmp_path / "b.json",
        [_f("CI-TEST-001", "/a/repo/main.tf", 1, "<module:repo>")],
        "/a/repo",
    )
    retained, _ = apply_baseline(
        [_f("CI-TEST-001", "/b/clone/main.tf", 1, "<module:clone>")],
        base,
        Path("/b/clone"),
    )
    assert retained == []


def test_unreadable_baseline_retains_everything(tmp_path) -> None:
    current = [_f("R-1", "/repo/main.tf", 1)]
    assert apply_baseline(current, tmp_path / "missing.json") == (current, [])


# ---- end to end ----------------------------------------------------------------------


def _scan(target: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--format",
            "json",
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_baseline_survives_lines_moving_and_a_new_checkout(tmp_path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(CORPUS, repo)
    base = tmp_path / "base.json"
    base.write_text(_scan(repo).stdout)
    assert json.loads(base.read_text())["target"] == str(repo.resolve())

    clone = tmp_path / "elsewhere" / "clone"
    shutil.copytree(repo, clone)
    first = sorted(clone.glob("*.tf"))[0]
    first.write_text("# a new comment\n\n" + first.read_text())
    proc = _scan(clone, "--baseline", str(base), "--fail-on", "LOW")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["findings"] == []

    first.write_text(
        first.read_text() + 'resource "aws_db_instance" "brand_new" {\n'
        "  publicly_accessible = true\n}\n"
    )
    proc = _scan(clone, "--baseline", str(base), "--fail-on", "LOW")
    assert proc.returncode == 1
    assert {f["resource"] for f in json.loads(proc.stdout)["findings"]} == {
        "aws_db_instance.brand_new"
    }
