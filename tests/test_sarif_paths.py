"""SARIF that GitHub Code Scanning can use: repo-relative URIs, and
fingerprints that neither collide nor change when code moves."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import _output

REPO = Path(__file__).resolve().parents[1]
OPEN_SG = REPO / "fixtures" / "aws_sg_open"


def _sarif(target: Path) -> dict:
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--format",
            "sarif",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return json.loads(out.stdout)["runs"][0]


def _locations(run: dict) -> list[dict]:
    return [
        r["locations"][0]["physicalLocation"]["artifactLocation"]
        for r in run["results"]
    ]


def _repo_with_infra(root: Path) -> Path:
    (root / ".git").mkdir(parents=True)  # enough for root detection
    infra = root / "infra"
    shutil.copytree(OPEN_SG, infra)
    return infra


def test_uris_are_relative_to_the_repository_root(tmp_path) -> None:
    infra = _repo_with_infra(tmp_path / "repo")
    run = _sarif(infra)
    locs = _locations(run)
    assert locs and all(loc["uriBaseId"] == "%SRCROOT%" for loc in locs)
    assert {loc["uri"] for loc in locs} == {"infra/main.tf"}
    srcroot = run["originalUriBaseIds"]["%SRCROOT%"]["uri"]
    assert srcroot == (tmp_path / "repo").resolve().as_uri() + "/"


def test_outside_a_repository_uris_are_relative_to_the_target(tmp_path) -> None:
    target = tmp_path / "plain dir"
    shutil.copytree(OPEN_SG, target)
    assert {loc["uri"] for loc in _locations(_sarif(target))} == {"main.tf"}


def test_uri_is_percent_encoded(tmp_path) -> None:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    shutil.copytree(OPEN_SG, root / "my infra")
    assert {loc["uri"] for loc in _locations(_sarif(root / "my infra"))} == {
        "my%20infra/main.tf"
    }


def _fingerprints(run: dict) -> list[dict]:
    return [r["partialFingerprints"] for r in run["results"]]


def test_fingerprints_do_not_depend_on_checkout_location(tmp_path) -> None:
    a = _sarif(_repo_with_infra(tmp_path / "a"))
    b = _sarif(_repo_with_infra(tmp_path / "elsewhere" / "b"))
    assert _fingerprints(a) == _fingerprints(b)


def test_fingerprints_survive_lines_moving(tmp_path) -> None:
    infra = _repo_with_infra(tmp_path / "repo")
    before = sorted(map(json.dumps, _fingerprints(_sarif(infra))))
    main = infra / "main.tf"
    main.write_text("# a new comment\n\n" + main.read_text())
    after = sorted(map(json.dumps, _fingerprints(_sarif(infra))))
    assert before == after


def test_findings_sharing_a_key_get_distinct_fingerprints() -> None:
    findings = [
        {"id": "MOD-PIN-001", "file": "/r/main.tf", "line": 9, "resource": ""},
        {"id": "MOD-PIN-001", "file": "/r/main.tf", "line": 3, "resource": ""},
    ]
    entries = [{"id": "MOD-PIN-001", "title": "Module not pinned"}]
    run = _output.to_sarif(findings, entries, source_root=Path("/r"))["runs"][0]
    fps = [r["partialFingerprints"] for r in run["results"]]
    assert fps[0]["tfAnalyze/v1"] != fps[1]["tfAnalyze/v1"]
    # The earlier line is #0, so it keeps the un-numbered fingerprint.
    assert (
        fps[1]["tfAnalyze/v1"]
        == _output._sarif_fingerprint(findings[1], "main.tf")["tfAnalyze/v1"]
    )
    # No resource: no resource-level key that every such finding would share.
    assert all("tfAnalyze/v1-resource" not in fp for fp in fps)
    assert run["results"][0]["message"]["text"] == "Module not pinned (file)"
