"""The scanner runs on untrusted Terraform (e.g. a pull request). Content
in the scanned tree must not be able to hide findings, read or write
files outside the target, or inject script into the HTML report."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import _attack_graph
import _cache
import detect

REPO = Path(__file__).resolve().parents[1]
OPEN_SG = REPO / "fixtures" / "aws_sg_open"  # SEC-AWS-SG-001


def _scan(target: Path, *extra: str, env: dict | None = None):
    out = subprocess.run(
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
        env=env,
    )
    return json.loads(out.stdout)["findings"], out.stderr


def _copy_open_sg(dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    for tf in OPEN_SG.glob("*.tf"):
        (dest / tf.name).write_text(tf.read_text())
    return dest


# ---- scan cache ------------------------------------------------------------------


def test_default_cache_path_is_outside_the_target(tmp_path) -> None:
    path = _cache.default_cache_path(tmp_path)
    assert not path.resolve().is_relative_to(tmp_path.resolve())
    assert path != _cache.default_cache_path(tmp_path / "other")


def test_committed_cache_file_cannot_replay_clean_result(tmp_path, monkeypatch) -> None:
    target = _copy_open_sg(tmp_path / "repo")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    findings, _ = _scan(target, "--cache")
    assert "SEC-AWS-SG-001" in {f["id"] for f in findings}
    # The corpus hash is computable from public inputs; take the real one
    # from wherever the first scan wrote its cache.
    in_target = target / ".tf-analyze-cache.json"
    written = in_target if in_target.exists() else _cache.default_cache_path(target)
    real_hash = json.loads(written.read_text())["corpus_hash"]
    # A PR commits a cache file at the (old) default path, findings blanked.
    in_target.write_text(json.dumps({
        "version": _cache.CACHE_FORMAT_VERSION, "corpus_hash": real_hash,
        "findings": [],
    }))
    findings, _ = _scan(target, "--cache")
    assert "SEC-AWS-SG-001" in {f["id"] for f in findings}


def test_cache_write_replaces_a_symlink_instead_of_following_it(tmp_path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    link = tmp_path / "cache.json"
    link.symlink_to(victim)
    _cache.save_scan_cache(link, "abc", [])
    assert victim.read_text() == "keep me"
    assert not link.is_symlink()
    assert _cache.load_scan_cache(link)["corpus_hash"] == "abc"


# ---- HTML report -------------------------------------------------------------------


def test_graph_json_cannot_close_its_script_block() -> None:
    evil = "</script><img src=x onerror=alert(1)><!--"
    html = _attack_graph._render_graph_html(
        {"nodes": [{"id": evil, "label": evil}], "edges": []}
    )
    assert "</script><img" not in html and "<!--" not in html
    start = html.index("var G=") + len("var G=")
    graph = json.loads(html[start : html.index(";\n", start)])
    assert graph["nodes"][0]["id"] == evil  # same data once parsed


# ---- symlinks --------------------------------------------------------------------------


def test_symlink_out_of_the_target_is_not_read(tmp_path) -> None:
    outside = _copy_open_sg(tmp_path / "outside")
    target = tmp_path / "repo"
    target.mkdir()
    (target / "leak.tf").symlink_to(next(outside.glob("*.tf")))
    (target / "sub").mkdir()
    (target / "sub" / "inside.tf").symlink_to(target / "leak.tf")
    findings, stderr = _scan(target)
    assert not any(f["id"] == "SEC-AWS-SG-001" for f in findings)
    assert "resolves outside the target" in stderr


def test_tf_json_symlink_out_of_the_target_is_not_read(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "main.tf.json").write_text(json.dumps({"resource": {
        "aws_db_instance": {"d": {"publicly_accessible": True}}}}))
    target = tmp_path / "repo"
    target.mkdir()
    (target / "leak.tf.json").symlink_to(outside / "main.tf.json")
    findings, stderr = _scan(target)
    assert not any(f["id"] == "SEC-AWS-RDS-001" for f in findings)
    assert "resolves outside the target" in stderr


def test_symlink_within_the_target_is_scanned(tmp_path) -> None:
    target = tmp_path / "repo"
    real = _copy_open_sg(target / "real")
    (target / "linked.tf").symlink_to(next(real.glob("*.tf")))
    files = {
        Path(f["file"]).name for f in _scan(target)[0] if f["id"] == "SEC-AWS-SG-001"
    }
    assert "linked.tf" in files


# ---- inline suppressions --------------------------------------------------------------


def test_ignore_marker_counts_only_in_comments() -> None:
    text = (
        'resource "a" "b" { # tf-analyze:ignore X-1\n'
        '  description = "# tf-analyze:ignore X-2"\n'
        "  s = <<EOT\n"
        "# tf-analyze:ignore X-3\n"
        "EOT\n"
        '  y = "http://x" // c # tf-analyze:ignore X-4\n'
        "}\n"
    )
    found = set().union(*detect.load_inline_suppressions(text).values())
    assert found == {"X-1", "X-4"}


def test_string_value_does_not_suppress_end_to_end(tmp_path) -> None:
    src = (OPEN_SG / "main.tf").read_text()
    header = 'resource "aws_security_group" '
    assert header in src
    # A string value on the line above the header: as a comment, the
    # marker would cover the header line and hide the finding.
    marker = 'locals { note = "# tf-analyze:ignore SEC-AWS-SG-001" }\n'
    (tmp_path / "main.tf").write_text(src.replace(header, marker + header, 1))
    assert "SEC-AWS-SG-001" in {f["id"] for f in _scan(tmp_path)[0]}
