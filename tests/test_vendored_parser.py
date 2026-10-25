"""The vendored HCL parser (tasks/hcl-parser-migration.md §4.1–4.2, Step 1).

The engine always parses with the python-hcl2 + lark copies in
`scripts/_vendor/`, refreshed only by `scripts/vendor_deps.py`. These tests
pin that the vendored copy is the one loaded, that it matches the pins,
that every surface can ship it (wheel package list, grammar files,
licences), where lark's grammar cache may live, that the old
parser-selection switches are harmless no-ops, and that the scan cache
is keyed on the parser version.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "scripts"
VENDOR = SCRIPTS / "_vendor"
DETECT_PY = SCRIPTS / "detect.py"

sys.path.insert(0, str(SCRIPTS))

import _hcl  # noqa: E402
import vendor_deps  # noqa: E402


# ---- the vendored copy is the one loaded ------------------------------------

def test_hcl2_is_loaded_from_vendor_dir() -> None:
    assert _hcl.HCL2_PATH == (VENDOR / "hcl2").resolve()


def test_vendored_parser_loads_in_an_isolated_interpreter() -> None:
    """`-I` ignores user site-packages and PYTHON* env vars: the engine must
    still find its parser with nothing installed."""
    res = subprocess.run(
        [sys.executable, "-I", "-c",
         f"import sys; sys.path.insert(0, {str(SCRIPTS)!r}); import _hcl; "
         "print(_hcl.HCL2_PATH)"],
        capture_output=True, text=True, timeout=60,
    )
    assert res.returncode == 0, res.stderr
    assert Path(res.stdout.strip()) == (VENDOR / "hcl2").resolve()


# ---- the vendored tree matches the pins and can ship ------------------------

def test_versions_file_matches_pins() -> None:
    lines = (VENDOR / "VERSIONS").read_text().split()
    expected = []
    for dist, (version, sha, _pkg) in vendor_deps.PINS.items():
        expected += [f"{dist}=={version}", f"sha256={sha}"]
    assert lines == expected


def test_loaded_versions_match_pins() -> None:
    assert _hcl.HCL2_VERSION == vendor_deps.PINS["python-hcl2"][0]
    assert _hcl.LARK_VERSION == vendor_deps.PINS["lark"][0]


def test_grammar_files_and_licences_are_vendored() -> None:
    assert (VENDOR / "hcl2" / "hcl2.lark").is_file()
    assert (VENDOR / "lark" / "grammars" / "common.lark").is_file()
    for dist in vendor_deps.PINS:
        assert (VENDOR / f"LICENSE.{dist}").is_file()


def test_grammar_cache_is_gitignored() -> None:
    assert "scripts/_vendor/hcl2/.lark_cache.bin" in (REPO_ROOT / ".gitignore").read_text()


def test_pyproject_lists_every_vendored_package() -> None:
    """The wheel ships `scripts/_vendor` as `tf_analyze_vendor`; setuptools
    only installs package dirs that are listed, so a re-vendor that adds a
    subpackage must update pyproject.toml too."""
    on_disk = {
        ".".join(("tf_analyze_vendor",) + p.parent.relative_to(VENDOR).parts)
        for p in VENDOR.rglob("__init__.py")
    }
    listed = set(re.findall(
        r'"(tf_analyze_vendor(?:\.[\w.]+)?)"',
        (REPO_ROOT / "pyproject.toml").read_text(),
    ))
    assert on_disk <= listed, f"missing from pyproject packages: {sorted(on_disk - listed)}"


# ---- grammar cache location -------------------------------------------------

def _no_write(blocked: Path):
    real = os.access

    def access(path, mode, *a, **k):
        if mode == os.W_OK and Path(path).resolve() == blocked.resolve():
            return False
        return real(path, mode, *a, **k)
    return access


def test_grammar_cache_defaults_next_to_vendored_parser() -> None:
    """In a writable checkout the cache sits beside the vendored parser.py."""
    cache = Path(_hcl._hcl2_parser.PARSER_FILE).resolve()
    assert cache.parent == (VENDOR / "hcl2").resolve()


def test_grammar_cache_falls_back_to_user_cache_dir(tmp_path, monkeypatch) -> None:
    ro = tmp_path / "ro"
    ro.mkdir()
    monkeypatch.setattr(_hcl._hcl2_parser, "PARSER_FILE", ro / ".lark_cache.bin")
    monkeypatch.setattr(_hcl.os, "access", _no_write(ro))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(_hcl.sys, "platform", "linux")
    path = _hcl._grammar_cache_path()
    assert path.parent == tmp_path / "xdg" / "tf-analyze"
    assert _hcl.HCL2_VERSION in path.name


def test_grammar_cache_never_uses_shared_temp_dir(tmp_path, monkeypatch) -> None:
    """lark loads the cache with pickle, so it must never sit in a shared,
    world-writable directory. With no writable location it rebuilds in
    memory (os.devnull) instead."""
    ro = tmp_path / "ro"
    ro.mkdir()
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("")
    monkeypatch.setattr(_hcl._hcl2_parser, "PARSER_FILE", ro / ".lark_cache.bin")
    monkeypatch.setattr(_hcl.os, "access", _no_write(ro))
    monkeypatch.setenv("XDG_CACHE_HOME", str(not_a_dir))  # mkdir under a file fails
    monkeypatch.setattr(_hcl.sys, "platform", "linux")
    path = _hcl._grammar_cache_path()
    assert path == Path(os.devnull)
    assert not str(path).startswith(tempfile.gettempdir())


# ---- deprecated parser switches ---------------------------------------------

def _run(*argv: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(DETECT_PY), *argv],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, **(env or {})},
    )


def test_deprecated_flags_are_no_ops_with_a_notice() -> None:
    for flag in ("--no-hcl2", "--use-hcl2"):
        res = _run(flag, "--list-rules")
        assert res.returncode == 0, res.stderr
        assert f"NOTE: {flag} is deprecated and has no effect" in res.stderr


def test_deprecated_env_vars_print_a_notice() -> None:
    for var in ("TF_ANALYZE_NO_HCL2", "TF_ANALYZE_USE_HCL2"):
        res = _run("--list-rules", env={var: "1"})
        assert res.returncode == 0, res.stderr
        assert f"NOTE: {var} is deprecated and has no effect" in res.stderr


def test_deprecated_flags_are_hidden_from_help() -> None:
    res = _run("--help")
    assert res.returncode == 0
    assert "hcl2" not in res.stdout


def test_no_notice_without_deprecated_switches() -> None:
    env = {k: v for k, v in os.environ.items()
           if k not in ("TF_ANALYZE_NO_HCL2", "TF_ANALYZE_USE_HCL2")}
    res = subprocess.run(
        [sys.executable, str(DETECT_PY), "--list-rules"],
        capture_output=True, text=True, timeout=60, env=env,
    )
    assert "deprecated" not in res.stderr
    assert "python-hcl2 not installed" not in res.stderr


# ---- scan cache is keyed on the parser --------------------------------------

def test_corpus_hash_changes_with_parser_version(monkeypatch) -> None:
    import _cache
    files = {"main.tf": 'resource "null_resource" "x" {}\n'}
    entries = [{"id": "X-001", "patterns": []}]
    before = _cache.corpus_hash(files, entries)
    assert _cache.corpus_hash(files, entries) == before
    monkeypatch.setattr(_hcl, "HCL2_VERSION", "0.0.0-test")
    assert _cache.corpus_hash(files, entries) != before


def test_old_cache_format_is_ignored(tmp_path) -> None:
    import json
    import _cache
    p = tmp_path / ".tf-analyze-cache.json"
    p.write_text(json.dumps({"version": 1, "corpus_hash": "x", "findings": []}))
    assert _cache.load_scan_cache(p) is None
    _cache.save_scan_cache(p, "abc", [])
    assert _cache.load_scan_cache(p)["version"] == _cache.CACHE_FORMAT_VERSION
