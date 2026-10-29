"""The VS Code extension only passes flags the engine accepts.

The extension built its scan and report command lines with
``--section <s>``, a flag ``detect.py`` never had (the flag is
``--focus``). Anyone who set ``tf-analyze.section`` got an argparse
error (exit 2) and no scan. These tests read every ``--flag`` string
literal in the extension's TypeScript source and check that the
engine's parser knows it, and that ``--focus`` really narrows a scan
to the values the ``tf-analyze.section`` setting offers.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import CATALOG_DIR, DETECT_PY, FIXTURES_DIR, run_detect

REPO_ROOT = Path(__file__).parent.parent
EXT_DIR = REPO_ROOT / "vscode-extension"
EXT_SRC = EXT_DIR / "src"

_FLAG_LITERAL = re.compile(r"--[a-z][a-z0-9-]*(?==|$)")


def _string_literals(src: str) -> list[str]:
    """Contents of the '...', "..." and `...` literals in TypeScript
    source, skipping // and /* */ comments (doc comments quote flags
    such as `--flag value` that are never passed to the engine)."""
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j == -1 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j == -1 else j + 2
        elif c in "'\"`":
            j = i + 1
            buf = []
            while j < n and src[j] != c:
                if src[j] == "\\":
                    buf.append(src[j : j + 2])
                    j += 2
                    continue
                buf.append(src[j])
                j += 1
            out.append("".join(buf))
            i = j + 1
        else:
            i += 1
    return out


def _extension_flags() -> dict[str, set[str]]:
    """Map each engine flag the extension's source names in a string
    literal to the files that name it."""
    found: dict[str, set[str]] = {}
    sources = [
        p for p in EXT_SRC.rglob("*.ts") if "test" not in p.relative_to(EXT_SRC).parts
    ]
    for ts in sources:
        for lit in _string_literals(ts.read_text(encoding="utf-8")):
            m = _FLAG_LITERAL.match(lit)
            if m:
                found.setdefault(m.group(0), set()).add(ts.name)
    return found


def _engine_options() -> set[str]:
    import detect  # type: ignore

    opts: set[str] = set()
    for action in detect._build_parser()._actions:
        opts.update(action.option_strings)
    return opts


@pytest.fixture(scope="module")
def ext_flags() -> dict[str, set[str]]:
    if not EXT_SRC.is_dir():
        pytest.skip("vscode-extension/src not present")
    return _extension_flags()


def test_extension_flag_scan_is_not_vacuous(ext_flags: dict[str, set[str]]) -> None:
    # If the literal scanner breaks, the check below would pass on an
    # empty set; make sure it still sees the flags every scan uses.
    assert {"--target", "--format", "--attack-graph", "--focus"} <= set(ext_flags)


def test_every_extension_flag_is_an_engine_flag(ext_flags: dict[str, set[str]]) -> None:
    unknown = {
        f: sorted(files) for f, files in ext_flags.items() if f not in _engine_options()
    }
    assert not unknown, (
        f"the VS Code extension passes flags detect.py does not accept: {unknown}"
    )


def test_extension_never_passes_section() -> None:
    for ts in EXT_SRC.rglob("*.ts"):
        for lit in _string_literals(ts.read_text(encoding="utf-8")):
            assert lit != "--section", f"{ts.name}: use --focus, not --section"


def _section_setting_values() -> list[str]:
    pkg = json.loads((EXT_DIR / "package.json").read_text(encoding="utf-8"))
    prop = pkg["contributes"]["configuration"]["properties"]["tf-analyze.section"]
    return [v for v in prop["enum"] if v]


def test_section_setting_values_are_catalogue_sections() -> None:
    from _catalog import load_catalog  # type: ignore

    sections = {e.get("section") for e in load_catalog(CATALOG_DIR)}
    missing = sorted(set(_section_setting_values()) - sections)
    assert not missing, f"tf-analyze.section offers sections with no rules: {missing}"


def test_focus_narrows_a_scan_to_one_section() -> None:
    target = FIXTURES_DIR / "attack_graph_demo"
    everything = run_detect(target, all_rules=True)
    sections = {f.get("section") for f in everything}
    assert len(sections) > 1, "fixture needs findings from more than one section"
    section = "security"
    assert section in sections


    r = subprocess.run(
        [
            sys.executable,
            str(DETECT_PY),
            "--target",
            str(target),
            "--format",
            "json",
            "--show-info",
            "--focus",
            section,
        ],
        capture_output=True,
        text=True,
    )
    assert r.returncode in (0, 1), r.stderr
    focused = json.loads(r.stdout)["findings"]
    assert focused
    assert {f.get("section") for f in focused} == {section}
    assert len(focused) == sum(1 for f in everything if f.get("section") == section)


def test_focus_on_unknown_section_is_an_error() -> None:

    r = subprocess.run(
        [
            sys.executable,
            str(DETECT_PY),
            "--target",
            str(FIXTURES_DIR / "attack_graph_demo"),
            "--format",
            "json",
            "--focus",
            "no-such-section",
        ],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 2
    assert "--focus" in r.stderr
