"""Catalogue regexes must not backtrack catastrophically, and a slow rule
must not hang a scan.

SEC-K8S-SECRET-001 once shipped a regex that took hours on a 40-item
list (exponential backtracking: a ReDoS), and custom rules from a scanned
repo's `rules_dir` are never reviewed. Two guards:

* every shipped regex is probed with crafted HCL-like input that grows to
  ~120 repetitions; each probe runs under a 0.25 s alarm, so a bad regex
  fails the test instead of hanging it;
* at scan time each pattern runs under `detect.PATTERN_TIME_BUDGET_S`;
  a timeout skips it, is reported, and fails `--fail-on`.

Both rely on SIGALRM, so they are skipped where it does not exist
(Windows); Python's `re` honours the signal mid-match.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import detect
import pytest

pytestmark = pytest.mark.skipif(
    not hasattr(signal, "setitimer"), reason="needs SIGALRM"
)

REPO = Path(__file__).resolve().parents[1]

# Units repeated to build probe input: HCL tokens, quoted and interpolated
# strings, separators — the shapes that make overlapping alternatives or
# nested quantifiers backtrack.
_ATOMS = [
    '"${a}"',
    '"a"',
    '"',
    "${a}",
    "a",
    "0",
    " ",
    "\n",
    ",",
    "=",
    "{",
    "}",
    "[",
    "]",
    "(",
    ")",
    "#",
    "//",
    "*",
    "-",
    ".",
    ":",
    "\\",
    "$",
    "\t",
]
_SEPS = ["", " ", ", ", "\n", " = "]
_REPEAT = 120
_LIMIT_S = 0.25


class _Slow(Exception):
    pass


def _raise_slow(signum, frame):
    raise _Slow()


def _prefixes(rx: str) -> list[str]:
    """`""` plus the pattern's leading words (e.g. `data`, `source`), so a
    probe gets past the anchor the regex starts with."""
    src = re.sub(r"\\[sSdDwWbB]", " ", rx)
    src = re.sub(r"\\(.)", r"\1", src)
    words = sorted(set(re.findall(r"[A-Za-z_][A-Za-z0-9_\-]{2,}", src)))[:4]
    return [""] + [f"{w} = {{\n  " for w in words] + [f"{w} " for w in words]


def _slow_probe(rx: str) -> tuple[str, str] | None:
    """The first (prefix, unit) whose probe exceeds `_LIMIT_S`, or None."""
    compiled = re.compile(rx)
    previous = signal.signal(signal.SIGALRM, _raise_slow)
    try:
        for prefix in _prefixes(rx):
            for atom in _ATOMS:
                for sep in _SEPS:
                    probe = prefix + (atom + sep) * _REPEAT + "\x00!"
                    signal.setitimer(signal.ITIMER_REAL, _LIMIT_S)
                    try:
                        compiled.search(probe)
                    except _Slow:
                        return prefix, atom + sep
                    finally:
                        signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        signal.signal(signal.SIGALRM, previous)
    return None


def _regexes(node, where: str):
    """Every regex in a pattern: values under a key containing `regex`, and
    `alternatives` lists, at any depth (suppress_if, escalation …)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str) and "regex" in key:
                yield f"{where}.{key}", value
            elif key == "alternatives" and isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        yield f"{where}.{key}[{i}]", item
            else:
                yield from _regexes(value, f"{where}.{key}")
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _regexes(item, f"{where}[{i}]")


CATALOGUE_REGEXES = [
    pytest.param(rx, id=f"{entry['id']}{where}")
    for entry in detect.load_catalog(REPO / "catalog")
    for where, rx in _regexes(
        {"patterns": entry.get("patterns"), "escalation": entry.get("escalation")}, ""
    )
]


def test_the_probe_catches_a_known_exponential_regex() -> None:
    # SEC-K8S-SECRET-001 before Round 56's fix: overlapping alternatives.
    old = r'(?ms)^\s*data\s*=\s*\{(?:[^}"]|"\$\{[^"]*"|"[^"]*"(?=\s*[=,)]))*?=\s*"(?!\$\{)'
    assert _slow_probe(old) is not None
    assert _slow_probe(r"(a+)+$") is not None


@pytest.mark.parametrize("rx", CATALOGUE_REGEXES)
def test_catalogue_regex_does_not_backtrack(rx: str) -> None:
    slow = _slow_probe(rx)
    assert slow is None, f"backtracks on {slow!r} x{_REPEAT}"


def test_a_slow_custom_rule_is_stopped_and_fails_the_gate(tmp_path) -> None:
    rules = tmp_path / ".tf-analyze-rules"
    rules.mkdir()
    (tmp_path / ".tf-analyze.yaml").write_text("rules_dir: .tf-analyze-rules/\n")
    (rules / "CUSTOM-SLOW-001.yaml").write_text(
        "id: CUSTOM-SLOW-001\n"
        'title: "Catastrophic backtracking"\n'
        "section: ops\n"
        "default_urgency: LOW\n"
        "blast_radius: single-resource\n"
        "status: active\n"
        "patterns:\n"
        "  - kind: grep\n"
        "    regex: '(a+)+$'\n"
        "recommendation: |\n"
        "  None.\n"
        "verification: |\n"
        "  None.\n"
        "fixtures: []\n"
    )
    (tmp_path / "main.tf").write_text('locals {\n  x = "' + "a" * 40 + '!"\n}\n')
    start = time.monotonic()
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "json",
            "--fail-on",
            "CRITICAL",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env={**os.environ, "TF_ANALYZE_PATTERN_TIMEOUT": "0.5"},
    )
    assert time.monotonic() - start < 30
    assert "CUSTOM-SLOW-001 exceeded" in proc.stderr, proc.stderr
    assert proc.returncode == 1, proc.stderr
    summary = json.loads(proc.stdout)["summary"]
    assert summary["rule_timeouts"][0]["rule"] == "CUSTOM-SLOW-001"


def test_a_handler_swallowing_exceptions_cannot_outrun_the_budget(monkeypatch) -> None:
    # Policy / IAM handlers wrap work in `except Exception: continue`; the
    # timeout must get through them, and the next slow call must still be
    # bounded rather than run with the alarm already spent.
    monkeypatch.setattr(detect, "PATTERN_TIME_BUDGET_S", 0.3)
    monkeypatch.setattr(detect, "RULE_TIMEOUTS", [])
    slow = re.compile(r"(a+)+$")

    def handler(_ctx):
        out = []
        for _ in range(3):
            try:
                slow.search("a" * 40 + "!")
            except Exception:  # noqa: BLE001 - the shape under test
                continue
            out.append({"id": "X"})
        return out

    start = time.monotonic()
    with detect._pattern_budget_scope() as enforced:
        assert enforced
        assert detect._call_with_budget(handler, None, "CUSTOM-X", "main.tf", enforced) == []
    assert time.monotonic() - start < 5
    assert detect.RULE_TIMEOUTS == [{"rule": "CUSTOM-X", "file": "main.tf"}]
