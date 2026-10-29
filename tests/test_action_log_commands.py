"""Engine output printed to an Actions log can't run workflow commands.

The engine's stderr names repo files, and a PR controls those names. A path
holding a newline could start a log line with `::error::`, `::add-mask::` or
`::stop-commands::` and forge annotations or hide later output. The action
prints that output between `::stop-commands::<token>` and `::<token>::`, with
a random token. These tests run the real loop from action.yml.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).parent.parent
ACTION = yaml.safe_load((REPO_ROOT / "action.yml").read_text())
BOT = (REPO_ROOT / "integrations" / "github-action-bot.yml").read_text()

FORGED = "WARN: cannot parse a\n::error file=main.tf::all checks passed\n::add-mask::x\n::stop-commands::abc\n"


def _print_loop() -> str:
    script = next(
        s["run"]
        for s in ACTION["runs"]["steps"]
        if "tf-analyze-json-stderr.txt" in s.get("run", "")
    )
    start = script.index('LOG_TOKEN="')
    end = script.index("done\n", start) + len("done\n")
    return script[start:end]


def _run(tmp_path: Path) -> list[str]:
    (tmp_path / "tf-analyze-json-stderr.txt").write_text(FORGED)
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", _print_loop()],
        cwd=tmp_path,
        env={"OUT": str(tmp_path), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.splitlines()


def test_engine_stderr_is_printed_with_commands_stopped(tmp_path: Path) -> None:
    lines = _run(tmp_path)
    stop = next(
        i for i, ln in enumerate(lines) if ln.startswith("::stop-commands::tfa-")
    )
    token = lines[stop].split("::stop-commands::", 1)[1]
    resume = lines.index(f"::{token}::")
    # Every forged line sits between the stop and the resume.
    for forged in FORGED.splitlines():
        assert stop < lines.index(forged) < resume
    assert (
        lines[0] == "::group::tf-analyze-json-stderr.txt"
        and lines[-1] == "::endgroup::"
    )


def test_the_token_is_random(tmp_path: Path) -> None:
    tokens = set()
    for i in range(3):
        d = tmp_path / str(i)
        d.mkdir()
        stop = next(ln for ln in _run(d) if ln.startswith("::stop-commands::"))
        tokens.add(stop.split("::stop-commands::", 1)[1])
    assert len(tokens) == 3
    assert all(re.fullmatch(r"tfa-[0-9a-f]{32}", t) for t in tokens)


def test_every_raw_cat_in_action_and_bot_is_wrapped() -> None:
    action_text = (REPO_ROOT / "action.yml").read_text()
    for text in (action_text, BOT):
        lines = text.splitlines()
        for i, ln in enumerate(lines):
            if re.match(r"\s*cat \S+\s*$", ln):
                assert "::stop-commands::" in lines[i - 1], ln
                assert re.search(r"::\$\{LOG_TOKEN\}::", lines[i + 1]), ln
