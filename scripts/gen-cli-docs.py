#!/usr/bin/env python3
"""Generate docs/cli.md from detect.py's argparse definition.

Run after editing argparse in detect.py to keep the doc in sync. The
output file is human-readable markdown — list of every flag with help
text, default, and choices, grouped roughly by purpose.

Usage:
  scripts/gen-cli-docs.py                   # writes docs/cli.md
  scripts/gen-cli-docs.py --check           # exit 1 if doc would change
  scripts/gen-cli-docs.py --stdout          # print to stdout instead of writing
"""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path
import importlib.util

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
DETECT_PY = SCRIPT_DIR / "detect.py"
DOCS_DIR = SKILL_DIR / "docs"
OUT_PATH = DOCS_DIR / "cli.md"


def _load_argparse() -> argparse.ArgumentParser:
    """Import detect.py and walk its main() to extract the ArgumentParser.

    We don't want to actually run main(), so we monkey-patch parse_args
    to capture the parser the moment it's complete and stop execution.
    """
    spec = importlib.util.spec_from_file_location("detect", DETECT_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore

    captured: dict = {}

    class _Capture(Exception):
        pass

    original_parse = argparse.ArgumentParser.parse_args

    def fake_parse(self, *_a, **_kw):
        captured["parser"] = self
        raise _Capture()

    argparse.ArgumentParser.parse_args = fake_parse  # type: ignore
    try:
        try:
            mod.main()
        except _Capture:
            pass
        except SystemExit:
            pass
    finally:
        argparse.ArgumentParser.parse_args = original_parse  # type: ignore
    return captured["parser"]


# Group flags by intent. The ordering inside each group matches argparse
# declaration order so it's easy to keep mental model in sync.
# Tuples (not sets) — set iteration order is unstable across Python
# runs and would make the generator non-deterministic, breaking --check.
_GROUPS = [
    ("Scan target", ("--target", "--catalog")),
    ("Output", ("--format", "--reports-dir")),
    ("Mode", ("--mode", "--prior-report", "--diff-base", "--plan-json")),
    ("Filtering", ("--only-fixture", "--include-stubs", "--strict-catalog", "--focus")),
    ("Suppression", ("--no-suppress",)),
    ("Comparison & gating", ("--compare", "--auto-compare", "--fail-on")),
    ("Auto-stub", ("--auto-stub", "--propose-stub")),
    ("Optional fast-path", ("--use-hcl2",)),
    ("Meta-commands", ("--list-rules", "--explain", "--new-rule")),
]


def _render_md(parser: argparse.ArgumentParser) -> str:
    actions = [a for a in parser._actions if a.option_strings]
    by_flag: dict[str, argparse.Action] = {}
    for a in actions:
        for opt in a.option_strings:
            by_flag[opt] = a

    out = io.StringIO()
    out.write("# `detect.py` CLI reference\n\n")
    out.write(
        "**Auto-generated** by `scripts/gen-cli-docs.py` from "
        "`scripts/detect.py`'s argparse. Do not edit by hand — re-run "
        "the generator after changing flags.\n\n"
    )
    seen: set[str] = set()
    for group_name, flag_set in _GROUPS:
        rows = []
        for flag in flag_set:
            if flag not in by_flag or flag in seen:
                continue
            a = by_flag[flag]
            seen.add(flag)
            for f in a.option_strings:
                seen.add(f)
            rows.append((flag, a))
        if not rows:
            continue
        out.write(f"## {group_name}\n\n")
        for flag, a in rows:
            opts = "/".join(a.option_strings)
            metavar = a.metavar or (a.dest.upper() if not isinstance(
                a, (argparse._StoreTrueAction, argparse._StoreFalseAction,
                    argparse._HelpAction)
            ) else "")
            head = f"### `{opts}"
            if metavar and not isinstance(
                a, (argparse._StoreTrueAction, argparse._StoreFalseAction,
                    argparse._HelpAction),
            ):
                head += f" {metavar}"
            head += "`\n\n"
            out.write(head)
            if a.choices:
                out.write(f"**Choices:** `{'`, `'.join(str(c) for c in a.choices)}`\n\n")
            if a.default not in (None, False):
                # Normalize the catalog default so the doc isn't pinned
                # to whoever generated it ("/Users/chris/..." -> "<skill>/catalog").
                default_str = str(a.default)
                skill_str = str(SKILL_DIR)
                if default_str.startswith(skill_str):
                    default_str = (
                        "<skill>" + default_str[len(skill_str):]
                    )
                out.write(f"**Default:** `{default_str}`\n\n")
            help_text = (a.help or "").strip().replace("\n", " ")
            if help_text:
                out.write(help_text + "\n\n")
        out.write("\n")

    # Anything we didn't bucket — just dump under "Other"
    other = [
        (f, by_flag[f]) for f in by_flag
        if f not in seen and f != "-h"
    ]
    if other:
        out.write("## Other\n\n")
        for flag, a in other:
            out.write(f"### `{'/'.join(a.option_strings)}`\n\n")
            help_text = (a.help or "").strip().replace("\n", " ")
            if help_text:
                out.write(help_text + "\n\n")
    return out.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if docs/cli.md would change.")
    ap.add_argument("--stdout", action="store_true",
                    help="Write to stdout instead of disk.")
    args = ap.parse_args()

    parser = _load_argparse()
    rendered = _render_md(parser)

    if args.stdout:
        sys.stdout.write(rendered)
        return 0
    DOCS_DIR.mkdir(exist_ok=True)
    if args.check:
        if not OUT_PATH.exists():
            print("docs/cli.md is missing — run gen-cli-docs.py", file=sys.stderr)
            return 1
        existing = OUT_PATH.read_text()
        if existing != rendered:
            print(
                "docs/cli.md is stale; re-run gen-cli-docs.py and commit.",
                file=sys.stderr,
            )
            return 1
        return 0
    OUT_PATH.write_text(rendered)
    print(f"# wrote {OUT_PATH.relative_to(SKILL_DIR)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
