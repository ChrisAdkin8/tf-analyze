#!/usr/bin/env python3
"""Changelog fragments: one file per change, assembled into CHANGELOG.md.

Every PR used to add its `## Round N` section at the top of CHANGELOG.md,
so any two open PRs edited the same lines and conflicted, and two PRs
open at once both claimed the same round number. Now a PR adds its own
file under `changelog.d/` and leaves CHANGELOG.md alone. `build` gives
each fragment the next round number, in the order the fragments reached
the branch, and moves them into CHANGELOG.md.

A fragment is `changelog.d/<anything>.md`:

    ## A character reference can't undo PR-comment escaping

    - **`&` is escaped**: ...

The heading is the title only: `build` adds `Round N — ` and ` — DATE`.

Usage:
  scripts/changelog.py check                 # fragments are well formed
  scripts/changelog.py check --base origin/main
                                             # ...and this branch adds one
                                             # and doesn't edit CHANGELOG.md
  scripts/changelog.py build                 # assemble into CHANGELOG.md
  scripts/changelog.py pending               # exit 1 if any are unbuilt

Exit codes: 0 ok, 1 a check failed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
FRAGMENT_DIR = REPO_ROOT / "changelog.d"
# changelog.d/README.md explains the folder; it is not a fragment.
NOT_FRAGMENTS = {"README.md"}

_ROUND_RE = re.compile(r"^## Round (\d+)\b", re.MULTILINE)
# A title that already carries a round or a date was copied from an old
# entry; `build` would print them twice.
_TITLE_ROUND_RE = re.compile(r"^Round\s+\d+", re.IGNORECASE)
_TITLE_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


@dataclass
class Fragment:
    path: Path
    title: str
    body: str


def fragment_paths(fragment_dir: Path = FRAGMENT_DIR) -> list[Path]:
    if not fragment_dir.is_dir():
        return []
    return sorted(p for p in fragment_dir.glob("*.md") if p.name not in NOT_FRAGMENTS)


def parse_fragment(path: Path) -> tuple[Fragment | None, list[str]]:
    """Return the fragment, or None and the reasons it is malformed."""
    text = path.read_text(encoding="utf-8")
    lines = text.strip("\n").splitlines()
    errors: list[str] = []
    if not lines or not lines[0].startswith("## "):
        errors.append("first line must be a `## Title` heading")
        return None, errors
    title = lines[0][3:].strip()
    body = "\n".join(lines[1:]).strip("\n")
    if not title:
        errors.append("the heading has no title")
    if _TITLE_ROUND_RE.match(title):
        errors.append("leave `Round N` out of the title; `build` adds it")
    if _TITLE_DATE_RE.search(title):
        errors.append("leave the date out of the title; `build` adds it")
    if not body:
        errors.append("there is no text under the heading")
    if re.search(r"^#{1,2} ", body, re.MULTILINE):
        errors.append("use `###` or lower inside a fragment; `##` starts a new entry")
    if errors:
        return None, errors
    return Fragment(path, title, body), []


def _git(*args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _added_at(path: Path) -> tuple[int, str]:
    """When the fragment first reached this branch: (unix time, YYYY-MM-DD).

    Rounds are numbered in that order. A fragment not committed yet sorts
    last and takes today's date.
    """
    out = _git("log", "--diff-filter=A", "--format=%ct %cs", "--", str(path))
    if out:
        stamp, day = out.splitlines()[-1].split()
        return int(stamp), day
    return sys.maxsize, dt.date.today().isoformat()


def build(
    changelog: Path = CHANGELOG,
    fragment_dir: Path = FRAGMENT_DIR,
    date: str | None = None,
) -> list[str]:
    """Move every fragment into `changelog`. Return the new headings."""
    fragments = []
    for path in fragment_paths(fragment_dir):
        frag, errors = parse_fragment(path)
        if errors:
            raise SystemExit(f"changelog: {path.name}: " + "; ".join(errors))
        stamp, day = _added_at(path)
        fragments.append((stamp, path.name, date or day, frag))
    if not fragments:
        return []
    fragments.sort(key=lambda f: (f[0], f[1]))

    text = changelog.read_text(encoding="utf-8")
    head, sep, rest = text.partition("\n---\n")
    if not sep:
        raise SystemExit(f"changelog: no `---` divider in {changelog.name}")
    last = max((int(n) for n in _ROUND_RE.findall(text)), default=0)

    entries = []
    for offset, (_, _, day, frag) in enumerate(fragments, start=1):
        heading = f"## Round {last + offset} — {frag.title} — {day}"
        entries.append(f"{heading}\n\n{frag.body}\n")
    entries.reverse()  # newest round at the top

    changelog.write_text(
        head + sep + "\n" + "\n".join(entries) + "\n" + rest.lstrip("\n"),
        encoding="utf-8",
    )
    for _, _, _, frag in fragments:
        frag.path.unlink()
    return [e.splitlines()[0] for e in entries]


def check_fragments(fragment_dir: Path = FRAGMENT_DIR) -> list[str]:
    errors = []
    for path in fragment_paths(fragment_dir):
        for err in parse_fragment(path)[1]:
            errors.append(f"{path.relative_to(REPO_ROOT)}: {err}")
    return errors


def check_branch(base: str) -> list[str]:
    """This branch adds (or edits) a fragment and leaves CHANGELOG.md to `build`."""
    # `-z`: without it git quotes a non-ASCII name, which then isn't seen
    # as a fragment. Fields are NUL-separated: status, path, status, path.
    out = _git("-c", "core.quotepath=off", "diff", "--name-status", "--no-renames",
               "-z", f"{base}...HEAD")
    if not out and not _git("rev-parse", "--verify", base):
        return [f"can't diff against `{base}` (fetch it, or use fetch-depth: 0)"]
    touched: dict[str, str] = {}
    fields = out.split("\0")
    for status, name in zip(fields[::2], fields[1::2]):
        touched[name] = status[:1]
    frag_changes = {
        name: st
        for name, st in touched.items()
        if name.startswith("changelog.d/")
        and name.endswith(".md")
        and Path(name).name not in NOT_FRAGMENTS
    }
    is_build = any(st == "D" for st in frag_changes.values())
    if "CHANGELOG.md" in touched and not is_build:
        return [
            "CHANGELOG.md was edited directly. Put the entry in "
            "changelog.d/<branch-name>.md instead; `scripts/changelog.py build` "
            "moves it into CHANGELOG.md later."
        ]
    if not frag_changes:
        return [
            "no changelog fragment. Add changelog.d/<branch-name>.md "
            "(see changelog.d/README.md), or label the PR `no-changelog` "
            "if users won't notice the change."
        ]
    return []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_check = sub.add_parser("check", help="validate fragments")
    p_check.add_argument("--base", help="also check this branch's diff against BASE")
    p_build = sub.add_parser("build", help="assemble fragments into CHANGELOG.md")
    p_build.add_argument("--date", help="use this date (YYYY-MM-DD) for every entry")
    sub.add_parser("pending", help="exit 1 if any fragments are unbuilt")
    args = ap.parse_args(argv)

    if args.cmd == "build":
        headings = build(date=args.date)
        if not headings:
            print("changelog: no fragments to build")
        for h in headings:
            print(f"changelog: added {h}")
        return 0

    if args.cmd == "pending":
        names = [p.name for p in fragment_paths()]
        for name in names:
            print(f"changelog: unbuilt fragment changelog.d/{name}")
        if names:
            print(
                "changelog: run `python3 scripts/changelog.py build` and merge that first"
            )
        return 1 if names else 0

    errors = check_fragments()
    if args.base:
        errors += check_branch(args.base)
    for err in errors:
        print(f"changelog: {err}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
