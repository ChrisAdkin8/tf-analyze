#!/usr/bin/env python3
"""Report on stub catalogue entries: how old they are and which are stale.

A stub is a catalogue YAML with `status: stub`. It usually means a rule
was sketched out but its detection pattern, recommendation text, or
fixture isn't finished yet. Stubs are excluded from normal scans, so a
forgotten stub causes silent under-coverage.

Usage:
  scripts/stub-status.py
  scripts/stub-status.py --age 90d        # only stubs older than 90 days
  scripts/stub-status.py --format json    # machine-readable

The age comes from `git log --diff-filter=A` on the file. If git history
is unavailable (shallow clone, file not yet committed), age is reported
as "uncommitted".

Exit codes: 0 = no stale stubs; 1 = at least one stub exceeds --age.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
SKILL_DIR = SCRIPT_DIR.parent
CATALOG_DIR = SKILL_DIR / "catalog"


def _load_yaml(path: Path) -> dict:
    """Reuse detect.py's micro-loader to avoid PyYAML dep."""
    sys.path.insert(0, str(SCRIPT_DIR))
    from detect import load_yaml  # type: ignore

    return load_yaml(path.read_text())


def _file_age_days(path: Path) -> int | None:
    """Return age in days from first git commit, or None if uncommitted."""
    try:
        result = subprocess.run(
            [
                "git", "log", "--diff-filter=A", "--follow",
                "--format=%cI", "--", str(path),
            ],
            cwd=str(SKILL_DIR),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    lines = [ln for ln in result.stdout.strip().splitlines() if ln]
    if not lines:
        return None
    # Last line is the oldest add. Format: 2026-04-15T10:30:00+00:00
    try:
        added = datetime.datetime.fromisoformat(lines[-1])
    except ValueError:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    return (now - added).days


def _parse_age(spec: str) -> int:
    """Accept '90d', '12w', '1y'. Return days."""
    m = re.match(r"^(\d+)([dwy])$", spec)
    if not m:
        raise argparse.ArgumentTypeError(
            f"--age expects N[d|w|y], got {spec!r}"
        )
    n, unit = int(m.group(1)), m.group(2)
    return {"d": n, "w": n * 7, "y": n * 365}[unit]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--age",
        type=_parse_age,
        default=0,
        help="Only show stubs at least N days/weeks/years old (e.g. 90d, 12w, 1y).",
    )
    ap.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
    )
    args = ap.parse_args()

    stubs: list[dict] = []
    for yml in sorted(CATALOG_DIR.glob("*.yaml")):
        try:
            data = _load_yaml(yml)
        except Exception as e:
            print(f"WARN: cannot parse {yml}: {e}", file=sys.stderr)
            continue
        if data.get("status") != "stub":
            continue
        age = _file_age_days(yml)
        stubs.append({
            "id": data.get("id") or yml.stem,
            "file": str(yml.relative_to(SKILL_DIR)),
            "title": data.get("title", ""),
            "section": data.get("section", "?"),
            "age_days": age,
            "fixtures": data.get("fixtures") or [],
        })

    threshold = args.age
    stale = [s for s in stubs if (s["age_days"] or 0) >= threshold]

    if args.format == "json":
        print(json.dumps({"stubs": stubs, "stale": stale}, indent=2))
        return 1 if stale else 0

    if not stubs:
        print("No stub entries in the catalogue. Nice.")
        return 0
    print(f"# {len(stubs)} stub entries total"
          + (f"; {len(stale)} older than {threshold}d" if threshold else "")
          + ".")
    print()
    print(f"{'ID':<32} {'AGE':<10} {'FIXTURES':<10} TITLE")
    print(f"{'-' * 32} {'-' * 10} {'-' * 10} {'-' * 30}")
    for s in sorted(stubs, key=lambda x: -(x["age_days"] or 0)):
        age = "uncommitted" if s["age_days"] is None else f"{s['age_days']}d"
        marker = "*" if (s["age_days"] or 0) >= threshold and threshold else " "
        fixtures = "yes" if s["fixtures"] else "no"
        print(f"{marker}{s['id']:<31} {age:<10} {fixtures:<10} {s['title']}")
    if threshold:
        print()
        print("* = exceeds --age threshold")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
