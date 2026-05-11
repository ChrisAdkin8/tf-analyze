"""Git-diff / base-branch helpers for the ``--mode diff`` flow.

Three thin wrappers around ``git`` extracted from ``detect.py`` as the
**eleventh modularisation seam**. All three run ``git`` via
``subprocess`` and tolerate it being missing — when ``git`` isn't
available, ``get_diff_files`` returns an empty set so the caller can
gracefully fall back to a full scan.

Functions are named without the leading underscore (this module is
the canonical home now); detect.py re-exports them as their old
private names so existing call sites keep working without churn.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def auto_detect_base_branch(target: Path) -> str:
    """Return 'main' or 'master' depending on which the repo uses, else 'main'."""
    for branch in ("main", "master"):
        result = subprocess.run(
            ["git", "rev-parse", "--verify", branch],
            capture_output=True, cwd=str(target),
        )
        if result.returncode == 0:
            return branch
    return "main"


def find_latest_prior(reports_dir: Path, suffix: str = ".md") -> Path | None:
    """Most-recent ``tf-analysis-YYYY-MM-DD<suffix>`` under ``reports_dir``."""
    if not reports_dir.is_dir():
        return None
    candidates = sorted(
        reports_dir.glob(f"tf-analysis-*{suffix}"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def get_diff_files(target: Path, diff_base: str) -> set[Path]:
    """Set of ``.tf`` files changed between ``diff_base`` and HEAD.

    Three sources are unioned:

    * ``git diff --name-only <base>...HEAD`` (the canonical three-dot
      diff, falls back to two-dot if the merge-base lookup fails).
    * ``git ls-files --others --exclude-standard`` for untracked files.
    * Every result is resolved against the repo's git root so the
      caller gets absolute paths that survive any later ``chdir``.

    Returns an empty set when git is not on ``PATH`` (operator probably
    invoked the engine outside a git workspace; caller can decide
    whether to fall back to a full scan or bail).
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{diff_base}...HEAD", "--", "*.tf"],
            capture_output=True,
            text=True,
            cwd=str(target),
        )
        if result.returncode != 0:
            # Fall back to diff against working tree
            result = subprocess.run(
                ["git", "diff", "--name-only", diff_base, "--", "*.tf"],
                capture_output=True,
                text=True,
                cwd=str(target),
            )
        # Also include untracked .tf files
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard", "--", "*.tf"],
            capture_output=True,
            text=True,
            cwd=str(target),
        )

        files: set[Path] = set()
        git_root_result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, cwd=str(target),
        )
        git_root = Path(git_root_result.stdout.strip()) if git_root_result.returncode == 0 else target

        for line in result.stdout.strip().splitlines():
            if line:
                fp = (git_root / line).resolve()
                if fp.exists():
                    files.add(fp)
        for line in (untracked.stdout or "").strip().splitlines():
            if line:
                fp = (git_root / line).resolve()
                if fp.exists():
                    files.add(fp)
        return files
    except FileNotFoundError:
        print("WARN: git not found, falling back to full scan", file=sys.stderr)
        return set()
