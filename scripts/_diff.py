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

# Round-5 audit fix #3 — every git subprocess call now carries a
# 30-second wall-clock cap. A hung git (corrupted repo, NFS stall, lock
# file held by another process, network drive freeze) used to leave
# the engine waiting forever. 30 s is generous for any realistic git
# command on a real workspace (sub-second in practice) and short
# enough that a freeze surfaces quickly with a clear stderr WARN
# instead of an indefinite hang.
_GIT_TIMEOUT_SEC = 30


def _run_git(argv: list[str], target: Path, *, text: bool = False) -> subprocess.CompletedProcess | None:
    """Run a git subprocess with a timeout. Returns None on hang.

    Centralises the timeout + WARN-on-hang discipline so the four
    call sites below share one error path. Callers that need the
    `text=True` shape pass it through.
    """
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=text,
            cwd=str(target),
            timeout=_GIT_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        sys.stderr.write(
            f"WARN: git command exceeded {_GIT_TIMEOUT_SEC}s and was killed: "
            f"{' '.join(argv)}\n"
        )
        return None


def auto_detect_base_branch(target: Path) -> str:
    """Return 'main' or 'master' depending on which the repo uses, else 'main'.

    Round-5 audit fix #17 — additionally surface a stderr WARN when
    every probed branch fails (typical cause: not in a git repo, or
    git is missing). Previously the function silently returned the
    default `"main"`, so the operator running `--mode diff` outside a
    git workspace saw "no findings" instead of a clear signal.
    """
    failures: list[str] = []
    for branch in ("main", "master"):
        result = _run_git(["git", "rev-parse", "--verify", branch], target)
        if result is None:
            continue
        if result.returncode == 0:
            return branch
        # Record the stderr for the final WARN if every probe failed.
        failures.append((result.stderr or b"").decode("utf-8", "replace").strip())
    if failures:
        sys.stderr.write(
            "WARN: git rev-parse failed for all probed base branches "
            f"(main, master): {failures[0] or '(empty stderr)'}\n"
        )
    return "main"


def find_latest_prior(reports_dir: Path, suffix: str = ".md") -> Path | None:
    """Most-recent ``tf-analysis-YYYY-MM-DD<suffix>`` under ``reports_dir``."""
    if not reports_dir.is_dir():
        return None
    # Audit item 8 — `glob()` returns a snapshot but `stat()` is called
    # later; a concurrent unlink between the two raises
    # `FileNotFoundError`. Tolerate it by skipping the missing entry
    # instead of crashing the whole scan.
    def _mtime_safe(p: Path) -> float:
        try:
            return p.stat().st_mtime
        except OSError:
            return -1.0
    candidates = sorted(
        (p for p in reports_dir.glob(f"tf-analysis-*{suffix}") if _mtime_safe(p) >= 0),
        key=_mtime_safe,
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
        # All git calls below go through `_run_git`, which applies the
        # 30-second timeout. A None return means the call hung past
        # the cap — degrade gracefully (empty diff → full scan).
        result = _run_git(
            ["git", "diff", "--name-only", f"{diff_base}...HEAD", "--", "*.tf"],
            target, text=True,
        )
        if result is None:
            return set()
        if result.returncode != 0:
            # Fall back to diff against working tree
            result = _run_git(
                ["git", "diff", "--name-only", diff_base, "--", "*.tf"],
                target, text=True,
            )
            if result is None:
                return set()
        # Also include untracked .tf files
        untracked = _run_git(
            ["git", "ls-files", "--others", "--exclude-standard", "--", "*.tf"],
            target, text=True,
        )
        if untracked is None:
            untracked_stdout = ""
        else:
            untracked_stdout = untracked.stdout or ""

        files: set[Path] = set()
        git_root_result = _run_git(
            ["git", "rev-parse", "--show-toplevel"],
            target, text=True,
        )
        if git_root_result is None or git_root_result.returncode != 0:
            git_root = target
        else:
            git_root = Path(git_root_result.stdout.strip())

        for line in (result.stdout or "").strip().splitlines():
            if line:
                fp = (git_root / line).resolve()
                if fp.exists():
                    files.add(fp)
        for line in untracked_stdout.strip().splitlines():
            if line:
                fp = (git_root / line).resolve()
                if fp.exists():
                    files.add(fp)
        return files
    except FileNotFoundError:
        print("WARN: git not found, falling back to full scan", file=sys.stderr)
        return set()
