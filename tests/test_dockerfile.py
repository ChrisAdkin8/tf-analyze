"""Drift gates for ``Dockerfile``.

Round 31.7 closed a critical regression: the R30.13–R30.15 refactor
split ``detect.py`` into 24 ``_*.py`` sibling modules, but the
Dockerfile still ``COPY``-ied only ``scripts/detect.py``. The smoke
test inside the build (``RUN python3 detect.py --list-rules``) caught
this every time, so the docker workflow failed silently 20+ times in
a row without anyone noticing — no required-check gates the workflow.

These tests assert the COPY surface keeps including every sibling
module, so the same regression can't sneak back in even if the
docker workflow stays unmonitored.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"
SCRIPTS_DIR = REPO_ROOT / "scripts"


def test_dockerfile_copies_scripts_glob() -> None:
    """The COPY must use a glob (or list every sibling) so adding a
    new ``scripts/_foo.py`` import doesn't silently break the build
    weeks later when the import is exercised at runtime."""
    text = DOCKERFILE.read_text()
    # The straight-forward fix is `COPY scripts/*.py ./` — accept that
    # OR an explicit list that names every existing sibling module.
    if "COPY scripts/*.py" in text:
        return
    siblings = sorted(p.name for p in SCRIPTS_DIR.glob("_*.py"))
    missing = [s for s in siblings if f"scripts/{s}" not in text]
    assert not missing, (
        f"Dockerfile must copy every scripts/_*.py sibling module — "
        f"prefer `COPY scripts/*.py ./` (the R31.7 fix) over enumeration. "
        f"Currently missing: {missing}"
    )


def test_dockerfile_does_not_narrow_to_detect_only() -> None:
    """The pre-R31.7 form. If this comes back, the build will start
    failing again as soon as ``detect.py`` imports a new sibling."""
    text = DOCKERFILE.read_text()
    # Tolerate the line appearing inside a comment block (the fix
    # quotes the old form as part of the rationale).
    non_comment_lines = [
        ln for ln in text.splitlines()
        if not ln.lstrip().startswith("#")
    ]
    body = "\n".join(non_comment_lines)
    assert "COPY scripts/detect.py" not in body, (
        "Dockerfile reverted to copying only detect.py; sibling "
        "modules (_versions, _handlers_*, …) will be missing in the "
        "built image. Use `COPY scripts/*.py ./` instead."
    )


def test_smoke_test_step_still_present() -> None:
    """The build-time smoke test (``RUN python3 detect.py --list-rules``)
    is what surfaced the missing-modules bug. Without it, a broken
    image could publish and we'd only find out via user reports. Keep
    the gate."""
    text = DOCKERFILE.read_text()
    assert re.search(r"RUN python3 detect\.py --list-rules", text), (
        "Dockerfile must keep the in-build smoke test — it's the only "
        "gate that catches missing sibling modules before publish"
    )
