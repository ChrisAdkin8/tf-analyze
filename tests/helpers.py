"""Shared test helpers for the tf-analyze test suite."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = REPO_ROOT / "fixtures"
CATALOG_DIR = REPO_ROOT / "catalog"
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))


def run_detect(target: Path, *, all_rules: bool = False, fixture_name: str = "") -> list[dict]:
    # Always include INFO-tier findings in test runs so the assertion
    # surface matches the catalogue's `fixtures:` declarations regardless
    # of the rule's tier. The filter that --show-info disables is a
    # display concern, not a correctness one.
    args = [sys.executable, str(DETECT_PY), "--target", str(target), "--format", "json", "--show-info"]
    if not all_rules and fixture_name:
        args += ["--only-fixture", fixture_name]
    result = subprocess.run(args, capture_output=True, text=True)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return data
    return data.get("findings", [])


def fixture_cases() -> list[tuple[str, set[str]]]:
    """Return (fixture_name, expected_ids) pairs for all non-clean positive fixtures."""
    from detect import load_yaml  # type: ignore

    fixture_dirs = sorted(
        p for p in FIXTURES_DIR.iterdir()
        if p.is_dir() and not p.name.endswith("_clean")
    )
    expected_map: dict[str, set[str]] = {}
    for yml in sorted(CATALOG_DIR.glob("*.yaml")):
        try:
            data = load_yaml(yml.read_text())
        except Exception:
            continue
        if data.get("status") == "deprecated":
            continue
        for fx in data.get("fixtures") or []:
            expected_map.setdefault(fx, set()).add(data["id"])

    return [
        (fx_dir.name, expected_map[fx_dir.name])
        for fx_dir in fixture_dirs
        if fx_dir.name in expected_map
    ]


def clean_fixture_cases() -> list[str]:
    """Return rule IDs for which a *_clean fixture exists."""
    return [
        p.name.removesuffix("_clean")
        for p in sorted(FIXTURES_DIR.glob("*_clean"))
        if p.is_dir()
    ]
