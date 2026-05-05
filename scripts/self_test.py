#!/usr/bin/env python3
"""Run detect.py against every fixture and assert expected catalogue IDs.

Each fixture is a directory under `fixtures/`. The expected IDs for a fixture
are derived from the catalogue itself: any catalogue entry whose `fixtures:`
list contains the fixture name is expected to fire on that fixture.

Exit code 0 = all fixtures pass. Exit code 1 = at least one mismatch.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
SKILL_DIR = SCRIPT_DIR.parent
FIXTURES_DIR = SKILL_DIR / "fixtures"
CATALOG_DIR = SKILL_DIR / "catalog"
DETECT_PY = SCRIPT_DIR / "detect.py"


def load_yaml_minimal(path: Path) -> dict:
    """Tiny loader: we only need `id` and `fixtures` from each catalogue file."""
    sys.path.insert(0, str(SCRIPT_DIR))
    from detect import load_yaml  # type: ignore
    return load_yaml(path.read_text())


def expected_ids_for_fixture(fixture_name: str) -> set[str]:
    expected = set()
    for yml in sorted(CATALOG_DIR.glob("*.yaml")):
        try:
            data = load_yaml_minimal(yml)
        except Exception as e:
            print(f"WARN: cannot parse {yml}: {e}", file=sys.stderr)
            continue
        if data.get("status") == "deprecated":
            continue
        fixtures = data.get("fixtures") or []
        if fixture_name in fixtures:
            expected.add(data["id"])
    return expected


def run_detect(fixture_dir: Path, fixture_name: str, all_rules: bool = False) -> set[str]:
    args = [
        sys.executable,
        str(DETECT_PY),
        "--target",
        str(fixture_dir),
        "--format",
        "json",
    ]
    if not all_rules:
        args.extend(["--only-fixture", fixture_name])
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  detect.py failed: {result.stderr}", file=sys.stderr)
        return set()
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"  invalid JSON from detect.py", file=sys.stderr)
        return set()
    # Handle both old list format and new dict format
    if isinstance(data, list):
        findings = data
    else:
        findings = data.get("findings", [])
    return {f["id"] for f in findings}


def is_zero_finding_fixture(fixture_dir: Path) -> bool:
    """Check if a fixture declares it expects zero findings."""
    main_tf = fixture_dir / "main.tf"
    if not main_tf.exists():
        return False
    content = main_tf.read_text()
    return "# Expected findings: NONE" in content


def catalog_entries_without_fixtures() -> list[str]:
    """Return catalogue IDs that declare no `fixtures:` — gaps in coverage."""
    missing = []
    for yml in sorted(CATALOG_DIR.glob("*.yaml")):
        try:
            data = load_yaml_minimal(yml)
        except Exception:
            continue
        if data.get("status") in ("deprecated", "stub"):
            continue
        if not (data.get("fixtures") or []):
            missing.append(data.get("id") or yml.stem)
    return missing


def main() -> int:
    fixtures = sorted(p for p in FIXTURES_DIR.iterdir() if p.is_dir())
    if not fixtures:
        print(f"ERROR: no fixtures in {FIXTURES_DIR}", file=sys.stderr)
        return 2

    failures = 0
    for fixture in fixtures:
        name = fixture.name
        expected = expected_ids_for_fixture(name)
        zero_expected = is_zero_finding_fixture(fixture)
        if not expected and not zero_expected:
            print(f"SKIP {name}: no catalogue entries reference this fixture")
            continue
        # For zero-finding fixtures, always run the full catalogue. We need
        # to verify that NO catalogue rule fires — restricting to fixtures
        # listed in `fixtures:` would defeat the test (and errors when a
        # fixture like clean_baseline has no catalogue references at all).
        guards = _parse_guards(fixture / "main.tf") if zero_expected else set()
        actual = run_detect(fixture, name, all_rules=zero_expected)
        if zero_expected:
            if guards:
                unexpected = {f for f in actual if f in guards}
                if not unexpected:
                    print(f"PASS {name}: guards {sorted(guards)} held (negative test)")
                else:
                    failures += 1
                    print(f"FAIL {name}: guarded IDs fired")
                    print(f"  unexpected: {sorted(unexpected)}")
            else:
                if not actual:
                    print(f"PASS {name}: zero findings (negative test)")
                else:
                    failures += 1
                    print(f"FAIL {name}: expected zero findings")
                    print(f"  unexpected: {sorted(actual)}")
            continue
        missing = expected - actual
        unexpected = actual - expected
        if not missing and not unexpected:
            print(f"PASS {name}: {sorted(expected)}")
        else:
            failures += 1
            print(f"FAIL {name}:")
            if missing:
                print(f"  missing:    {sorted(missing)}")
            if unexpected:
                print(f"  unexpected: {sorted(unexpected)}")

    # Symmetry check: catalogue entries without any fixture are coverage gaps
    uncovered = catalog_entries_without_fixtures()
    if uncovered:
        print()
        print(f"WARN: {len(uncovered)} catalogue entries have no fixtures:")
        for cid in uncovered:
            print(f"  - {cid}")

    print()
    print(f"Result: {len(fixtures) - failures}/{len(fixtures)} fixtures passed")
    return 0 if failures == 0 else 1


def _parse_guards(main_tf: Path) -> set[str]:
    """Parse `# Guards against: ID1, ID2` from a negative fixture."""
    if not main_tf.exists():
        return set()
    for line in main_tf.read_text().splitlines():
        s = line.strip().lstrip("#").strip()
        if s.lower().startswith("guards against:"):
            rest = s.split(":", 1)[1]
            return {p.strip() for p in rest.split(",") if p.strip()}
    return set()


if __name__ == "__main__":
    sys.exit(main())
