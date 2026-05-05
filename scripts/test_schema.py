#!/usr/bin/env python3
"""Self-test for the catalogue YAML schema validator.

Constructs synthetic broken catalogue entries in a tempdir, runs
`validate_catalog_entry`, and asserts the right errors fire. Also
exercises `load_catalog` end-to-end with a mix of good and bad files
to confirm the loader prints ERROR lines, skips bad entries, and
returns the good ones.

Exit code 0 = all pass. Exit code 1 = at least one expectation missed.

This is the regression test for the loud-validation contract from
T1.1 — without it, a regression that quietly relaxes the validator
would only show up when a real-world catalogue file goes malformed.
"""

from __future__ import annotations

import io
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))
from detect import (  # type: ignore
    load_catalog,
    validate_catalog_entry,
)


_GOOD_ENTRY = """\
id: SEC-DEMO-001
title: "Demo good entry"
section: security
default_urgency: HIGH
blast_radius: module
status: active
patterns:
  - kind: grep
    regex: "TODO"
recommendation: |
  TODO
verification: |
  TODO
"""

_CASES: list[tuple[str, str, list[str]]] = [
    # (filename, contents, list of error fragments expected in output)
    (
        "SEC-MISSING-FIELD-001.yaml",
        # Missing recommendation + verification.
        """\
id: SEC-MISSING-FIELD-001
title: "Missing recommendation/verification"
section: security
default_urgency: HIGH
blast_radius: module
status: active
patterns:
  - kind: grep
    regex: "TODO"
""",
        ["missing required field 'recommendation'",
         "missing required field 'verification'"],
    ),
    (
        "SEC-BAD-URGENCY-001.yaml",
        """\
id: SEC-BAD-URGENCY-001
title: "Bad urgency enum"
section: security
default_urgency: WHATEVER
blast_radius: module
patterns:
  - kind: grep
    regex: "TODO"
recommendation: TODO
verification: TODO
""",
        ["default_urgency 'WHATEVER' not in"],
    ),
    (
        "SEC-BAD-SECTION-001.yaml",
        """\
id: SEC-BAD-SECTION-001
title: "Bad section enum"
section: cybersecurity
default_urgency: HIGH
blast_radius: module
patterns:
  - kind: grep
    regex: "TODO"
recommendation: TODO
verification: TODO
""",
        ["section 'cybersecurity' not in"],
    ),
    (
        "SEC-MISMATCH-NAME-001.yaml",
        # id field doesn't match filename stem.
        """\
id: SEC-OTHER-002
title: "id != filename"
section: security
default_urgency: HIGH
blast_radius: module
patterns:
  - kind: grep
    regex: "TODO"
recommendation: TODO
verification: TODO
""",
        ["does not match filename stem"],
    ),
    (
        "SEC-EMPTY-PATTERNS-001.yaml",
        """\
id: SEC-EMPTY-PATTERNS-001
title: "Empty patterns list"
section: security
default_urgency: HIGH
blast_radius: module
patterns: []
recommendation: TODO
verification: TODO
""",
        # The minimal YAML loader parses inline `[]` as the literal
        # string "[]", which the validator catches as a type error.
        # Either error is acceptable — what matters is the validator
        # rejected the entry.
        ["'patterns'"],
    ),
    (
        "SEC-PATTERN-NO-KIND-001.yaml",
        """\
id: SEC-PATTERN-NO-KIND-001
title: "Pattern missing kind"
section: security
default_urgency: HIGH
blast_radius: module
patterns:
  - description: TODO
recommendation: TODO
verification: TODO
""",
        ["patterns[0] missing 'kind'"],
    ),
]


def test_validate_function() -> int:
    """Direct unit test of validate_catalog_entry."""
    failures = 0
    for fname, body, expected_errs in _CASES:
        from detect import load_yaml  # type: ignore
        try:
            data = load_yaml(body)
        except Exception as e:
            print(f"FAIL {fname}: yaml parse failed: {e}")
            failures += 1
            continue
        errs = validate_catalog_entry(data, fname)
        for needle in expected_errs:
            if not any(needle in e for e in errs):
                print(f"FAIL {fname}: expected error containing {needle!r}")
                print(f"       actual errors: {errs}")
                failures += 1
                break
        else:
            print(f"PASS {fname}")
    return failures


def test_load_catalog_end_to_end() -> int:
    """Mix good + bad entries in a tempdir, verify load_catalog skips
    the bad ones, prints ERROR lines, and returns the good ones."""
    with tempfile.TemporaryDirectory() as td:
        tdpath = Path(td)
        (tdpath / "SEC-DEMO-001.yaml").write_text(_GOOD_ENTRY)
        for fname, body, _ in _CASES:
            (tdpath / fname).write_text(body)
        captured = io.StringIO()
        with redirect_stderr(captured):
            entries = load_catalog(tdpath, include_stubs=False)
        ids = [e["id"] for e in entries]
        if ids != ["SEC-DEMO-001"]:
            print(
                f"FAIL load_catalog: expected only SEC-DEMO-001 "
                f"to load, got {ids}"
            )
            return 1
        stderr = captured.getvalue()
        if "ERROR:" not in stderr:
            print("FAIL load_catalog: expected ERROR: lines on stderr")
            return 1
        print(f"PASS load_catalog: loaded {len(entries)} good, "
              f"emitted {stderr.count('ERROR:')} ERROR lines for bad files")
        # Strict mode should sys.exit(2) — capture and verify.
        try:
            with redirect_stderr(io.StringIO()):
                load_catalog(tdpath, include_stubs=False, strict=True)
        except SystemExit as e:
            if e.code == 2:
                print("PASS load_catalog --strict: exited with code 2 as expected")
                return 0
            print(f"FAIL load_catalog --strict: exited with code {e.code}, "
                  f"wanted 2")
            return 1
        print("FAIL load_catalog --strict: did not exit on errors")
        return 1


def main() -> int:
    failures = 0
    print("=== validate_catalog_entry ===")
    failures += test_validate_function()
    print()
    print("=== load_catalog end-to-end ===")
    failures += test_load_catalog_end_to_end()
    print()
    print(f"Result: {failures} failure(s)")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
