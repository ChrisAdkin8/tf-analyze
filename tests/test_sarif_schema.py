"""SARIF output must validate against the official SARIF 2.1.0 schema.

GitHub code scanning is lenient, so shape tests alone let invalid SARIF
ship (964 schema errors per run until 2026-10-26: a `name` on every
`relationships[].target`). The schema is the OASIS errata01 file, vendored
at tests/schemas/ so the test runs offline.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

REPO = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (REPO / "tests" / "schemas" / "sarif-schema-2.1.0.json").read_text()
)
VALIDATOR = jsonschema.Draft4Validator(SCHEMA)


def _sarif(target: Path, *extra: str) -> dict:
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--format",
            "sarif",
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return json.loads(proc.stdout)


def _errors(doc: dict) -> list[str]:
    return [
        f"{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}"
        for e in VALIDATOR.iter_errors(doc)
    ]


@pytest.mark.parametrize(
    ("target", "extra"),
    [
        ("fixtures/aws_sg_open", ()),
        ("examples", ()),
        ("examples", ("--attack-graph", "--show-info")),
        ("demo", ()),
    ],
)
def test_sarif_validates_against_schema(target: str, extra: tuple) -> None:
    errors = _errors(_sarif(REPO / target, *extra))
    assert not errors, f"{len(errors)} schema error(s), first: {errors[:5]}"


def test_sarif_with_no_findings_validates(tmp_path) -> None:
    errors = _errors(_sarif(tmp_path))
    assert not errors, errors[:5]
