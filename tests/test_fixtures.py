"""Parametrized positive fixture tests — every fixture must fire expected IDs."""
from __future__ import annotations

import pytest

from helpers import FIXTURES_DIR, fixture_cases, run_detect


@pytest.mark.parametrize("fixture_name,expected_ids", fixture_cases(), ids=lambda x: x if isinstance(x, str) else "")
def test_positive_fixture(fixture_name: str, expected_ids: set[str]) -> None:
    fixture_dir = FIXTURES_DIR / fixture_name
    actual = {f["id"] for f in run_detect(fixture_dir, fixture_name=fixture_name)}
    missing = expected_ids - actual
    unexpected = actual - expected_ids
    assert not missing, f"Expected IDs not found: {sorted(missing)}"
    assert not unexpected, f"Unexpected IDs fired: {sorted(unexpected)}"
