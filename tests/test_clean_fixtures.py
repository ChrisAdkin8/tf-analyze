"""Clean fixture tests — corresponding rule must NOT fire on a correct configuration."""
from __future__ import annotations

import pytest

from helpers import FIXTURES_DIR, clean_fixture_cases, run_detect


@pytest.mark.parametrize("rule_id", clean_fixture_cases())
def test_clean_fixture_no_false_positive(rule_id: str) -> None:
    clean_dir = FIXTURES_DIR / f"{rule_id}_clean"
    findings = run_detect(clean_dir, all_rules=True)
    fired = {f["id"] for f in findings}
    assert rule_id not in fired, (
        f"{rule_id} fired on its clean fixture — false positive. "
        f"All fired IDs: {sorted(fired)}"
    )
