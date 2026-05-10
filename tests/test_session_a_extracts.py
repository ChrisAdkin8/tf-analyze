"""Tests for the Session-A modularisation extracts: `_versions.py`
and `_scoring.py`.

The functional contracts for both modules are already covered:
* `_versions._provider_constraint_allows` — by the 10-case truth
  table in `tests/test_a1_improvements.py`.
* `_scoring._compute_summary` — by the worked-examples assertions in
  `tests/test_output_formats.py::TestComputeSummary`.

These tests cover the *seam contract* — that the new modules expose
the names callers expect, and that `detect.py` re-exports each name
as a binding (not a copy) so future renames stay in sync.

Same shape as the prior `_mitre.py` seam tests in
`tests/test_sarif_taxonomies_and_refactor.py::TestMitreModule`.
"""
from __future__ import annotations

import sys

from helpers import REPO_ROOT


class TestVersionsModule:
    def test_module_imports_cleanly(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _versions
        # Public surface every external caller depends on.
        assert hasattr(_versions, "_version_tuple")
        assert hasattr(_versions, "_provider_constraint_allows")
        assert hasattr(_versions, "_extract_provider_constraints")
        assert hasattr(_versions, "_extract_terraform_version")
        assert hasattr(_versions, "_entry_applies_to_providers")

    def test_detect_re_exports_bindings_not_copies(self) -> None:
        """The legacy `detect._provider_constraint_allows` symbol must
        be the same function object as the one in `_versions.py`. If a
        future rename adds a copy or a wrapper, this catches it."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        import _versions
        assert detect._version_tuple is _versions._version_tuple
        assert detect._provider_constraint_allows is _versions._provider_constraint_allows
        assert detect._extract_provider_constraints is _versions._extract_provider_constraints
        assert detect._extract_terraform_version is _versions._extract_terraform_version
        assert detect._entry_applies_to_providers is _versions._entry_applies_to_providers

    def test_round_trip(self) -> None:
        """Sanity smoke for the public surface — keeps this seam test
        independent of the deep truth-table coverage in test_a1_improvements."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from _versions import (
            _version_tuple,
            _provider_constraint_allows,
            _entry_applies_to_providers,
        )
        assert _version_tuple("5.42.1") == (5, 42, 1)
        assert _provider_constraint_allows("~> 5.40", "5.0") is True
        assert _provider_constraint_allows("< 5.0", "5.0") is False
        # `applies_when` gating: missing constraint passes (permissive default).
        assert _entry_applies_to_providers({}, {}, "") is True


class TestScoringModule:
    def test_module_imports_cleanly(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _scoring
        assert hasattr(_scoring, "_SCORING_VERSION")
        assert hasattr(_scoring, "_RISK_WEIGHTS")
        assert hasattr(_scoring, "_GRADE_TIERS")
        assert hasattr(_scoring, "_grade_for_score")
        assert hasattr(_scoring, "_compute_summary")

    def test_detect_re_exports_bindings_not_copies(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        import _scoring
        # Constants must be the same object (so SKILL.md's
        # "single source of truth" claim holds) — `is` not `==`.
        assert detect._RISK_WEIGHTS is _scoring._RISK_WEIGHTS
        assert detect._GRADE_TIERS is _scoring._GRADE_TIERS
        assert detect._compute_summary is _scoring._compute_summary
        assert detect._grade_for_score is _scoring._grade_for_score
        # _SCORING_VERSION is an int (immutable) — `==` is the right test.
        assert detect._SCORING_VERSION == _scoring._SCORING_VERSION

    def test_skill_md_worked_examples(self) -> None:
        """SKILL.md documents three worked examples for the score
        formula. Locking them at the seam-test level (in addition to
        `tests/test_output_formats.py::TestComputeSummary`) ensures the
        re-export shim keeps the same behaviour as a direct import."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from _scoring import _compute_summary

        # 0 CRITICAL, 0 HIGH, 4 MEDIUM, 6 LOW → 100 − (0 + 0 + 12 + 6) = 82 (B)
        f_82 = [{"urgency": "MEDIUM"}] * 4 + [{"urgency": "LOW"}] * 6
        s = _compute_summary(f_82)
        assert s["score"] == 82
        assert s["grade"] == "B"

        # 0 CRITICAL, 4 HIGH, 11 MEDIUM, 6 LOW → 100 − 67 = 33 (D)
        f_33 = [{"urgency": "HIGH"}] * 4 + [{"urgency": "MEDIUM"}] * 11 + [{"urgency": "LOW"}] * 6
        s = _compute_summary(f_33)
        assert s["score"] == 33
        assert s["grade"] == "D"

        # Empty → 100 (A)
        s = _compute_summary([])
        assert s["score"] == 100
        assert s["grade"] == "A"

    def test_info_findings_carry_zero_weight(self) -> None:
        """INFO findings must never move the score — locked here
        because the rule is restated in three different docs and could
        silently drift if `_RISK_WEIGHTS["INFO"]` ever changed."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from _scoring import _compute_summary, _RISK_WEIGHTS
        assert _RISK_WEIGHTS["INFO"] == 0
        # A repo with 100 INFO findings should still score 100.
        s = _compute_summary([{"urgency": "INFO"}] * 100)
        assert s["score"] == 100
        assert s["counts"]["INFO"] == 100
