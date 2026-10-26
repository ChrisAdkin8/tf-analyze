"""Scoring version 2: hygiene findings are judged relative to repository
size; critical and high findings are not; the --explain-score ceiling is
projected from the unclamped penalty."""

from __future__ import annotations

from _scoring import _compute_summary, explain_score


def _findings(**counts: int) -> list[dict]:
    return [
        {"id": f"R-{u}", "urgency": u, "file": "main.tf", "line": i}
        for u, n in counts.items()
        for i in range(n)
    ]


def test_small_repository_scores_as_version_1() -> None:
    f = _findings(MEDIUM=4, LOW=6)
    assert _compute_summary(f)["score"] == 82
    assert _compute_summary(f, resources_scanned=20)["score"] == 82


def test_hygiene_is_judged_relative_to_size() -> None:
    f = _findings(MEDIUM=20)  # 60 points of hygiene penalty
    small = _compute_summary(f, resources_scanned=10)
    large = _compute_summary(f, resources_scanned=400)
    assert small["score"] == 40
    assert large["size_factor"] == 4.472
    assert large["score"] == 86  # 100 - 60 / 4.472


def test_critical_and_high_cost_the_same_in_any_repository() -> None:
    f = _findings(CRITICAL=2, HIGH=1)
    for n in (5, 500, 5000):
        assert _compute_summary(f, resources_scanned=n)["score"] == 63


def test_summary_explains_its_number() -> None:
    s = _compute_summary(_findings(HIGH=1, MEDIUM=8), resources_scanned=80)
    assert (s["resources_scanned"], s["size_factor"], s["penalty"]) == (80, 2.0, 19.0)
    assert s["score"] == 81


def test_explain_ceiling_is_not_inflated_by_the_zero_clamp() -> None:
    f = _findings(CRITICAL=60)  # penalty 900, score clamped at 0
    s = _compute_summary(f)
    out = explain_score(f, s)
    assert out["base_score"] == 0
    assert out["perfect_score"] == 0  # 900 - 5*15 is still far below 0
    assert all(r["projected_score"] == 0 for r in out["top"])


def test_explain_projects_scaled_weights() -> None:
    f = _findings(MEDIUM=10)
    s = _compute_summary(f, resources_scanned=80)  # factor 2: 15 points
    assert s["score"] == 85
    out = explain_score(f, s, top_n=2)
    assert [r["projected_score"] for r in out["top"]] == [86, 88]
