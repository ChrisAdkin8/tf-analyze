"""Scoring version 2: hygiene findings are judged relative to repository
size; critical and high findings are not; the --explain-score ceiling is
projected from the unclamped penalty and each fix shows its real points;
only resources a rule checks count towards the size."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from _scoring import (
    _compute_summary,
    _scored_resource_count,
    explain_score,
    render_score_explanation,
)

REPO = Path(__file__).resolve().parents[1]


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


def test_explain_shows_the_points_a_fix_is_worth() -> None:
    f = _findings(MEDIUM=1)
    s = _compute_summary(f, resources_scanned=80)  # factor 2
    row = explain_score(f, s)["top"][0]
    assert (row["weight"], row["points"]) == (3, 1.5)
    assert "−1.5 pts" in render_score_explanation(explain_score(f, s))
    critical = explain_score(_findings(CRITICAL=1), s)["top"][0]
    assert critical["points"] == 15  # never scaled


def test_only_rule_covered_resources_count_towards_size() -> None:
    entries = [{"id": "R-1", "patterns": [{"kind": "resource_arg", "resource": "aws_s3_bucket"}]}]
    types = ["aws_s3_bucket", "terraform_data", "null_resource", "aws_s3_bucket"]
    assert _scored_resource_count(types, entries) == 2


def _summary(target: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"),
         "--target", str(target), "--format", "json"],
        capture_output=True, text=True, check=False,
    )
    return json.loads(proc.stdout)["summary"]


def test_padding_with_unassessed_resources_does_not_lift_the_score(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "x" {\n  bucket = "x"\n  acl    = "public-read"\n}\n'
    )
    before = _summary(tmp_path)
    (tmp_path / "pad.tf").write_text("".join(
        f'resource "terraform_data" "p{i}" {{}}\n' for i in range(500)
    ))
    after = _summary(tmp_path)
    assert after["resources_scanned"] == before["resources_scanned"] == 1
    assert after["score"] == before["score"]


_URGENCIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@given(
    counts=st.fixed_dictionaries({u: st.integers(0, 60) for u in _URGENCIES}),
    resources=st.integers(0, 5000),
    fixed=st.sampled_from(_URGENCIES),
)
def test_fixing_a_finding_never_lowers_the_score(counts, resources, fixed) -> None:
    if not counts[fixed]:
        return
    after = dict(counts, **{fixed: counts[fixed] - 1})
    before_score = _compute_summary(_findings(**counts), resources_scanned=resources)["score"]
    after_score = _compute_summary(_findings(**after), resources_scanned=resources)["score"]
    assert after_score >= before_score
