"""Risk-score formula + letter-grade helpers.

Extracted from `detect.py` as the third seam in the modularisation
(after `_mitre.py` and `_versions.py`). Pure functions over plain
dicts, no I/O. Same shape as the prior extracts.

Public surface:
  * `_SCORING_VERSION` — bumped whenever the weight table changes;
    downstream gates can pin against this.
  * `_RISK_WEIGHTS` — `{urgency: penalty per finding}`.
  * `_GRADE_TIERS` — `[(score_floor, letter)]`, first-match-wins.
  * `_grade_for_score(score)` — int → letter.
  * `_compute_summary(findings, suppressed?, suppressed_by_baseline?)` —
    full summary block: `{scoring_version, score, grade, counts,
    suppressed_count, formula}`.

These constants are the SINGLE SOURCE OF TRUTH for the score and
letter grade documented in SKILL.md (search for "Risk Score"). The
CLI emits the same number the LLM-driven markdown report computes,
so two runs against the same code always agree.

Score formula:
    score = max(0, 100 - sum(weight * count for each urgency))
Suppressed findings count at half weight (acknowledged but the
underlying risk still exists).

Names are kept underscore-prefixed (`_RISK_WEIGHTS`, `_compute_summary`)
because external callers reference them under those names — preserving
the no-behaviour-change invariant of the extraction.
"""
from __future__ import annotations


# Tagged with `_SCORING_VERSION` so downstream gates can pin to a
# specific weighting; bump it whenever weights change.
_SCORING_VERSION = 1

_RISK_WEIGHTS: dict[str, int] = {
    "CRITICAL": 15,
    "HIGH":     7,
    "MEDIUM":   3,
    "LOW":      1,
    "INFO":     0,
}

# (lower bound of score, letter grade) — first match wins; sorted descending.
_GRADE_TIERS: list[tuple[int, str]] = [
    (90, "A"),
    (75, "B"),
    (65, "B-"),
    (50, "C"),
    (30, "D"),
    (0,  "F"),
]


def _grade_for_score(score: int) -> str:
    for floor, grade in _GRADE_TIERS:
        if score >= floor:
            return grade
    return "F"


def _compute_summary(
    findings: list[dict],
    suppressed: list[dict] | None = None,
    suppressed_by_baseline: list[dict] | None = None,
) -> dict:
    """Compute the always-emitted summary block.

    Score formula: ``max(0, 100 - sum(weight * count))`` where suppressed
    findings (both ignore-suppressed and baseline-suppressed) contribute
    half weight. INFO findings carry weight 0 so they never affect the
    score; their count is reported for context.

    The dict returned is JSON-safe and stable: keys, types, and ordering
    are part of the public contract pinned by ``scoring_version``.
    """
    counts: dict[str, int] = {u: 0 for u in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for f in findings:
        u = f.get("urgency", "MEDIUM")
        counts[u] = counts.get(u, 0) + 1

    # Half-weight contribution from suppressed/baselined findings.
    suppressed_count = 0
    half_penalty = 0.0
    for bucket in (suppressed or [], suppressed_by_baseline or []):
        for f in bucket:
            suppressed_count += 1
            u = f.get("urgency", "MEDIUM")
            half_penalty += _RISK_WEIGHTS.get(u, 0) / 2

    full_penalty = sum(_RISK_WEIGHTS.get(u, 0) * c for u, c in counts.items())
    raw_score = 100 - full_penalty - half_penalty
    score = max(0, int(round(raw_score)))
    return {
        "scoring_version": _SCORING_VERSION,
        "score": score,
        "grade": _grade_for_score(score),
        "counts": counts,
        "suppressed_count": suppressed_count,
        "formula": (
            "max(0, 100 - sum(weight * count)); "
            "weights: CRITICAL=15, HIGH=7, MEDIUM=3, LOW=1, INFO=0; "
            "suppressed at half weight"
        ),
    }
