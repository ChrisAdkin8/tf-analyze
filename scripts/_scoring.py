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

# Ordered urgency tiers — LOW < MEDIUM < HIGH < CRITICAL — used by the
# attack-graph's `_apply_reachability_urgency` to promote findings on
# critical-path resources by one tier and demote findings on
# unreachable resources by one tier. INFO is deliberately omitted: it
# is a zero-weight tag, not a position on this ordered axis.
_URGENCY_TIERS: list[str] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

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


def explain_score(
    findings: list[dict],
    summary: dict,
    *,
    top_n: int = 5,
) -> dict:
    """Rank findings by score impact and project the score if each is fixed.

    Returns a JSON-safe dict carrying:
      * ``top`` — list of `{rank, id, urgency, weight, file, line, resource,
        title, projected_score, projected_grade}` entries, sorted by score
        contribution descending (highest-impact first), with deterministic
        secondary sort on (id, file, line) so two runs against the same
        corpus agree.
      * ``base_score`` / ``base_grade`` — the unchanged score before any
        fix is applied. Mirrors `summary['score']` for self-contained
        consumption.
      * ``perfect_score`` — what the score would be after fixing all
        listed findings (capped at 100). Useful as a "ceiling if you do
        all of this" hint in the PR comment.

    Pure function. INFO-tier findings carry weight 0 so they are excluded
    from the top-N (fixing them does not move the score).

    R30.8: `--explain-score` flag. Tells the user which fix is worth the
    most — the single highest-leverage piece of advice an IaC scanner
    can give beyond the "you broke rule X" line.
    """
    base_score = int(summary.get("score", 100))
    eligible = [
        f for f in findings
        if _RISK_WEIGHTS.get(f.get("urgency", "MEDIUM"), 0) > 0
    ]
    # Sort: weight desc, then id/file/line asc for deterministic output.
    ranked = sorted(
        eligible,
        key=lambda f: (
            -_RISK_WEIGHTS.get(f.get("urgency", "MEDIUM"), 0),
            f.get("id", ""),
            f.get("file", ""),
            f.get("line", 0),
        ),
    )
    top = ranked[:top_n]
    cumulative = 0
    rows: list[dict] = []
    for i, f in enumerate(top, start=1):
        w = _RISK_WEIGHTS.get(f.get("urgency", "MEDIUM"), 0)
        cumulative += w
        projected = min(100, base_score + cumulative)
        rows.append({
            "rank": i,
            "id": f.get("id"),
            "urgency": f.get("urgency"),
            "weight": w,
            "file": f.get("file"),
            "line": f.get("line"),
            "resource": f.get("resource", ""),
            "title": f.get("title", ""),
            "projected_score": projected,
            "projected_grade": _grade_for_score(projected),
        })
    perfect = min(100, base_score + sum(r["weight"] for r in rows))
    return {
        "base_score": base_score,
        "base_grade": summary.get("grade", _grade_for_score(base_score)),
        "perfect_score": perfect,
        "perfect_grade": _grade_for_score(perfect),
        "top": rows,
    }


def render_score_explanation(payload: dict) -> str:
    """Format `explain_score()` output for text/PR-summary surfaces.

    Stable text block; consumed by detect.py's text formatter and the
    GitHub Action's PR comment. JSON consumers should use the structured
    `score_explanation` field instead.
    """
    base = payload["base_score"]
    base_grade = payload["base_grade"]
    perfect = payload["perfect_score"]
    perfect_grade = payload["perfect_grade"]
    rows = payload["top"]
    lines = [
        "# --explain-score: top fixes ranked by score impact",
        f"# current: {base} ({base_grade}) · ceiling if you fix the top "
        f"{len(rows)}: {perfect} ({perfect_grade})",
    ]
    if not rows:
        lines.append("# (no score-affecting findings — score is already at the ceiling)")
        return "\n".join(lines)
    for r in rows:
        loc = f"{r['file']}:{r['line']}" if r.get("file") else "<corpus>"
        title = f" {r['title']}" if r.get("title") else ""
        lines.append(
            f"  #{r['rank']} [{r['urgency']}] {r['id']} −{r['weight']} pts  "
            f"({loc}) → if fixed: {r['projected_score']} "
            f"({r['projected_grade']}){title}"
        )
    return "\n".join(lines)


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
