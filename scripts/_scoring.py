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

Score formula (scoring version 2):
    penalty = 15*CRITICAL + 7*HIGH + (3*MEDIUM + 1*LOW) / size_factor
    score   = max(0, floor(100 - penalty))
    size_factor = max(1, sqrt(resources_scanned / 20))
`resources_scanned` counts only resources of a type at least one rule
checks (`_scored_resource_count`): `terraform_data`, `null_resource` or
`random_*` blocks are never assessed, so they cannot inflate the size
factor (500 empty `terraform_data` blocks took a score from 50 to 61).
CRITICAL and HIGH findings are each a concrete exposure, so they cost
the same in any repository. MEDIUM and LOW are hygiene, judged relative
to size: a repository of up to 20 resources scores exactly as in version
1, while 80 resources halve the hygiene penalty and 2,000 divide it by
ten — a large estate is not graded F for the sheer number of resources
it has. Hygiene is scored as mess per assessed resource, so adding a real
resource cleaner than the average, or deleting one dirtier than it, can
move the score by a point the "wrong" way; fixing a finding always helps.
Suppressed findings count at half weight (acknowledged but the
underlying risk still exists).

Names are kept underscore-prefixed (`_RISK_WEIGHTS`, `_compute_summary`)
because external callers reference them under those names — preserving
the no-behaviour-change invariant of the extraction.
"""
from __future__ import annotations

import math


# Tagged with `_SCORING_VERSION` so downstream gates can pin to a
# specific weighting; bump it whenever weights change.
_SCORING_VERSION = 2

# Urgencies whose penalty is divided by the size factor (hygiene); the
# others cost the same in a repository of any size.
_SIZE_SCALED = frozenset({"MEDIUM", "LOW"})
# Resources up to which the size factor is 1 (version-1 scores).
_SIZE_BASELINE = 20


def _size_factor(resources_scanned: int | None) -> float:
    """``max(1, sqrt(resources / 20))``; 1 when the count is unknown."""
    if not resources_scanned:
        return 1.0
    return max(1.0, math.sqrt(resources_scanned / _SIZE_BASELINE))


def _scored_resource_types(entries: list[dict]) -> frozenset[str]:
    """Resource types at least one catalogue pattern checks (its
    ``resource:``) — the resources that count towards the size factor."""
    return frozenset(
        p["resource"]
        for e in entries
        for p in e.get("patterns") or []
        if isinstance(p, dict) and isinstance(p.get("resource"), str)
    )


def _scored_resource_count(resource_types: list[str], entries: list[dict]) -> int:
    """How many of `resource_types` (one per resource block) count towards
    the size factor."""
    scored = _scored_resource_types(entries)
    return sum(1 for t in resource_types if t in scored)


def _effective_weight(urgency: str, size_factor: float) -> float:
    w = _RISK_WEIGHTS.get(urgency, 0)
    return w / size_factor if urgency in _SIZE_SCALED else float(w)

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
      * ``top`` — list of `{rank, id, urgency, weight, points, file, line,
        resource, title, projected_score, projected_grade}` entries
        (`weight` is the urgency's catalogue weight; `points` what fixing
        the finding actually removes from the penalty once MEDIUM / LOW
        are divided by the size factor), sorted by score
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
    factor = float(summary.get("size_factor", 1.0))
    # Project from the unclamped penalty: adding a fixed finding's weight
    # back onto a score already clamped at 0 promised a ceiling the fix
    # would never reach (500 CRITICALs "→ 75 (B) if you fix 5").
    penalty = float(summary.get("penalty", 100 - base_score))
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
    cumulative = 0.0
    rows: list[dict] = []

    def project(removed: float) -> int:
        return min(100, max(0, math.floor(100 - (penalty - removed))))

    for i, f in enumerate(top, start=1):
        u = f.get("urgency", "MEDIUM")
        w = _RISK_WEIGHTS.get(u, 0)
        points = _effective_weight(u, factor)
        cumulative += points
        projected = project(cumulative)
        rows.append({
            "rank": i,
            "id": f.get("id"),
            "urgency": f.get("urgency"),
            "weight": w,
            "points": round(points, 2),
            "file": f.get("file"),
            "line": f.get("line"),
            "resource": f.get("resource", ""),
            "title": f.get("title", ""),
            "projected_score": projected,
            "projected_grade": _grade_for_score(projected),
        })
    perfect = project(cumulative)
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
        points = r.get("points", r["weight"])
        lines.append(
            f"  #{r['rank']} [{r['urgency']}] {r['id']} −{points:g} pts  "
            f"({loc}) → if fixed: {r['projected_score']} "
            f"({r['projected_grade']}){title}"
        )
    return "\n".join(lines)


def _compute_summary(
    findings: list[dict],
    suppressed: list[dict] | None = None,
    suppressed_by_baseline: list[dict] | None = None,
    resources_scanned: int | None = None,
) -> dict:
    """Compute the always-emitted summary block.

    Score formula: see the module docstring — CRITICAL / HIGH at full
    weight, MEDIUM / LOW divided by the size factor for
    `resources_scanned` (1 when it is None, i.e. version-1 scoring).
    Suppressed findings (both ignore-suppressed and baseline-suppressed)
    contribute half weight. INFO findings carry weight 0 so they never
    affect the score; their count is reported for context.

    The dict returned is JSON-safe and stable: keys, types, and ordering
    are part of the public contract pinned by ``scoring_version``.
    """
    counts: dict[str, int] = {u: 0 for u in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for f in findings:
        u = f.get("urgency", "MEDIUM")
        counts[u] = counts.get(u, 0) + 1

    # Half-weight contribution from suppressed/baselined findings.
    factor = _size_factor(resources_scanned)
    suppressed_count = 0
    half_penalty = 0.0
    for bucket in (suppressed or [], suppressed_by_baseline or []):
        for f in bucket:
            suppressed_count += 1
            half_penalty += _effective_weight(f.get("urgency", "MEDIUM"), factor) / 2

    full_penalty = sum(_effective_weight(u, factor) * c for u, c in counts.items())
    penalty = full_penalty + half_penalty
    raw_score = 100 - penalty
    # Round DOWN (floor), not round-half-to-even. A suppressed finding adds a
    # half-weight penalty, so raw_score can land on X.5; banker's rounding then
    # moved the grade up or down depending only on parity (99.5→100 but
    # 98.5→98), which was surprising. Floor is the conservative, predictable
    # choice for a penalty-based health score — it never over-credits.
    score = max(0, math.floor(raw_score))
    return {
        "scoring_version": _SCORING_VERSION,
        "score": score,
        "grade": _grade_for_score(score),
        "counts": counts,
        "suppressed_count": suppressed_count,
        "resources_scanned": resources_scanned,
        "size_factor": round(factor, 3),
        "penalty": round(penalty, 3),
        "formula": (
            "max(0, floor(100 - (15*CRITICAL + 7*HIGH "
            "+ (3*MEDIUM + 1*LOW) / size_factor))); "
            "size_factor = max(1, sqrt(resources_scanned / 20)), "
            "counting resources of a type a rule checks; "
            "INFO=0; suppressed at half weight"
        ),
    }
