"""SVG badge rendering for tf-analyze scan results.

Lifted from ``integrations/badge-service/server.py`` when the badge
service was unified under ``tfanalyze.com``. The HMAC ingest path was
dropped — the public scanner's per-SHA cache makes the
push-from-CI workflow obsolete.

Two renderers:

* ``render_badge_svg(label, score, grade)`` — shields.io-shape badge
  for a repo with a cached scan result.
* ``render_unknown_badge(label)`` — placeholder for repos that have
  never been scanned. README authors typically wrap this in a link to
  the live scanner so the first click populates the cache.
"""
from __future__ import annotations


# Grade → (background colour, foreground colour). The greens and reds
# match the engine's per-rule docs site palette so the badges feel like
# part of the same surface.
_GRADE_COLOURS: dict[str, tuple[str, str]] = {
    "A":  ("#4c1", "#fff"),
    "B":  ("#97CA00", "#fff"),
    "B-": ("#a4a61d", "#fff"),
    "C":  ("#dfb317", "#fff"),
    "D":  ("#fe7d37", "#fff"),
    "F":  ("#e05d44", "#fff"),
}


def _grade_colour(grade: str) -> tuple[str, str]:
    return _GRADE_COLOURS.get(grade, ("#9f9f9f", "#fff"))


def render_badge_svg(label: str, score: int, grade: str) -> str:
    """Render a shields.io-shape SVG badge: ``<label> | <score> (<grade>)``.

    The width of the score region scales with the rendered text length
    so a "B-" grade doesn't get clipped. Uses Verdana (shields.io's
    canonical font) to match the rest of the badge ecosystem visually.
    """
    bg, fg = _grade_colour(grade)
    score_text = f"{score} ({grade})"
    # Approximate width: 6.7 px per character in 11-pt Verdana, +14 padding.
    label_w = max(74, int(6.7 * len(label) + 14))
    score_w = max(56, int(6.7 * len(score_text) + 14))
    total_w = label_w + score_w

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{total_w}" height="20" role="img" '
        f'aria-label="{label}: {score} ({grade})">'
        f'<title>{label}: {score} ({grade})</title>'
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/>'
        f'</linearGradient>'
        f'<clipPath id="r"><rect width="{total_w}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{label_w}" height="20" fill="#555"/>'
        f'<rect x="{label_w}" width="{score_w}" height="20" fill="{bg}"/>'
        f'<rect width="{total_w}" height="20" fill="url(#s)"/>'
        f'</g>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" '
        f'text-rendering="geometricPrecision" font-size="110">'
        f'<text aria-hidden="true" x="{label_w * 5}" y="150" fill="#010101" '
        f'fill-opacity=".3" transform="scale(.1)" textLength="{(label_w - 10) * 10}">{label}</text>'
        f'<text x="{label_w * 5}" y="140" transform="scale(.1)" fill="{fg}" '
        f'textLength="{(label_w - 10) * 10}">{label}</text>'
        f'<text aria-hidden="true" x="{(label_w + score_w / 2) * 10}" y="150" '
        f'fill="#010101" fill-opacity=".3" transform="scale(.1)" '
        f'textLength="{(score_w - 10) * 10}">{score_text}</text>'
        f'<text x="{(label_w + score_w / 2) * 10}" y="140" transform="scale(.1)" '
        f'fill="{fg}" textLength="{(score_w - 10) * 10}">{score_text}</text>'
        f'</g></svg>'
    )


def render_unknown_badge(label: str = "tf-analyze") -> str:
    """Badge shown when no cached scan exists for the requested repo.

    README authors typically wrap this in a link to
    ``tfanalyze.com/scan/<owner>/<repo>`` so the first click populates
    the cache; the next badge fetch then renders a real score.
    """
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="130" height="20" '
        f'role="img" aria-label="{label}: no data">'
        f'<title>{label}: no data</title>'
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="130" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="74" height="20" fill="#555"/>'
        f'<rect x="74" width="56" height="20" fill="#9f9f9f"/>'
        f'<rect width="130" height="20" fill="url(#s)"/></g>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110">'
        f'<text x="370" y="140" transform="scale(.1)" textLength="640">{label}</text>'
        f'<text x="1020" y="140" transform="scale(.1)" textLength="460">no data</text>'
        f'</g></svg>'
    )
