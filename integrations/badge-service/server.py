"""tf-analyze badge service.

Tiny FastAPI app that returns shields.io-style SVG badges for a
repository's most recent tf-analyze score. The headline shape:

    GET /score/<owner>/<repo>.svg
    GET /score/<owner>/<repo>/<branch>.svg

Embeddable in any README:

    ![tf-analyze](https://tf-analyze-badge.fly.dev/score/foo/bar.svg)

Each rendered badge is an ad — the goal is virality. Score + grade are
the inherently shareable artefacts the engine already emits, so the
badge is a thin renderer on top of stored scan results.

## Deployment shape

Stateless on the request path: every score is keyed by
``(owner, repo, branch, scan_id)`` in a small KV store (env-var
``TFA_BADGE_BACKEND``: ``memory`` for local dev, ``redis://…`` for
Fly.io). A scan workflow (see ``scripts/upload-score.sh``) POSTs the
JSON output of ``detect.py --format json`` to ``/ingest`` with an
HMAC-signed shared secret; the badge endpoint reads the most recent
ingestion for the path.

## Why static SVG (not shields.io endpoint)

shields.io's ``/endpoint`` route requires a public URL returning JSON
in their schema. We could shim that, but rendering the SVG ourselves:

    * removes a hop (latency, cache) from every badge render
    * lets us colour the badge by *grade* (A green → F red) rather
      than only by the numeric threshold rules shields.io supports
    * lets us embed a delta-vs-main figure on PR badges later

## Operator deployment (out of scope for this file)

    flyctl launch --copy-config --no-deploy
    flyctl secrets set TFA_BADGE_INGEST_SECRET=<random 32+ bytes>
    flyctl deploy
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse


app = FastAPI(
    title="tf-analyze badge service",
    description="SVG score badges for tf-analyze-scanned repositories.",
    version="0.1.0",
)


# ---------------------------------------------------------------------------
# Storage backend (in-memory by default; redis in prod)
# ---------------------------------------------------------------------------


@dataclass
class ScoreRecord:
    score: int
    grade: str
    counts: dict
    scan_id: str
    ingested_at: float


class InMemoryStore:
    """Stub backend: process-local dict. Lost on redeploy. Adequate for
    local dev and demos; production should use a persistent backend."""

    def __init__(self) -> None:
        self._records: dict[str, ScoreRecord] = {}

    def put(self, key: str, record: ScoreRecord) -> None:
        self._records[key] = record

    def get(self, key: str) -> Optional[ScoreRecord]:
        return self._records.get(key)


_store: InMemoryStore = InMemoryStore()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

# GitHub-style owner/repo: 1–39 chars per github docs; we allow up to 100
# to accommodate self-hosted GitLab / Gitea naming. Strict character set
# guards against path traversal injected via the URL.
_OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-_.]{0,99}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-_.]{0,99}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-_./]{0,255}$")


def _key(owner: str, repo: str, branch: str = "main") -> str:
    return f"{owner}/{repo}@{branch}"


def _validate_repo_path(owner: str, repo: str, branch: str) -> None:
    if not _OWNER_RE.match(owner):
        raise HTTPException(400, f"invalid owner: {owner!r}")
    if not _REPO_RE.match(repo):
        raise HTTPException(400, f"invalid repo: {repo!r}")
    if not _BRANCH_RE.match(branch):
        raise HTTPException(400, f"invalid branch: {branch!r}")


# ---------------------------------------------------------------------------
# SVG rendering
# ---------------------------------------------------------------------------

# Grade → (background colour, foreground colour). The greens and reds
# match the engine's per-rule docs site palette so the badges feel like
# part of the same surface.
_GRADE_COLOURS: dict[str, tuple[str, str]] = {
    "A":  ("#4c1", "#fff"),    # bright green
    "B":  ("#97CA00", "#fff"), # yellow-green
    "B-": ("#a4a61d", "#fff"), # yellow-green-amber
    "C":  ("#dfb317", "#fff"), # amber
    "D":  ("#fe7d37", "#fff"), # orange
    "F":  ("#e05d44", "#fff"), # red
}


def _grade_colour(grade: str) -> tuple[str, str]:
    # Round-3 audit fix #21 — validate the grade at render time too,
    # not just at ingest. A future engine that emits `"A+"` or any
    # other unrecognised letter would slip through ingest if its
    # validation surface ever loosens; rendering with a clear fallback
    # (`F` colour + a stderr log) prevents silent grey badges that
    # users could mistake for "scan not yet run".
    if grade in _GRADE_COLOURS:
        return _GRADE_COLOURS[grade]
    import sys
    sys.stderr.write(
        f"[badge-service] WARN: unrecognised grade {grade!r}; "
        f"rendering with F-tier colour\n",
    )
    return _GRADE_COLOURS["F"]


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
    """Badge shown when no scan is on file for the requested repo.
    Click-through behaviour is on the README author — they can wrap the
    badge in a link to the workflow that runs the scan."""
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


# ---------------------------------------------------------------------------
# HMAC verification (shared with the run-task server pattern)
# ---------------------------------------------------------------------------


def _verify_hmac(body: bytes, signature_hdr: Optional[str]) -> None:
    """Reject any /ingest body whose HMAC-SHA256 doesn't match the
    shared secret. The header shape is ``sha256=<hex>``, matching
    GitHub's webhook convention so existing webhook tooling round-trips.
    """
    secret = os.environ.get("TFA_BADGE_INGEST_SECRET")
    if not secret:
        # Without a secret configured, /ingest is disabled rather than
        # silently accepting unauthenticated writes.
        raise HTTPException(503, "TFA_BADGE_INGEST_SECRET is not configured")
    if not signature_hdr or not signature_hdr.startswith("sha256="):
        raise HTTPException(401, "missing X-TFA-Signature: sha256=<hex>")
    expected = hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    actual = signature_hdr.removeprefix("sha256=")
    if not hmac.compare_digest(expected, actual):
        raise HTTPException(401, "HMAC signature mismatch")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/", response_class=PlainTextResponse)
def root() -> str:
    return (
        "tf-analyze badge service\n\n"
        "GET /score/<owner>/<repo>.svg          → SVG score badge (main branch)\n"
        "GET /score/<owner>/<repo>/<branch>.svg → branch-specific badge\n"
        "POST /ingest                           → upload a scan result (HMAC-signed)\n"
        "GET /health                            → liveness check\n\n"
        "Source: https://github.com/ChrisAdkin8/tf-analyze/tree/main/integrations/badge-service\n"
    )


@app.get("/health", response_class=PlainTextResponse)
def health() -> str:
    return "ok"


def _badge_response(svg: str) -> Response:
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={
            # READMEs render via GitHub's image proxy (camo.githubusercontent.com),
            # which respects Cache-Control. 5-minute TTL: short enough that
            # post-merge scores propagate quickly, long enough to absorb
            # bursty PR traffic without melting the backend.
            "Cache-Control": "public, max-age=300, s-maxage=300",
            # Defense in depth — these badges are user-controlled SVG
            # rendered content. Pin so a future change can't accidentally
            # ship XHTML / inline scripts.
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/score/{owner}/{repo}.svg")
def score_main_branch(owner: str, repo: str,
                      label: str = Query("tf-analyze", max_length=32)) -> Response:
    _validate_repo_path(owner, repo, "main")
    record = _store.get(_key(owner, repo))
    if record is None:
        return _badge_response(render_unknown_badge(label))
    return _badge_response(
        render_badge_svg(label, record.score, record.grade)
    )


@app.get("/score/{owner}/{repo}/{branch:path}.svg")
def score_branch(owner: str, repo: str, branch: str,
                 label: str = Query("tf-analyze", max_length=32)) -> Response:
    # `{branch:path}` matches anything up to the trailing `.svg`,
    # including slashes (so `release/v1.0`, `feat/foo` work). FastAPI
    # strips the `.svg` suffix because it's not part of the path param;
    # the validator below catches malformed shapes.
    _validate_repo_path(owner, repo, branch)
    record = _store.get(_key(owner, repo, branch))
    if record is None:
        return _badge_response(render_unknown_badge(label))
    return _badge_response(
        render_badge_svg(label, record.score, record.grade)
    )


@app.post("/ingest")
async def ingest(request: Request) -> dict:
    """Accept a tf-analyze JSON output and register the score for the
    repo. Authenticated by HMAC-SHA256 over the raw request body.

    Expected body:

        {
          "owner": "ChrisAdkin8",
          "repo":  "tf-analyze",
          "branch": "main",
          "scan":  {<full --format json output, must include `summary`>}
        }
    """
    body = await request.body()
    _verify_hmac(body, request.headers.get("X-TFA-Signature"))

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"invalid JSON body: {e}")

    owner = str(payload.get("owner") or "")
    repo = str(payload.get("repo") or "")
    branch = str(payload.get("branch") or "main")
    _validate_repo_path(owner, repo, branch)

    scan = payload.get("scan") or {}
    summary = scan.get("summary") or {}
    score = summary.get("score")
    grade = summary.get("grade")
    if not isinstance(score, int) or not isinstance(grade, str):
        raise HTTPException(
            400,
            "scan.summary must include integer `score` and string `grade` "
            "(emitted by `detect.py --format json`)",
        )
    if grade not in _GRADE_COLOURS:
        raise HTTPException(400, f"unknown grade: {grade!r}")

    counts = summary.get("counts") or {}
    scan_id = str(payload.get("scan_id") or hashlib.sha256(body).hexdigest()[:16])

    _store.put(_key(owner, repo, branch), ScoreRecord(
        score=score, grade=grade, counts=counts,
        scan_id=scan_id, ingested_at=time.time(),
    ))
    return {"ok": True, "key": _key(owner, repo, branch), "scan_id": scan_id}
