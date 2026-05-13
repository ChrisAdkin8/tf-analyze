"""tf-analyze interactive web demo + public-scanner backend.

Three surfaces:

* ``POST /scan/hcl`` — paste-and-scan, used by the index page editor.
* ``POST /scan/repo`` — JSON body ``{repo: <github-url>}``, legacy API.
* ``GET /scan/<owner>/<repo>`` (R30.14) — **the public scanner.** Renders
  an HTML permalink for a public GitHub repo's latest commit. Pages
  are cached by commit SHA so two strangers hitting the same URL share
  one scan. This is the load-bearing virality surface; every share is
  an organic referral.

Hardening shared across all three:

* Per-IP rate limiting (10 req / 60s sliding window).
* 30s subprocess timeout on the scanner.
* Single-branch shallow clone (``--depth 1``).
* Allow-list regex restricts ``/scan/repo`` URLs to github.com / gitlab.com.
* HCL paste capped at 50 KB.
* Permalink HTML never echoes user-supplied repo URLs without escaping
  via ``html.escape`` (defence in depth — the regex above does not
  permit angle brackets).
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# Sibling import — works under both `uvicorn app:app` (Docker container,
# WORKDIR=/app/demo) and `uvicorn demo.app:app` (local dev from repo root).
sys.path.insert(0, str(Path(__file__).parent))
from _badge import render_badge_svg, render_unknown_badge  # noqa: E402

app = FastAPI(title="tf-analyze demo", docs_url=None, redoc_url=None)

REPO_ROOT = Path(__file__).parent.parent
DETECT = REPO_ROOT / "scripts" / "detect.py"
CATALOG = REPO_ROOT / "catalog"

# Persisted scan cache. Defaults to /var/cache/tf-analyze inside the
# Fly.io container (mounted as a volume in fly.toml) so two visits to
# the same commit don't re-clone + re-scan. Overridable via env for
# local dev.
CACHE_DIR = Path(os.environ.get("TFA_SCAN_CACHE_DIR", "/var/cache/tf-analyze"))
try:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
except (PermissionError, OSError):
    # Fall back to a tmp dir if the container's /var/cache isn't writable
    # (e.g. when running outside of Fly.io with the default volume mount).
    CACHE_DIR = Path(tempfile.gettempdir()) / "tf-analyze-scan-cache"
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

_rate: dict[str, list[float]] = defaultdict(list)

# Bound the public scanner to "reasonable" repos. Anything beyond this
# probably needs a longer-running CI job (the GitHub Action is the
# right surface for those).
MAX_TF_FILES = 500
MAX_CLONE_BYTES = 50 * 1024 * 1024  # 50 MB
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60


def _catalog_hash() -> str:
    """Compact hash (first 8 hex of SHA-256) of every YAML under CATALOG.

    Used as a suffix on the per-SHA cache key so that a rule-pack ship
    invalidates the cache automatically — old entries with the previous
    hash stop being looked up after redeploy, no manual cache purge.

    Computed once at import time. Cost is negligible (~1 ms for ~343
    YAMLs). Returns the empty string if the catalogue can't be read at
    all (so the key shape stays well-formed even in dev environments
    without a populated CATALOG dir).
    """
    h = hashlib.sha256()
    try:
        for p in sorted(CATALOG.glob("*.yaml")):
            try:
                h.update(p.read_bytes())
            except OSError:
                # A YAML disappeared mid-iteration is fine — skip it; the
                # remaining files still produce a deterministic hash for
                # this process' view of the catalogue.
                continue
    except OSError:
        return ""
    return h.hexdigest()[:8]


CATALOG_HASH = _catalog_hash()


def _load_ignore_paths(target: Path) -> list[str]:
    """Read `ignore_paths:` from `<target>/.tf-analyze.yaml`.

    Returns a list of normalised path prefixes (no leading/trailing
    slashes). Empty list on missing file or any parse error — the cap
    check then falls back to counting every `.tf` file, matching pre-
    R32-rebuild behaviour.

    We inline a tiny YAML parser instead of importing the engine's
    `_catalog._load_project_config` because (a) the demo app deliberately
    shells out to `detect.py` rather than importing engine internals and
    (b) the shape we need is a single string-list under one top-level
    key — trivial to parse without a YAML library.
    """
    cfg_path = target / ".tf-analyze.yaml"
    if not cfg_path.exists():
        return []
    try:
        text = cfg_path.read_text()
    except OSError:
        return []
    out: list[str] = []
    in_ignore = False
    for line in text.splitlines():
        # Strip inline comments before further parsing.
        if "#" in line:
            line = line[: line.index("#")]
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == "ignore_paths:":
            in_ignore = True
            continue
        if in_ignore:
            # A list item under ignore_paths.
            if stripped.startswith("- "):
                val = stripped[2:].strip().strip('"').strip("'").strip("/")
                if val:
                    out.append(val)
                continue
            # A new top-level key means we're done with ignore_paths.
            if not line.startswith((" ", "\t")):
                in_ignore = False
    return out


def _path_is_ignored(rel: Path, ignore_paths: list[str]) -> bool:
    """Component-wise prefix match against `ignore_paths`.

    Mirrors `scripts/detect.py:_path_is_ignored` so the engine's view
    of which files are in scope agrees with the cap check here. Each
    pattern matches if all its `/`-separated components match the
    corresponding leading components of `rel`.
    """
    if not ignore_paths:
        return False
    parts = rel.parts
    for pat in ignore_paths:
        pat_parts = tuple(pat.split("/"))
        if len(pat_parts) <= len(parts) and parts[: len(pat_parts)] == pat_parts:
            return True
    return False


def _rate_check(ip: str) -> bool:
    now = time.time()
    _rate[ip] = [t for t in _rate[ip] if now - t < RATE_LIMIT_WINDOW_SECONDS]
    if len(_rate[ip]) >= RATE_LIMIT_REQUESTS:
        return False
    _rate[ip].append(now)
    return True


class ScanHcl(BaseModel):
    hcl: str


class ScanRepo(BaseModel):
    repo: str


def _run_scan(target_dir: str) -> dict:
    result = subprocess.run(
        [
            "python3", str(DETECT),
            "--target", target_dir,
            "--catalog", str(CATALOG),
            "--format", "json",
            "--attack-graph",
            "--explain-score",
            # R30.16 — emit INFO-tier findings (module-reuse advisor + style)
            # so the paste-and-scan UI can render the dedicated 📦 panel.
            # Frontend segregates MOD-REUSE-* from other INFO findings to
            # keep the noise floor low.
            "--show-info",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    # Round-3 audit fix #19 — a non-JSON stdout could mean either (a)
    # a real parse error in a non-empty payload, or (b) an empty
    # payload because the engine crashed with a config error before
    # emitting JSON. The original handler raised "invalid JSON" for
    # both, masking case (b)'s root cause (visible only in stderr).
    # Distinguish them so the 500 message carries actionable signal.
    if not result.stdout.strip():
        raise HTTPException(
            status_code=500,
            detail=(
                f"Scanner emitted empty stdout (exit {result.returncode}). "
                f"Engine stderr: {(result.stderr or '').strip()[:500] or '(empty)'}"
            ),
        )
    if result.returncode > 1:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Scanner exited {result.returncode}. "
                f"stderr: {(result.stderr or '').strip()[:500] or '(empty)'}"
            ),
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Scanner returned invalid JSON: {e}. "
                f"stderr: {(result.stderr or '').strip()[:500] or '(empty)'}"
            ),
        )


# ---------------------------------------------------------------------------
# Public scanner — GET /scan/{owner}/{repo}
# ---------------------------------------------------------------------------


_OWNER_RE = re.compile(r"^[A-Za-z0-9][\w.\-]{0,38}$")
_REPO_RE = re.compile(r"^[\w.\-]{1,100}$")


def _resolve_head_sha(owner: str, repo: str) -> str | None:
    """Resolve the default branch HEAD to a 40-char SHA via `git ls-remote`.

    No `gh` CLI dependency, no auth, no token. Returns None on any
    failure (404 repo, network blip, etc.) so the caller can surface
    a clean 404 to the user.
    """
    url = f"https://github.com/{owner}/{repo}.git"
    try:
        out = subprocess.run(
            ["git", "ls-remote", "--symref", url, "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if out.returncode != 0:
        return None
    # Last line is `<sha>\tHEAD`.
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1].strip() == "HEAD" and len(parts[0]) == 40:
            return parts[0]
    return None


def _clone_and_scan(owner: str, repo: str, sha: str) -> dict:
    """Shallow-clone the repo at `sha` and run the engine.

    Cache hit short-circuits via `_cached_scan`. Cloned tree is
    deleted as soon as the scan completes — no on-disk state beyond
    the JSON cache entry.
    """
    # Cache key includes the catalogue hash so a rule-pack ship
    # invalidates entries naturally — without the suffix, every release
    # required a manual `rm -rf /var/cache/tf-analyze/*` on Fly because
    # cached results would still be served against the new image.
    cache_key = f"{owner}_{repo}_{sha}__{CATALOG_HASH}.json" if CATALOG_HASH else f"{owner}_{repo}_{sha}.json"
    cache_file = CACHE_DIR / cache_key
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text())
        except json.JSONDecodeError:
            cache_file.unlink(missing_ok=True)

    url = f"https://github.com/{owner}/{repo}.git"
    with tempfile.TemporaryDirectory() as d:
        clone = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch",
             "--filter=blob:limit=1m", url, d],
            capture_output=True, text=True, timeout=60,
        )
        if clone.returncode != 0:
            raise HTTPException(status_code=404, detail="Could not clone repository")
        # Respect the cloned repo's `.tf-analyze.yaml:ignore_paths`. The
        # engine already skips these at scan time, so counting them
        # toward the cap blocks repos (like tf-analyze itself) that have
        # large `fixtures/` or `examples/` corpora but small production
        # surface. The cap now reflects what's actually scanned.
        clone_root = Path(d)
        ignore_paths = _load_ignore_paths(clone_root)
        # Quick size guard. Refuse to scan anything ridiculous.
        # Round-5 audit fix #18 — accumulate the file size DURING the
        # rglob iteration so the race window between "discover" and
        # "stat" is per-file, not per-glob. The previous shape was
        # already correct (the loop computes size as it iterates); the
        # only TOCTOU concern is files added mid-iteration that the
        # lazy rglob doesn't see. That isn't fixable without a snapshot
        # and is bounded by `MAX_TF_FILES` anyway, so the cap is safe.
        # A file deleted between iteration and stat raises OSError and
        # we skip it — already correct, documented here for clarity.
        total = 0
        tf_count = 0
        for p in clone_root.rglob("*.tf"):
            if ".terraform" in p.parts:
                continue
            try:
                rel = p.relative_to(clone_root)
            except ValueError:
                continue
            if _path_is_ignored(rel, ignore_paths):
                continue
            tf_count += 1
            if tf_count > MAX_TF_FILES:
                # Short-circuit: don't even bother stat()ing the rest.
                # The HTTPException below will fire on the count alone.
                break
            try:
                total += p.stat().st_size
            except OSError:
                continue
            if total > MAX_CLONE_BYTES:
                # Same short-circuit on byte cap — avoid additional
                # stat() calls once we're over.
                break
        if tf_count == 0:
            raise HTTPException(status_code=400, detail="No .tf files found in repository")
        if tf_count > MAX_TF_FILES:
            raise HTTPException(
                status_code=413,
                detail=f"Repository has {tf_count} .tf files; scanner caps at {MAX_TF_FILES}",
            )
        if total > MAX_CLONE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Repository content exceeds {MAX_CLONE_BYTES // (1024*1024)} MB cap",
            )
        result = _run_scan(d)

    # Tag the cached result with the metadata permalink visitors care about.
    result["_meta"] = {
        "owner": owner,
        "repo": repo,
        "sha": sha,
        "url": f"https://github.com/{owner}/{repo}/tree/{sha}",
        "scanned_at": int(time.time()),
        "tf_file_count": tf_count,
    }
    try:
        cache_file.write_text(json.dumps(result, default=str))
    except OSError:
        pass  # Best-effort cache write; never fail the request on this.
    return result


def _render_public_report(result: dict) -> str:
    """Render a styled, share-ready HTML permalink for a scan result."""
    meta = result.get("_meta", {})
    summary = result.get("summary", {})
    score = summary.get("score", 0)
    grade = summary.get("grade", "?")
    counts = summary.get("counts", {})
    findings = result.get("findings") or []
    explanation = result.get("score_explanation") or {}

    repo_label = html.escape(f"{meta.get('owner','?')}/{meta.get('repo','?')}")
    repo_url = html.escape(meta.get("url", "#"))
    sha_short = html.escape(meta.get("sha", "?")[:7])
    grade_color = {
        "A": "#1a7f37", "B": "#1f883d", "B-": "#3fb950",
        "C": "#bf8700", "D": "#bc4c00", "F": "#cf222e",
    }.get(grade, "#666")

    counts_html = " · ".join(
        f"<b>{counts.get(tier, 0)}</b> {tier}"
        for tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if counts.get(tier, 0)
    ) or "<b>0</b> issues at default tiers"

    # Sort by severity (CRITICAL → HIGH → MEDIUM → LOW → INFO) before slicing
    # to top-10, so the "Top findings" table actually shows the most-severe
    # findings rather than the first ten in detection order. Stable sort keeps
    # secondary detection order intact within each tier, which matters when
    # several findings share an urgency. The rank mirrors
    # `scripts/_output.py:URGENCY_RANK_ASCENDING` (single source of truth; the
    # engine pins this via tests, so drift would surface there first).
    _SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings_by_severity = sorted(
        findings, key=lambda f: _SEVERITY_RANK.get(f.get("urgency", ""), 99)
    )
    top_rows = []
    for f in findings_by_severity[:10]:
        rid = html.escape(f.get("id", "?"))
        loc = html.escape(f"{Path(f.get('file', '')).name}:{f.get('line', '?')}")
        urgency = html.escape(f.get("urgency", "?"))
        kev = "🔥 " if f.get("kev") else ""
        url = f"https://chrisadkin8.github.io/tf-analyze/rules/{rid}/"
        top_rows.append(
            f"<tr><td>{kev}<b style='color:{grade_color}'>{urgency}</b></td>"
            f"<td><a href='{url}'><code>{rid}</code></a></td>"
            f"<td><code>{loc}</code></td></tr>"
        )
    top_table = (
        "<table><thead><tr><th>Urgency</th><th>Rule</th><th>Location</th></tr></thead>"
        f"<tbody>{''.join(top_rows)}</tbody></table>" if top_rows else
        "<p style='color:#1a7f37'>✅ Clean — no findings at default scoring tiers.</p>"
    )

    explain_rows = []
    for row in (explanation.get("top") or [])[:5]:
        rid = html.escape(row["id"])
        url = f"https://chrisadkin8.github.io/tf-analyze/rules/{rid}/"
        explain_rows.append(
            f"<li>#{row['rank']} <a href='{url}'><code>{rid}</code></a> "
            f"({row['urgency']}) — fix to lift score to <b>{row['projected_score']}</b> ({row['projected_grade']})</li>"
        )
    explain_block = (
        f"<h3>Top fixes ranked by score impact</h3><ol>{''.join(explain_rows)}</ol>"
        if explain_rows else ""
    )

    # R30.18 — Blast-radius surface on the permalink. SRE/oncall persona
    # lands here from a Slack share and wants "what could one apply touch?"
    # in one glance. Heat-coloured bar; click on resource opens the
    # canonical attack-graph view (future enhancement).
    blast_top = result.get("blast_radius") or []
    blast_rows = []
    blast_max = max((r.get("blast_radius", 0) for r in blast_top), default=0)
    for r in blast_top[:5]:
        addr = html.escape(r.get("resource", "?"))
        radius = int(r.get("blast_radius") or 0)
        pct = round((radius / blast_max) * 100) if blast_max else 0
        flag_chips = []
        if r.get("is_crown_jewel"):
            flag_chips.append('<span style="background:#fef3c7;color:#92400e;padding:1px 6px;border-radius:3px;font-size:11px">crown jewel</span>')
        if r.get("internet_reachable"):
            flag_chips.append('<span style="background:#fee2e2;color:#991b1b;padding:1px 6px;border-radius:3px;font-size:11px">internet-reachable</span>')
        flags = " ".join(flag_chips)
        bar = (
            f'<div style="background:#eee;border-radius:3px;height:18px;width:120px;display:inline-block;vertical-align:middle;overflow:hidden">'
            f'<div style="background:linear-gradient(90deg,#fef3c7,#fb923c,#ef4444);height:100%;width:{pct}%"></div>'
            f'</div>'
        )
        blast_rows.append(
            f"<tr><td><code>{addr}</code></td>"
            f"<td style='text-align:right;font-weight:600'>{radius}</td>"
            f"<td>{bar}</td>"
            f"<td>{flags}</td></tr>"
        )
    blast_block = (
        '<section><h2>🌊 Blast radius — what one <code>terraform apply</code> could touch</h2>'
        '<p style="color:#555;font-size:14px;margin-bottom:8px">Resources whose destruction or recreation would cascade to the most dependents. Treat as high-care-on-apply.</p>'
        '<table><thead><tr><th>Resource</th><th style="text-align:right">Downstream</th><th>Impact</th><th>Flags</th></tr></thead>'
        f"<tbody>{''.join(blast_rows)}</tbody></table></section>"
        if blast_rows else ""
    )

    permalink = html.escape(f"https://tfanalyze.com/scan/{meta.get('owner','?')}/{meta.get('repo','?')}")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>tf-analyze · {repo_label}</title>
<meta name="description" content="Static + plan-time Terraform analysis report for {repo_label} at {sha_short}. Score {score} ({grade}).">
<meta property="og:title" content="tf-analyze · {repo_label} → {score} ({grade})">
<meta property="og:description" content="{counts_html.replace('<b>','').replace('</b>','')}">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary">
<link rel="canonical" href="{permalink}">
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#222;line-height:1.55;margin:0;background:#f6f8fa}}
header{{background:linear-gradient(135deg,#157878 0%,#0a4a4a 100%);color:#fff;padding:24px 0}}
.container{{max-width:920px;margin:0 auto;padding:0 20px}}
h1{{margin:0;font-size:22px;font-weight:600}}
h1 a{{color:#fff;text-decoration:none;opacity:0.9}}
.subtitle{{opacity:0.85;font-size:14px;margin-top:6px}}
.score-card{{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,0.06);padding:24px;margin:24px 0;display:flex;align-items:center;gap:24px}}
.score{{font-size:64px;font-weight:700;color:{grade_color};line-height:1}}
.grade{{font-size:24px;color:{grade_color};font-weight:600;margin-left:8px}}
.counts{{font-size:14px;color:#555}}
.counts b{{color:#222}}
section{{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,0.06);padding:20px;margin-bottom:18px}}
section h2,section h3{{margin-top:0;color:#157878}}
table{{width:100%;border-collapse:collapse;margin-top:6px;font-size:14px}}
th,td{{text-align:left;padding:8px 6px;border-bottom:1px solid #eee}}
th{{background:#157878;color:#fff;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}}
code{{background:#f3f4f6;padding:1px 5px;border-radius:3px;font-family:'SF Mono',Consolas,monospace;font-size:13px}}
a{{color:#157878}}
.cta{{background:#f6f8fa;border:1px solid #d1d9e0;border-radius:6px;padding:12px;margin-top:14px;font-size:13px}}
.cta code{{background:#fff}}
footer{{font-size:12px;color:#888;text-align:center;padding:18px 0}}
</style></head>
<body>
<header><div class="container">
<h1><a href="/">tf-analyze</a> · <a href="{repo_url}" style="color:#fff">{repo_label}</a></h1>
<div class="subtitle">commit <code style="color:#fff;background:rgba(255,255,255,0.15)">{sha_short}</code> · {meta.get('tf_file_count','?')} .tf files</div>
</div></header>

<div class="container">
<div class="score-card">
<div>
<div><span class="score">{score}</span><span class="grade">({grade})</span></div>
<div class="counts">{counts_html}</div>
</div>
</div>

<section>
<h2>Top findings</h2>
{top_table}
</section>

{f'<section>{explain_block}</section>' if explain_block else ''}

{blast_block}

<section>
<h3>Run locally</h3>
<div class="cta">
<code>docker run --rm -v "$(pwd):/workspace" ghcr.io/chrisadkin8/tf-analyze --target /workspace --format text --attack-graph</code>
</div>
<div class="cta">Or paste a snippet at <a href="/">tfanalyze.com</a>. The full rule catalogue lives at <a href="https://chrisadkin8.github.io/tf-analyze/rules/">chrisadkin8.github.io/tf-analyze/rules</a>.</div>
</section>

<footer>
🛡 Powered by <a href="https://github.com/ChrisAdkin8/tf-analyze">tf-analyze</a> · deterministic IaC analysis · permalink: <code>{permalink}</code>
</footer>
</div>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (Path(__file__).parent / "index.html").read_text()


@app.get("/scan/{owner}/{repo}.json")
async def scan_public_json(owner: str, repo: str, request: Request) -> JSONResponse:
    """JSON form of the public permalink — same caching, machine-friendly.

    Declared **before** the HTML route because FastAPI matches in
    declaration order; without this, ``/scan/foo/bar.json`` is captured
    by the HTML handler with ``repo="bar.json"``.

    Useful for embedding in dashboards or for badge services that want
    the raw score without parsing HTML.
    """
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded (10 req/min)")
    if not _OWNER_RE.match(owner) or not _REPO_RE.match(repo):
        raise HTTPException(status_code=400, detail="Invalid owner/repo characters")
    repo = repo.removesuffix(".git")
    sha = _resolve_head_sha(owner, repo)
    if sha is None:
        raise HTTPException(status_code=404, detail="repo not found")
    return JSONResponse(_clone_and_scan(owner, repo, sha))


@app.get("/scan/{owner}/{repo}", response_class=HTMLResponse)
async def scan_public(owner: str, repo: str, request: Request):
    """Public scanner permalink (R30.14).

    Example: ``/scan/terraform-aws-modules/terraform-aws-vpc``.
    Resolves the default branch HEAD, scans, and returns a styled
    HTML page. Cached by commit SHA, so a stranger linking the URL
    serves a pre-computed report instantly.
    """
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded (10 req/min)")
    if not _OWNER_RE.match(owner) or not _REPO_RE.match(repo):
        raise HTTPException(status_code=400, detail="Invalid owner/repo characters")
    repo = repo.removesuffix(".git")
    sha = _resolve_head_sha(owner, repo)
    if sha is None:
        raise HTTPException(
            status_code=404,
            detail=f"Could not resolve HEAD for github.com/{owner}/{repo}",
        )
    result = _clone_and_scan(owner, repo, sha)
    return HTMLResponse(_render_public_report(result))


# ---------------------------------------------------------------------------
# Badge — GET /badge/{owner}/{repo}.svg
# ---------------------------------------------------------------------------


# Headers shared by every badge response. 5-minute Cache-Control is what
# GitHub's camo image proxy and Cloudflare's edge cache respect — short
# enough that post-merge score changes propagate within a sprint stand-up,
# long enough that a viral README doesn't melt the backend.
_BADGE_HEADERS = {
    "Cache-Control": "public, max-age=300, s-maxage=300",
    # Defense in depth — the badge content is server-rendered text-only,
    # but pin CSP so a future change can't accidentally ship inline scripts.
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
    "X-Content-Type-Options": "nosniff",
}


def _latest_cached_scan(owner: str, repo: str) -> dict | None:
    """Return the parsed JSON of the most-recent cached scan for this
    repo, or None if no cache entry exists.

    Cache files are named ``{owner}_{repo}_{sha}.json`` per
    ``_clone_and_scan``; we pick the newest mtime so badges always
    reflect the most-recent scan (which in turn reflects the most-recent
    visit to ``/scan/<owner>/<repo>``).
    """
    matches = list(CACHE_DIR.glob(f"{owner}_{repo}_*.json"))
    if not matches:
        return None
    latest = max(matches, key=lambda p: p.stat().st_mtime)
    try:
        return json.loads(latest.read_text())
    except (json.JSONDecodeError, OSError):
        return None


@app.get("/badge/{owner}/{repo}.svg")
async def badge(owner: str, repo: str, label: str = "tf-analyze") -> Response:
    """Score badge for a repo's most-recent cached scan.

    No per-IP rate limit — GitHub's camo proxy fans out badge requests
    through a small IP pool, so per-IP limits would break popular
    READMEs. The cache-hit path is parse-and-render (sub-ms);
    cache-miss is a fixed-cost "no data" placeholder.

    Stale scores update the next time someone visits the matching
    ``/scan/<owner>/<repo>`` permalink — README authors typically wrap
    the badge in a link to that URL to keep the cache warm.
    """
    if not _OWNER_RE.match(owner) or not _REPO_RE.match(repo):
        raise HTTPException(status_code=400, detail="Invalid owner/repo characters")
    repo = repo.removesuffix(".git")
    label = label[:32]  # bound the user-controlled bit before rendering

    result = _latest_cached_scan(owner, repo)
    if result is not None:
        summary = result.get("summary") or {}
        score = summary.get("score")
        grade = summary.get("grade")
        if isinstance(score, int) and isinstance(grade, str):
            svg = render_badge_svg(label, score, grade)
            return Response(content=svg, media_type="image/svg+xml", headers=_BADGE_HEADERS)

    svg = render_unknown_badge(label)
    return Response(content=svg, media_type="image/svg+xml", headers=_BADGE_HEADERS)


@app.post("/scan/hcl")
async def scan_hcl(body: ScanHcl, request: Request) -> dict:
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded (10 req/min)")
    if len(body.hcl) > 50_000:
        raise HTTPException(status_code=400, detail="HCL too large (max 50 KB)")
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "main.tf").write_text(body.hcl)
        return _run_scan(d)


@app.post("/scan/repo")
async def scan_repo(body: ScanRepo, request: Request) -> dict:
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded (10 req/min)")
    url = body.repo.strip()
    if not re.match(r"https://(github|gitlab)\.com/[\w.\-]+/[\w.\-]+(\.git)?$", url):
        raise HTTPException(status_code=400, detail="Only github.com and gitlab.com repos are supported")
    with tempfile.TemporaryDirectory() as d:
        clone = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", url, d],
            capture_output=True,
            timeout=30,
        )
        if clone.returncode != 0:
            raise HTTPException(status_code=400, detail="Could not clone repository")
        return _run_scan(d)


# ---------------------------------------------------------------------------
# Trend dashboard — GET /trend/{owner}/{repo}  (R31.4)
# ---------------------------------------------------------------------------
# The engine already emits per-commit new/resolved/net deltas via
# `--mode trend --lookback N` (see scripts/_modes.py:run_trend). Until R31.4
# that data lived only in CLI output. This route renders it as a styled HTML
# page so a permalink at /trend/<owner>/<repo> is shareable the same way
# /scan/<owner>/<repo> is.
#
# Caching: per-(owner, repo, HEAD-sha, lookback) — keyed on the HEAD SHA
# so each commit gets a fresh trend without re-walking history for every
# visit. File name shape mirrors the scan cache: ``trend-{owner}_{repo}_{sha}_{lookback}.json``.

MAX_TREND_LOOKBACK_DAYS = 365  # cap on `?lookback=` query param
DEFAULT_TREND_LOOKBACK_DAYS = 90


def _resolve_trend_lookback(raw: str | None) -> int:
    """Validate `?lookback=N` query param.

    Defaults to 90 days. Clamped to ``[7, 365]`` so a runaway request
    can't ask for 10 years of history (would dominate the worker).
    Falls back to default on any parse failure rather than 400'ing —
    the dashboard is for casual sharing, not API rigour.
    """
    if not raw:
        return DEFAULT_TREND_LOOKBACK_DAYS
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_TREND_LOOKBACK_DAYS
    return max(7, min(MAX_TREND_LOOKBACK_DAYS, n))


def _clone_and_trend(owner: str, repo: str, sha: str, lookback_days: int) -> dict:
    """Clone the repo at ``sha`` (full history) and run ``--mode trend``.

    Unlike ``_clone_and_scan`` which uses ``--depth 1`` (one commit's
    files), trend mode walks git log — so we need full history. Clones
    *with* tag/branch refs intact via ``--no-single-branch`` but still
    depth-limited to ``lookback_days * 2`` commits as a guard (most
    repos under a year of work fit comfortably under this).

    Cache hit returns immediately. Cache key includes ``lookback_days``
    so changing the window doesn't serve a stale narrower result.
    """
    cache_file = CACHE_DIR / f"trend-{owner}_{repo}_{sha}_{lookback_days}.json"
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text())
        except json.JSONDecodeError:
            cache_file.unlink(missing_ok=True)

    url = f"https://github.com/{owner}/{repo}.git"
    # Heuristic commit cap: 5 commits/day average ceiling. Most repos sit
    # well below 1 commit/day so this is generous. Hard floor of 200 so
    # very-quiet repos still see history.
    commit_cap = max(200, lookback_days * 5)
    with tempfile.TemporaryDirectory() as d:
        clone = subprocess.run(
            ["git", "clone", f"--depth={commit_cap}", "--no-single-branch",
             "--filter=blob:limit=1m", url, d],
            capture_output=True, text=True, timeout=120,
        )
        if clone.returncode != 0:
            raise HTTPException(status_code=404, detail="Could not clone repository")

        proc = subprocess.run(
            [
                "python3", str(DETECT),
                "--target", d,
                "--catalog", str(CATALOG),
                "--mode", "trend",
                "--lookback", str(lookback_days),
                "--format", "json",
            ],
            capture_output=True, text=True,
            timeout=300,  # trend can be slow on long histories
        )
        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Trend scan failed: {proc.stderr.strip()[:200]}",
            )
        try:
            rows = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=500,
                detail="Trend scan emitted unparseable JSON",
            )
    if not isinstance(rows, list):
        rows = []

    result = {
        "rows": rows,
        "_meta": {
            "owner": owner,
            "repo": repo,
            "sha": sha,
            "lookback_days": lookback_days,
            "url": f"https://github.com/{owner}/{repo}",
            "scanned_at": int(time.time()),
            "commits_analysed": len(rows),
        },
    }
    try:
        cache_file.write_text(json.dumps(result, default=str))
    except OSError:
        pass
    return result


def _trend_summary(rows: list[dict]) -> dict:
    """Aggregate stats from a trend row list for the headline / OG card."""
    if not rows:
        return {
            "total_new": 0, "total_resolved": 0, "net": 0,
            "first_total": 0, "last_total": 0, "biggest_jump": None,
        }
    total_new = sum(r["new"] for r in rows)
    total_res = sum(r["resolved"] for r in rows)
    net = total_new - total_res
    first_total = rows[0]["total"]
    last_total = rows[-1]["total"]
    # Biggest absolute-net row (one commit that moved the needle hardest).
    biggest = max(rows, key=lambda r: abs(r["net"])) if rows else None
    return {
        "total_new": total_new,
        "total_resolved": total_res,
        "net": net,
        "first_total": first_total,
        "last_total": last_total,
        "biggest_jump": biggest,
    }


def _trend_sparkline_svg(rows: list[dict], *, width: int = 900, height: int = 160) -> str:
    """Inline SVG sparkline of the ``total`` curve across commits.

    No external dependencies — plain SVG `<path>`. Trend over time of
    "how many findings exist at this commit", linearly mapped to canvas.
    Bigger area = more findings; downward slope = good.
    """
    if not rows:
        return f'<svg width="{width}" height="{height}"></svg>'
    totals = [r["total"] for r in rows]
    lo = min(totals)
    hi = max(totals) or 1
    span = hi - lo or 1
    n = len(rows)

    def x_at(i: int) -> float:
        return 20 + (width - 40) * (i / max(1, n - 1))

    def y_at(v: int) -> float:
        # Invert y so higher findings → lower on screen.
        return height - 30 - (height - 60) * ((v - lo) / span)

    points = " ".join(f"{x_at(i):.1f},{y_at(t):.1f}" for i, t in enumerate(totals))
    # Area fill underneath the line for the "weight of debt" visual.
    area_points = f"{x_at(0):.1f},{height - 30:.1f} {points} {x_at(n - 1):.1f},{height - 30:.1f}"
    # X-axis labels: first + last commit dates, plus midpoint.
    label_first = html.escape(rows[0]["date"])
    label_last = html.escape(rows[-1]["date"])
    label_mid = html.escape(rows[n // 2]["date"]) if n >= 3 else ""
    return (
        f'<svg viewBox="0 0 {width} {height}" preserveAspectRatio="none" '
        f'style="width:100%;max-width:{width}px;height:{height}px">'
        f'<polygon points="{area_points}" fill="#7B42BC" opacity="0.15"/>'
        f'<polyline points="{points}" fill="none" stroke="#7B42BC" stroke-width="2.5"/>'
        f'<text x="20" y="{height - 8}" font-size="11" fill="#8B949E">{label_first}</text>'
        + (f'<text x="{width / 2:.0f}" y="{height - 8}" font-size="11" '
           f'fill="#8B949E" text-anchor="middle">{label_mid}</text>' if label_mid else "")
        + f'<text x="{width - 20}" y="{height - 8}" font-size="11" '
        f'fill="#8B949E" text-anchor="end">{label_last}</text>'
        f'<text x="20" y="14" font-size="11" fill="#8B949E">{hi} max</text>'
        f'<text x="20" y="{height - 32:.0f}" font-size="11" fill="#8B949E">{lo} min</text>'
        f'</svg>'
    )


def _trend_velocity_table(rows: list[dict]) -> str:
    """Markdown-ish HTML table of per-commit new/resolved/net.

    Sorted oldest-first so the eye-trail matches the sparkline.
    """
    if not rows:
        return "<p>No commits touching .tf files in the analysed window.</p>"
    out = [
        "<table><thead><tr>"
        "<th>Date</th><th>SHA</th><th>New</th><th>Resolved</th>"
        "<th>Net</th><th>Total</th></tr></thead><tbody>"
    ]
    for r in rows:
        sha = html.escape(r["sha"])
        net = r["net"]
        net_str = f"+{net}" if net > 0 else str(net)
        net_color = "#cf222e" if net > 0 else ("#1a7f37" if net < 0 else "#666")
        out.append(
            f"<tr><td>{html.escape(r['date'])}</td>"
            f"<td><code>{sha}</code></td>"
            f"<td style='color:#cf222e'>+{r['new']}</td>"
            f"<td style='color:#1a7f37'>-{r['resolved']}</td>"
            f"<td style='color:{net_color}'><b>{net_str}</b></td>"
            f"<td>{r['total']}</td></tr>"
        )
    out.append("</tbody></table>")
    return "".join(out)


def _render_trend_report(result: dict) -> str:
    """Render a styled HTML trend page — sparkline + velocity table + OG card."""
    meta = result.get("_meta", {})
    rows = result.get("rows") or []
    summary = _trend_summary(rows)
    repo_label = html.escape(f"{meta.get('owner','?')}/{meta.get('repo','?')}")
    repo_url = html.escape(meta.get("url", "#"))
    lookback = meta.get("lookback_days", DEFAULT_TREND_LOOKBACK_DAYS)
    n_commits = summary and len(rows)
    net = summary["net"]
    net_str = f"+{net}" if net > 0 else str(net)
    # OG title is the share-bait: surface the headline number a Slack/Twitter
    # preview card will show. Phrased to be honest in either direction.
    if net < 0:
        og_headline = f"tf-analyze trend: {abs(net)} findings resolved over {lookback} days"
    elif net > 0:
        og_headline = f"tf-analyze trend: {net} findings introduced over {lookback} days"
    else:
        og_headline = f"tf-analyze trend: net-zero across {n_commits} commits ({lookback} days)"
    og_title = html.escape(f"{repo_label} — {og_headline}")
    og_desc = html.escape(
        f"{summary['total_new']} introduced · {summary['total_resolved']} resolved · "
        f"{n_commits} commits analysed"
    )
    sparkline = _trend_sparkline_svg(rows)
    velocity = _trend_velocity_table(rows)
    biggest = summary["biggest_jump"]
    biggest_html = ""
    if biggest:
        sha_short = html.escape(biggest["sha"])
        date = html.escape(biggest["date"])
        b_net = biggest["net"]
        b_net_str = f"+{b_net}" if b_net > 0 else str(b_net)
        biggest_html = (
            f"<p class='meta'>Biggest single-commit jump: "
            f"<code>{sha_short}</code> on {date} "
            f"({b_net_str} net findings).</p>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{og_title}</title>
<meta property="og:title" content="{og_title}">
<meta property="og:description" content="{og_desc}">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 980px;
          margin: 2rem auto; padding: 0 1rem; color: #1f2328; background: #fff; }}
  h1 {{ margin: 0 0 0.5rem; font-size: 1.6rem; }}
  h2 {{ font-size: 1.15rem; margin: 2rem 0 0.5rem; }}
  .headline {{ font-size: 2.2rem; margin: 0.5rem 0; font-weight: 700; }}
  .headline.up   {{ color: #cf222e; }}
  .headline.down {{ color: #1a7f37; }}
  .headline.flat {{ color: #57606a; }}
  .meta {{ color: #57606a; font-size: 0.92rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.92rem; }}
  th, td {{ text-align: left; padding: 0.35rem 0.55rem; border-bottom: 1px solid #d0d7de; }}
  th {{ background: #f6f8fa; font-weight: 600; }}
  code {{ background: #f6f8fa; padding: 0.1em 0.3em; border-radius: 3px; font-size: 0.9em; }}
  .footer {{ margin-top: 3rem; color: #8b949e; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>{repo_label} — risk trend</h1>
<p class='meta'><a href='{repo_url}'>{repo_url}</a> · {lookback}-day window · {n_commits} commits analysed</p>
<div class='headline {"up" if net > 0 else "down" if net < 0 else "flat"}'>{net_str} net findings</div>
<p class='meta'>{summary['total_new']} introduced · {summary['total_resolved']} resolved.
Started at {summary['first_total']} findings, ended at {summary['last_total']}.</p>
<h2>Total findings over time</h2>
{sparkline}
{biggest_html}
<h2>Per-commit velocity</h2>
{velocity}
<div class='footer'>
  Generated by <a href='https://github.com/ChrisAdkin8/tf-analyze'>tf-analyze</a>
  · See also: <a href='/scan/{html.escape(meta.get('owner','?'))}/{html.escape(meta.get('repo','?'))}'>current scan</a>
</div>
</body>
</html>"""


@app.get("/trend/{owner}/{repo}.json")
async def trend_public_json(owner: str, repo: str, request: Request,
                            lookback: str | None = None) -> JSONResponse:
    """JSON form of the trend permalink — same caching, machine-friendly.

    Declared **before** the HTML route so FastAPI matches it first (the
    HTML route would otherwise capture ``/trend/foo/bar.json`` with
    ``repo="bar.json"`` — same pattern as the scan routes above).
    """
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded (10 req/min)")
    if not _OWNER_RE.match(owner) or not _REPO_RE.match(repo):
        raise HTTPException(status_code=400, detail="Invalid owner/repo characters")
    repo = repo.removesuffix(".git")
    lookback_days = _resolve_trend_lookback(lookback)
    sha = _resolve_head_sha(owner, repo)
    if sha is None:
        raise HTTPException(status_code=404, detail="repo not found")
    return JSONResponse(_clone_and_trend(owner, repo, sha, lookback_days))


@app.get("/trend/{owner}/{repo}", response_class=HTMLResponse)
async def trend_public(owner: str, repo: str, request: Request,
                       lookback: str | None = None):
    """Public trend-dashboard permalink (R31.4).

    Example: ``/trend/terraform-aws-modules/terraform-aws-vpc?lookback=180``.
    Resolves HEAD, clones the full-history view, walks per-commit new/
    resolved/net findings, and renders a styled HTML page with a
    sparkline + velocity table + OG card.
    """
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded (10 req/min)")
    if not _OWNER_RE.match(owner) or not _REPO_RE.match(repo):
        raise HTTPException(status_code=400, detail="Invalid owner/repo characters")
    repo = repo.removesuffix(".git")
    lookback_days = _resolve_trend_lookback(lookback)
    sha = _resolve_head_sha(owner, repo)
    if sha is None:
        raise HTTPException(
            status_code=404,
            detail=f"Could not resolve HEAD for github.com/{owner}/{repo}",
        )
    result = _clone_and_trend(owner, repo, sha, lookback_days)
    return HTMLResponse(_render_trend_report(result))


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "cache_dir": str(CACHE_DIR)}
