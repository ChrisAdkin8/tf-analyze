"""Tests for the unified ``/badge/<owner>/<repo>.svg`` route.

The badge lives at the same Fly app as the public scanner — there is
no separate badge service after R30.15. Tests use ``TestClient`` and
write fake cache entries to a tmp dir rather than spinning up the
engine; the cache-file naming contract is the integration point.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from helpers import REPO_ROOT


fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # type: ignore

sys.path.insert(0, str(REPO_ROOT / "demo"))


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    """Spin up the demo app with the cache dir pointed at tmp_path."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setenv("TFA_SCAN_CACHE_DIR", str(cache_dir))
    sys.modules.pop("app", None)
    import importlib
    import app as demo_app  # type: ignore
    importlib.reload(demo_app)
    demo_app._rate.clear()
    return TestClient(demo_app.app), cache_dir


def _write_cache(cache_dir: Path, owner: str, repo: str, sha: str, score: int, grade: str) -> None:
    """Drop a minimally-valid scan JSON into the volume cache."""
    entry = {
        "summary": {"score": score, "grade": grade, "counts": {}},
        "findings": [],
        "_meta": {"owner": owner, "repo": repo, "sha": sha},
    }
    (cache_dir / f"{owner}_{repo}_{sha}.json").write_text(json.dumps(entry))


# ---------------------------------------------------------------------------
# Cache-hit rendering
# ---------------------------------------------------------------------------


def test_badge_renders_score_from_cache(client) -> None:
    c, cache_dir = client
    _write_cache(cache_dir, "ChrisAdkin8", "tf-analyze", "a" * 40, 87, "B")
    r = c.get("/badge/ChrisAdkin8/tf-analyze.svg")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/svg+xml")
    assert "87 (B)" in r.text
    assert "tf-analyze" in r.text


def test_badge_picks_most_recent_cache_entry(client) -> None:
    """Two scans for the same repo: the badge reflects the newer one."""
    c, cache_dir = client
    _write_cache(cache_dir, "owner", "repo", "a" * 40, 60, "D")
    # mtime ordering — write the newer one second
    import time
    time.sleep(0.01)
    _write_cache(cache_dir, "owner", "repo", "b" * 40, 95, "A")
    r = c.get("/badge/owner/repo.svg")
    assert r.status_code == 200
    assert "95 (A)" in r.text
    assert "60 (D)" not in r.text


def test_badge_label_query_override(client) -> None:
    c, cache_dir = client
    _write_cache(cache_dir, "owner", "repo", "a" * 40, 87, "B")
    r = c.get("/badge/owner/repo.svg?label=security")
    assert r.status_code == 200
    assert "security" in r.text
    assert "87 (B)" in r.text


def test_badge_label_length_capped(client) -> None:
    """Server-side cap stops a runaway label from breaking the SVG layout."""
    c, cache_dir = client
    _write_cache(cache_dir, "owner", "repo", "a" * 40, 87, "B")
    r = c.get("/badge/owner/repo.svg?label=" + "x" * 200)
    assert r.status_code == 200
    # 32-char cap from app.py — anything beyond that is truncated
    assert "x" * 32 in r.text
    assert "x" * 33 not in r.text


# ---------------------------------------------------------------------------
# Cache-miss → unknown badge
# ---------------------------------------------------------------------------


def test_badge_unknown_for_never_scanned_repo(client) -> None:
    c, _cache_dir = client
    r = c.get("/badge/never/scanned.svg")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/svg+xml")
    assert "no data" in r.text


def test_badge_unknown_when_cache_corrupt(client, tmp_path: Path) -> None:
    """A garbage JSON file shouldn't 500; falls through to the unknown badge."""
    c, cache_dir = client
    (cache_dir / "owner_repo_aaaa.json").write_text("{not json")
    r = c.get("/badge/owner/repo.svg")
    assert r.status_code == 200
    assert "no data" in r.text


def test_badge_unknown_when_summary_missing(client) -> None:
    """Cache file exists but lacks summary.score — fall through, don't 500."""
    c, cache_dir = client
    (cache_dir / "owner_repo_aaaa.json").write_text(json.dumps({"findings": []}))
    r = c.get("/badge/owner/repo.svg")
    assert r.status_code == 200
    assert "no data" in r.text


# ---------------------------------------------------------------------------
# Validation + headers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("owner,repo", [
    ("../etc", "repo"),
    ("owner", "../passwd"),
    ("", "repo"),
    ("owner", ""),
    ("has space", "repo"),
])
def test_badge_rejects_invalid_owner_or_repo(client, owner: str, repo: str) -> None:
    c, _ = client
    r = c.get(f"/badge/{owner}/{repo}.svg")
    assert r.status_code in (400, 404)  # 404 if FastAPI rejects the path itself


def test_badge_strips_dot_git_suffix(client) -> None:
    """`/badge/owner/repo.git.svg` should resolve to `owner/repo`."""
    c, cache_dir = client
    _write_cache(cache_dir, "owner", "repo", "a" * 40, 87, "B")
    r = c.get("/badge/owner/repo.git.svg")
    assert r.status_code == 200
    assert "87 (B)" in r.text


def test_badge_cache_control_header(client) -> None:
    c, cache_dir = client
    _write_cache(cache_dir, "owner", "repo", "a" * 40, 87, "B")
    r = c.get("/badge/owner/repo.svg")
    assert r.headers["cache-control"] == "public, max-age=300, s-maxage=300"


def test_badge_security_headers(client) -> None:
    c, cache_dir = client
    _write_cache(cache_dir, "owner", "repo", "a" * 40, 87, "B")
    r = c.get("/badge/owner/repo.svg")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in r.headers["content-security-policy"]


def test_badge_not_rate_limited(client) -> None:
    """The /scan/hcl route caps at 10 req/min. /badge should not — camo
    proxies would burn the budget instantly on a popular README."""
    c, cache_dir = client
    _write_cache(cache_dir, "owner", "repo", "a" * 40, 87, "B")
    for _ in range(20):
        r = c.get("/badge/owner/repo.svg")
        assert r.status_code == 200, r.status_code


# ---------------------------------------------------------------------------
# Unit tests on the renderer (no FastAPI)
# ---------------------------------------------------------------------------


def test_render_badge_svg_grade_palette() -> None:
    from _badge import render_badge_svg
    a_svg = render_badge_svg("tf-analyze", 95, "A")
    f_svg = render_badge_svg("tf-analyze", 12, "F")
    assert "#4c1" in a_svg     # bright green for A
    assert "#e05d44" in f_svg  # red for F


def test_render_badge_svg_handles_unknown_grade() -> None:
    """An unrecognised grade falls back to the neutral grey palette."""
    from _badge import render_badge_svg
    svg = render_badge_svg("tf-analyze", 50, "Z")
    assert "#9f9f9f" in svg  # grey fallback
