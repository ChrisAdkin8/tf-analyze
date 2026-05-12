"""Tests for the public web scanner (R30.14 — `tfanalyze.com/scan/<owner>/<repo>`).

Exercises the FastAPI app via `TestClient` rather than a real subprocess.
External `git ls-remote` / `git clone` calls are monkey-patched so CI
runs are hermetic and offline-safe.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from helpers import REPO_ROOT


fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # type: ignore

sys.path.insert(0, str(REPO_ROOT / "demo"))


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    """Spin up the demo app with the cache dir pointed at tmp_path."""
    monkeypatch.setenv("TFA_SCAN_CACHE_DIR", str(tmp_path / "cache"))
    # Re-import the module each test so the module-level CACHE_DIR
    # is recomputed against the patched env.
    sys.modules.pop("app", None)
    import importlib
    import app as demo_app  # type: ignore
    importlib.reload(demo_app)
    # Clear the rate-limit dict between tests.
    demo_app._rate.clear()
    return TestClient(demo_app.app)


def _fake_resolve_head(*_args, **_kwargs):
    return "a" * 40  # 40-char SHA


def _fake_clone_and_scan(owner: str, repo: str, sha: str):
    return {
        "summary": {
            "score": 87,
            "grade": "B",
            "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0, "INFO": 0},
            "suppressed_count": 0,
            "formula": "...",
        },
        "findings": [
            {
                "id": "SEC-AWS-S3-001",
                "file": "main.tf",
                "line": 12,
                "resource": "aws_s3_bucket.demo",
                "urgency": "HIGH",
                "kev": True,
            },
        ],
        "score_explanation": {
            "base_score": 87, "base_grade": "B",
            "perfect_score": 94, "perfect_grade": "A",
            "top": [
                {"rank": 1, "id": "SEC-AWS-S3-001", "urgency": "HIGH",
                 "weight": 7, "projected_score": 94, "projected_grade": "A"},
            ],
        },
        "_meta": {
            "owner": owner, "repo": repo, "sha": sha,
            "url": f"https://github.com/{owner}/{repo}/tree/{sha}",
            "scanned_at": 0, "tf_file_count": 3,
        },
    }


class TestPublicPermalink:
    def test_html_permalink_returns_styled_report(self, client) -> None:
        with patch("app._resolve_head_sha", _fake_resolve_head), \
             patch("app._clone_and_scan", _fake_clone_and_scan):
            r = client.get("/scan/terraform-aws-modules/terraform-aws-vpc")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        body = r.text
        # Score + grade prominent.
        assert "87" in body
        assert ">(B)<" in body or "(B)" in body
        # Finding ID + KEV badge present.
        assert "SEC-AWS-S3-001" in body
        assert "🔥" in body
        # Open Graph card.
        assert 'property="og:title"' in body
        # Canonical URL points back at tfanalyze.com.
        assert 'rel="canonical"' in body

    def test_json_permalink_returns_full_scan(self, client) -> None:
        with patch("app._resolve_head_sha", _fake_resolve_head), \
             patch("app._clone_and_scan", _fake_clone_and_scan):
            r = client.get("/scan/foo/bar.json")
        assert r.status_code == 200
        data = r.json()
        assert data["summary"]["score"] == 87
        assert data["_meta"]["owner"] == "foo"
        assert data["_meta"]["repo"] == "bar"

    def test_404_when_repo_does_not_exist(self, client) -> None:
        with patch("app._resolve_head_sha", lambda *a, **k: None):
            r = client.get("/scan/nonexistent/nonexistent")
        assert r.status_code == 404

    def test_invalid_owner_rejected(self, client) -> None:
        # Owner with `..` (path-traversal attempt) must be rejected at
        # the regex layer, never reaching the cloner.
        r = client.get("/scan/..%2Fetc/passwd")
        assert r.status_code in (400, 404)

    def test_rate_limit_kicks_in(self, client) -> None:
        with patch("app._resolve_head_sha", _fake_resolve_head), \
             patch("app._clone_and_scan", _fake_clone_and_scan):
            # 10 fast requests should succeed; the 11th hits the limit.
            for _ in range(10):
                assert client.get("/scan/foo/bar").status_code == 200
            limited = client.get("/scan/foo/bar")
            assert limited.status_code == 429


class TestCacheBehaviour:
    def test_second_visit_to_same_sha_is_cache_hit(
        self, client, tmp_path: Path, monkeypatch,
    ) -> None:
        """The second request must NOT re-clone. Verify by counting how
        many times the (mocked) cloner runs."""
        import app as demo_app  # type: ignore
        sha = "b" * 40
        call_count = {"n": 0}

        def _resolver(*a, **k):
            return sha

        # Real-shape `_clone_and_scan` writes the cache file; mock just
        # the subprocess call inside it so we can count clones.
        def _stub_subprocess_run(args, **kwargs):
            # Match the git-clone invocation: ["git", "clone", ...]
            if args and args[0] == "git" and args[1] == "clone":
                call_count["n"] += 1
                # Create a fake repo with one .tf file so the size guards pass.
                dest = args[-1]
                Path(dest).mkdir(exist_ok=True)
                (Path(dest) / "main.tf").write_text(
                    'resource "null_resource" "x" {}\n'
                )
                return subprocess.CompletedProcess(args, 0, "", "")
            # The python detect.py run.
            return subprocess.CompletedProcess(
                args, 0, json.dumps({
                    "summary": {"score": 100, "grade": "A",
                                "counts": {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
                                "suppressed_count": 0, "formula": ""},
                    "findings": [],
                }), "",
            )

        with patch("app._resolve_head_sha", _resolver), \
             patch("app.subprocess.run", _stub_subprocess_run):
            r1 = client.get("/scan/owner/repo.json")
            r2 = client.get("/scan/owner/repo.json")
        assert r1.status_code == 200 and r2.status_code == 200
        # Both responses share the same SHA — cache hit on the second.
        assert call_count["n"] == 1, (
            f"expected 1 clone (cache miss + hit), got {call_count['n']}"
        )


class TestHealth:
    def test_healthz(self, client) -> None:
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestFindingOrder:
    def test_top_findings_sorted_critical_first(self) -> None:
        """`_render_public_report` must order the Top-findings table from
        most-severe to least, regardless of the engine's emission order.
        Detection order is roughly file-walk order, so without this sort
        a HIGH finding could be hidden below ten LOWs.
        """
        import app as demo_app  # type: ignore
        # Mixed-severity scan result with the most-severe items emitted
        # last on purpose, to prove the renderer sorts them up.
        result = {
            "_meta": {"owner": "x", "repo": "y", "url": "u", "sha": "0" * 40},
            "summary": {
                "score": 50, "grade": "C",
                "counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 0},
            },
            "findings": [
                {"id": "LOW-1", "urgency": "LOW", "file": "a.tf", "line": 1},
                {"id": "MED-1", "urgency": "MEDIUM", "file": "b.tf", "line": 2},
                {"id": "HIGH-1", "urgency": "HIGH", "file": "c.tf", "line": 3},
                {"id": "CRIT-1", "urgency": "CRITICAL", "file": "d.tf", "line": 4},
            ],
        }
        html_out = demo_app._render_public_report(result)
        # The table renders one row per finding; the row text contains the
        # rule id. Assert their order in the HTML matches severity-desc.
        order = []
        for rid in ("CRIT-1", "HIGH-1", "MED-1", "LOW-1"):
            idx = html_out.find(rid)
            assert idx != -1, f"missing finding {rid} in rendered HTML"
            order.append((idx, rid))
        sorted_by_position = [rid for _, rid in sorted(order)]
        assert sorted_by_position == ["CRIT-1", "HIGH-1", "MED-1", "LOW-1"], (
            f"findings appeared in {sorted_by_position}, expected severity-desc"
        )

    def test_stable_within_tier(self) -> None:
        """Two LOW findings should appear in detection order (stable sort).
        Important when several findings share an urgency — the engine's
        emission order matches file/line position, which is the user's
        mental model."""
        import app as demo_app  # type: ignore
        result = {
            "_meta": {"owner": "x", "repo": "y", "url": "u", "sha": "0" * 40},
            "summary": {
                "score": 99, "grade": "A",
                "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 2, "INFO": 0},
            },
            "findings": [
                {"id": "LOW-FIRST", "urgency": "LOW", "file": "a.tf", "line": 1},
                {"id": "LOW-SECOND", "urgency": "LOW", "file": "a.tf", "line": 9},
            ],
        }
        html_out = demo_app._render_public_report(result)
        assert html_out.find("LOW-FIRST") < html_out.find("LOW-SECOND"), (
            "stable sort within a tier was lost — detection order should be preserved"
        )


# ---------------------------------------------------------------------------
# R31.4 — trend dashboard tests
# ---------------------------------------------------------------------------

def _fake_clone_and_trend(owner: str, repo: str, sha: str, lookback_days: int):
    """Synthetic trend result for the dashboard render path."""
    return {
        "rows": [
            {"date": "2026-01-15", "sha": "a1b2c3d4", "new": 12, "resolved": 0,
             "net": 12, "total": 12},
            {"date": "2026-02-01", "sha": "e5f6a7b8", "new": 3, "resolved": 5,
             "net": -2, "total": 10},
            {"date": "2026-03-10", "sha": "c9d0e1f2", "new": 1, "resolved": 8,
             "net": -7, "total": 3},
        ],
        "_meta": {
            "owner": owner,
            "repo": repo,
            "sha": sha,
            "lookback_days": lookback_days,
            "url": f"https://github.com/{owner}/{repo}",
            "scanned_at": 0,
            "commits_analysed": 3,
        },
    }


class TestTrendDashboard:
    def test_html_render_shape(self, client) -> None:
        """End-to-end: GET /trend/<owner>/<repo> returns styled HTML with
        the sparkline SVG + per-commit velocity table + OG metadata."""
        with patch("app._resolve_head_sha", _fake_resolve_head), \
             patch("app._clone_and_trend", _fake_clone_and_trend):
            r = client.get("/trend/terraform-aws-modules/terraform-aws-vpc")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        body = r.text
        # Sparkline SVG present.
        assert "<svg" in body
        assert "polyline" in body
        # All three commit SHAs appear in the velocity table.
        for sha in ("a1b2c3d4", "e5f6a7b8", "c9d0e1f2"):
            assert sha in body, f"missing sha {sha}"
        # OG card on the page — preview-ready.
        assert 'property="og:title"' in body
        # Net negative (3 resolved net) → headline should say "resolved".
        assert "resolved" in body
        # Repo back-link.
        assert "github.com/terraform-aws-modules/terraform-aws-vpc" in body

    def test_json_form_returns_rows(self, client) -> None:
        """``.json`` sibling route returns the raw rows + meta dict."""
        with patch("app._resolve_head_sha", _fake_resolve_head), \
             patch("app._clone_and_trend", _fake_clone_and_trend):
            r = client.get("/trend/foo/bar.json")
        assert r.status_code == 200
        data = r.json()
        assert len(data["rows"]) == 3
        assert data["_meta"]["owner"] == "foo"
        assert data["_meta"]["repo"] == "bar"

    def test_lookback_query_param_clamped(self, client) -> None:
        """``?lookback=`` must be clamped to ``[7, 365]`` — silly values
        fall back to default rather than 400'ing."""
        captured: dict = {}

        def capture(owner, repo, sha, lookback_days):
            captured["lookback_days"] = lookback_days
            return _fake_clone_and_trend(owner, repo, sha, lookback_days)

        with patch("app._resolve_head_sha", _fake_resolve_head), \
             patch("app._clone_and_trend", capture):
            # Above cap → 365.
            client.get("/trend/foo/bar?lookback=9999")
            assert captured["lookback_days"] == 365
            # Below min → 7.
            client.get("/trend/foo/bar?lookback=1")
            assert captured["lookback_days"] == 7
            # Garbage → default 90.
            client.get("/trend/foo/bar?lookback=not-a-number")
            assert captured["lookback_days"] == 90

    def test_404_when_head_unresolvable(self, client) -> None:
        """Same 404 contract as /scan/ — bad repo, no cloning attempt."""
        with patch("app._resolve_head_sha", lambda *a, **k: None):
            r = client.get("/trend/nonexistent/nonexistent")
        assert r.status_code == 404

    def test_empty_history_renders_without_crashing(self, client) -> None:
        """A repo with zero commits in the lookback window must still
        render a sensible page (not 500). Headline collapses to net-zero;
        velocity table prints a helpful placeholder."""
        def empty_trend(owner, repo, sha, lookback_days):
            return {
                "rows": [],
                "_meta": {
                    "owner": owner, "repo": repo, "sha": sha,
                    "lookback_days": lookback_days,
                    "url": f"https://github.com/{owner}/{repo}",
                    "scanned_at": 0, "commits_analysed": 0,
                },
            }
        with patch("app._resolve_head_sha", _fake_resolve_head), \
             patch("app._clone_and_trend", empty_trend):
            r = client.get("/trend/quiet/repo")
        assert r.status_code == 200
        # Sparkline still renders (just empty).
        assert "<svg" in r.text
        # Placeholder explains the empty state.
        assert "No commits" in r.text

    def test_biggest_jump_annotation_appears(self, client) -> None:
        """The biggest |net| commit gets called out separately —
        share-bait is the "this one commit moved the needle" framing."""
        with patch("app._resolve_head_sha", _fake_resolve_head), \
             patch("app._clone_and_trend", _fake_clone_and_trend):
            r = client.get("/trend/foo/bar")
        body = r.text
        # The third commit had net=-7 (biggest |net|); its SHA must
        # appear in the dedicated annotation line.
        assert "Biggest single-commit jump" in body
        assert "c9d0e1f2" in body
