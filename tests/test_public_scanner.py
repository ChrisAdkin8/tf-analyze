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
