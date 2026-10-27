"""Tests for ``integrations/badge-service/server.py``.

The badge service is a small FastAPI app that returns shields.io-shape
SVG badges for a repo's most recent tf-analyze score. These tests
cover:

  * SVG rendering — every supported grade produces a valid, minimally
    well-formed SVG with the engine's score+grade legible inside.
  * Path validation — the routes reject path-traversal, oversize, and
    malformed owner/repo/branch shapes.
  * /ingest authentication — HMAC-SHA256 over the request body must
    match ``TFA_BADGE_INGEST_SECRET``; mismatched bodies are 401.
  * Round-trip — POST a scan, GET the badge, assert the rendered SVG
    embeds the score.

FastAPI isn't a hard dep of the engine; tests `importorskip` so the
suite still runs cleanly when FastAPI is absent locally.
"""
from __future__ import annotations

import hashlib
import time
import itertools
import hmac
import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
BADGE_DIR = REPO_ROOT / "integrations" / "badge-service"

# Pull the badge service module in directly. We cannot rely on
# `pip install` of an editable package — the badge service is a
# stand-alone deployable, not part of the engine wheel.
sys.path.insert(0, str(BADGE_DIR))

# FastAPI is only required at import time. If absent (developer hasn't
# `pip install`-ed the badge-service requirements), skip the whole
# module rather than fail loudly.
fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient

import server  # noqa: E402 — dynamic path manipulation above


# ---------------------------------------------------------------------------
# SVG rendering
# ---------------------------------------------------------------------------


class TestSvgRendering:
    def test_every_grade_renders_a_well_formed_svg(self) -> None:
        for grade in ("A", "B", "B-", "C", "D", "F"):
            svg = server.render_badge_svg("tf-analyze", 75, grade)
            assert svg.startswith("<svg "), grade
            assert svg.endswith("</svg>"), grade
            assert "75 (" + grade + ")" in svg, (
                f"badge text missing score+grade for {grade}"
            )
            # Minimum: a label region + a score region + colour swatches.
            assert svg.count("<rect") >= 3, grade

    def test_grade_drives_colour_choice(self) -> None:
        # Each grade must map to a distinct background colour, so users
        # can spot the worst-of-the-worst without reading the digits.
        seen: set[str] = set()
        for grade in ("A", "B", "B-", "C", "D", "F"):
            bg, _ = server._grade_colour(grade)
            assert bg.startswith("#")
            seen.add(bg)
        assert len(seen) == 6, (
            "every grade must have a distinct colour; got: "
            f"{sorted(seen)}"
        )

    def test_unknown_grade_falls_back_to_f_tier(self, capsys) -> None:
        """Round-3 audit fix #21 — unrecognised grade renders as F-tier
        red, not neutral grey. Grey was easily misread as "no scan
        yet"; an engine that emitted a typo grade silently rendered as
        "missing data". Red + stderr WARN forces the operator to
        notice the mismatch.
        """
        bg, _ = server._grade_colour("X")
        # F-tier red is the canonical "worst" colour in the palette
        # and matches the rendered SVG so users see a real signal
        # rather than a placeholder.
        assert bg == server._GRADE_COLOURS["F"][0]
        captured = capsys.readouterr()
        assert "unrecognised grade" in captured.err

    def test_unknown_badge_renders_without_score(self) -> None:
        svg = server.render_unknown_badge()
        assert "<svg" in svg and "no data" in svg
        # No score should leak into the unknown-badge text.
        assert "(A)" not in svg and "(F)" not in svg

    def test_long_score_text_widens_score_region(self) -> None:
        # A 3-digit score with a 2-character grade like "B-" needs more
        # pixels than the default. Width must scale.
        narrow = server.render_badge_svg("tf-analyze", 1, "A")
        wide = server.render_badge_svg("tf-analyze", 100, "B-")
        # Pull the outer width attribute and confirm wide > narrow.
        import re as _re
        nw = int(_re.search(r'width="(\d+)"', narrow).group(1))
        ww = int(_re.search(r'width="(\d+)"', wide).group(1))
        assert ww > nw, f"wide={ww} should exceed narrow={nw}"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestPathValidation:
    @pytest.fixture
    def client(self) -> TestClient:
        return TestClient(server.app)

    def test_unknown_repo_returns_no_data_badge(self, client: TestClient) -> None:
        # No scan ingested → 200 with the "no data" SVG, not 404.
        # Returning 404 would break the README rendering (broken-image icon);
        # a no-data badge keeps the layout intact.
        resp = client.get("/score/SomeOwner/SomeRepo.svg")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("image/svg")
        assert b"no data" in resp.content

    def test_owner_with_traversal_is_rejected(self, client: TestClient) -> None:
        # The router will route `/score/../etc/repo.svg` to a different
        # path; what we care about is that the validator fires when
        # _validate_repo_path is called with hostile values.
        with pytest.raises(server.HTTPException):
            server._validate_repo_path("../etc", "repo", "main")
        with pytest.raises(server.HTTPException):
            server._validate_repo_path("owner", "repo;rm", "main")

    def test_oversize_owner_is_rejected(self) -> None:
        with pytest.raises(server.HTTPException):
            server._validate_repo_path("a" * 200, "repo", "main")

    def test_branch_can_contain_slashes(self) -> None:
        # release/v1.0 is a real branch shape.
        server._validate_repo_path("owner", "repo", "release/v1.0")
        server._validate_repo_path("owner", "repo", "feat/foo-bar")

    def test_branch_rejects_traversal(self) -> None:
        with pytest.raises(server.HTTPException):
            server._validate_repo_path("owner", "repo", "../main")


# ---------------------------------------------------------------------------
# /ingest HMAC authentication
# ---------------------------------------------------------------------------


SECRET = "test-secret-32+-bytes-of-shared-key-material"


_TICK = itertools.count()


def _signed(body: bytes, secret: str = SECRET, *, ts: int | None = None) -> dict:
    """Headers for an /ingest: HMAC-SHA256 of ``<ts>.<body>`` under the
    repo's derived key. Each call gets a later timestamp, so consecutive
    uploads in one test are not taken for replays."""
    payload = json.loads(body)
    key = server.repo_ingest_key(secret, payload["owner"], payload["repo"]).encode()
    ts = int(time.time()) + next(_TICK) % 60 if ts is None else ts
    sig = hmac.new(key, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return {"X-TFA-Signature": "sha256=" + sig, "X-TFA-Timestamp": str(ts)}


@pytest.fixture(autouse=True)
def _set_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TFA_BADGE_INGEST_SECRET", SECRET)
    # Reset the in-memory store between tests so leftovers from one
    # test don't bleed into the next.
    server._store = server.InMemoryStore()
    server._last_ingest_ts.clear()


def _scan_body(score: int = 82, grade: str = "B") -> bytes:
    payload = {
        "owner": "ChrisAdkin8",
        "repo": "tf-analyze",
        "branch": "main",
        "scan": {
            "summary": {
                "score": score,
                "grade": grade,
                "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 4, "LOW": 6, "INFO": 0},
            },
            "findings": [],
        },
    }
    return json.dumps(payload).encode("utf-8")


class TestIngestAuth:
    @pytest.fixture
    def client(self) -> TestClient:
        return TestClient(server.app)

    def test_missing_signature_is_401(self, client: TestClient) -> None:
        resp = client.post("/ingest", content=_scan_body())
        assert resp.status_code == 401
        assert "X-TFA-Signature" in resp.text

    def test_wrong_signature_is_401(self, client: TestClient) -> None:
        body = _scan_body()
        wrong = "sha256=" + ("a" * 64)
        resp = client.post(
            "/ingest", content=body,
            headers={"X-TFA-Signature": wrong, "X-TFA-Timestamp": str(int(time.time()))},
        )
        assert resp.status_code == 401
        assert "mismatch" in resp.text

    def test_correct_signature_is_accepted(self, client: TestClient) -> None:
        body = _scan_body()
        resp = client.post(
            "/ingest", content=body,
            headers=_signed(body),
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["ok"] is True
        assert data["key"] == "ChrisAdkin8/tf-analyze@main"

    def test_secret_unset_returns_503(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("TFA_BADGE_INGEST_SECRET", raising=False)
        body = _scan_body()
        resp = client.post(
            "/ingest", content=body,
            headers=_signed(body, "irrelevant"),
        )
        assert resp.status_code == 503

    def test_missing_summary_score_is_400(self, client: TestClient) -> None:
        bad = json.dumps({
            "owner": "x", "repo": "y", "branch": "main",
            "scan": {"summary": {"counts": {}}},
        }).encode("utf-8")
        resp = client.post(
            "/ingest", content=bad,
            headers=_signed(bad),
        )
        assert resp.status_code == 400
        assert "score" in resp.text

    def test_unknown_grade_is_400(self, client: TestClient) -> None:
        bad = _scan_body(score=50, grade="Z")
        resp = client.post(
            "/ingest", content=bad,
            headers=_signed(bad),
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Round-trip: ingest then GET the badge.
# ---------------------------------------------------------------------------


class TestRoundTrip:
    @pytest.fixture
    def client(self) -> TestClient:
        return TestClient(server.app)

    def test_ingest_then_score_returns_rendered_badge(
        self, client: TestClient,
    ) -> None:
        body = _scan_body(score=82, grade="B")
        ingest_resp = client.post(
            "/ingest", content=body,
            headers=_signed(body),
        )
        assert ingest_resp.status_code == 200

        badge_resp = client.get("/score/ChrisAdkin8/tf-analyze.svg")
        assert badge_resp.status_code == 200
        assert badge_resp.headers["content-type"].startswith("image/svg")
        # Rendered SVG must include the score+grade legible on screen.
        assert b"82 (B)" in badge_resp.content
        # Cache header so README badges don't melt the backend.
        assert "Cache-Control" in badge_resp.headers
        assert "public" in badge_resp.headers["Cache-Control"]

    def test_branch_specific_badge_after_ingest(
        self, client: TestClient,
    ) -> None:
        body = json.dumps({
            "owner": "ChrisAdkin8",
            "repo": "tf-analyze",
            "branch": "feat/new-stuff",
            "scan": {"summary": {"score": 65, "grade": "B-", "counts": {}}},
        }).encode("utf-8")
        client.post(
            "/ingest", content=body,
            headers=_signed(body),
        )
        resp = client.get("/score/ChrisAdkin8/tf-analyze/feat/new-stuff.svg")
        assert resp.status_code == 200
        assert b"65 (B-)" in resp.content

    def test_main_branch_does_not_leak_into_other_branch_badge(
        self, client: TestClient,
    ) -> None:
        # Ingest only against main; a different-branch badge must
        # still show "no data" rather than the main score.
        body = _scan_body(score=99, grade="A")
        client.post(
            "/ingest", content=body,
            headers=_signed(body),
        )
        resp = client.get("/score/ChrisAdkin8/tf-analyze/feature-branch.svg")
        assert resp.status_code == 200
        assert b"no data" in resp.content
        assert b"99" not in resp.content


# ---------------------------------------------------------------------------
# Label escaping, per-repo keys, replays, body cap (critical review)
# ---------------------------------------------------------------------------


def test_label_is_escaped_in_the_svg() -> None:
    svg = server.render_badge_svg('"/><a href="//x">pwn', 80, "B")
    assert "<a href" not in svg and "&lt;a href" in svg
    assert "<a href" not in server.render_unknown_badge('"><a href="//x">')


class TestIngestHardening:
    @pytest.fixture
    def client(self) -> TestClient:
        return TestClient(server.app)

    def test_one_repos_key_cannot_write_another_repo(self, client: TestClient) -> None:
        body = _scan_body()  # ChrisAdkin8/tf-analyze
        other = json.loads(body)
        other["repo"] = "someone-elses-repo"
        forged = json.dumps(other).encode()
        headers = _signed(body)  # signed with tf-analyze's key …
        ts = headers["X-TFA-Timestamp"]
        key = server.repo_ingest_key(SECRET, "ChrisAdkin8", "tf-analyze").encode()
        sig = hmac.new(key, f"{ts}.".encode() + forged, hashlib.sha256).hexdigest()
        resp = client.post("/ingest", content=forged,  # … for a different repo
                           headers={"X-TFA-Signature": "sha256=" + sig, "X-TFA-Timestamp": ts})
        assert resp.status_code == 401

    def test_a_replayed_upload_is_refused(self, client: TestClient) -> None:
        body = _scan_body()
        headers = _signed(body)
        assert client.post("/ingest", content=body, headers=headers).status_code == 200
        replay = client.post("/ingest", content=body, headers=headers)
        assert replay.status_code == 401 and "replay" in replay.text

    def test_a_stale_timestamp_is_refused(self, client: TestClient) -> None:
        body = _scan_body()
        resp = client.post("/ingest", content=body,
                           headers=_signed(body, ts=int(time.time()) - 3600))
        assert resp.status_code == 401 and "window" in resp.text

    def test_an_oversized_body_is_refused_before_parsing(self, client: TestClient) -> None:
        big = b"{" + b" " * (server.MAX_INGEST_BYTES + 1) + b"}"
        resp = client.post("/ingest", content=big,
                           headers={"X-TFA-Signature": "sha256=" + "a" * 64,
                                    "X-TFA-Timestamp": str(int(time.time()))})
        assert resp.status_code == 413
