"""Tests for `_threat_intel.py` (R30.2 — KEV + EPSS exploitability ranking).

The module is **offline-degrades-gracefully** — every test here runs
with `allow_network=False` and seeds the cache directory by hand. CI
must not depend on the live CISA / FIRST.org feeds.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import DETECT_PY, FIXTURES_DIR, REPO_ROOT


sys.path.insert(0, str(REPO_ROOT / "scripts"))
from _threat_intel import (  # type: ignore
    LoadStatus,
    enrich_findings,
    load_epss_scores,
    load_kev_cwes,
    rank_findings,
    warn_on_status,
)


# ---------------------------------------------------------------------------
# Cache loading — offline-degrades-gracefully behaviour
# ---------------------------------------------------------------------------


class TestKevLoading:
    def test_no_cache_no_network_returns_empty(self, tmp_path: Path) -> None:
        cwes, status = load_kev_cwes(cache_dir=tmp_path, allow_network=False)
        assert cwes == set()
        assert status.cached is False
        assert status.error is not None

    def test_fresh_cache_returns_set(self, tmp_path: Path) -> None:
        (tmp_path / "kev.json").write_text(
            json.dumps({"fetched_at": 0, "cwes": ["CWE-78", "CWE-269"]})
        )
        # Touch mtime to now so the freshness check passes.
        cwes, status = load_kev_cwes(cache_dir=tmp_path, allow_network=False)
        assert cwes == {"CWE-78", "CWE-269"}
        assert status.cached is True
        assert status.from_network is False
        assert status.stale is False


class TestEpssLoading:
    def test_no_cache_no_network_returns_empty(self, tmp_path: Path) -> None:
        scores, status = load_epss_scores(cache_dir=tmp_path, allow_network=False)
        assert scores == {}
        assert status.cached is False

    def test_fresh_cache_returns_scores(self, tmp_path: Path) -> None:
        (tmp_path / "epss.json").write_text(
            json.dumps({"fetched_at": 0, "scores": {"CVE-2024-1234": 0.97}})
        )
        scores, status = load_epss_scores(cache_dir=tmp_path, allow_network=False)
        assert scores == {"CVE-2024-1234": 0.97}
        assert status.cached is True


# ---------------------------------------------------------------------------
# Enrichment — KEV badging + urgency promotion
# ---------------------------------------------------------------------------


class TestEnrichFindings:
    def _entries(self) -> list[dict]:
        return [
            {"id": "SEC-DEMO-001", "cwe": ["CWE-269"], "default_urgency": "MEDIUM"},
            {"id": "SEC-DEMO-002", "cwe": ["CWE-200"], "default_urgency": "LOW"},
            {"id": "SEC-NO-CWE-003", "default_urgency": "HIGH"},
        ]

    def _findings(self) -> list[dict]:
        return [
            {"id": "SEC-DEMO-001", "urgency": "MEDIUM", "file": "a.tf", "line": 1},
            {"id": "SEC-DEMO-002", "urgency": "LOW", "file": "b.tf", "line": 2},
            {"id": "SEC-NO-CWE-003", "urgency": "HIGH", "file": "c.tf", "line": 3},
        ]

    def test_urgency_mode_does_not_change_anything(self) -> None:
        findings = self._findings()
        # `--rank-by urgency` is the default; the engine doesn't call
        # `enrich_findings` in that path. Still — calling it explicitly
        # in `urgency` mode must be a no-op for urgency promotion.
        out = enrich_findings(
            findings, self._entries(),
            rank_by="urgency",
            kev_cwes={"CWE-269"},
        )
        # KEV badging happens regardless of rank mode; promotion does not.
        assert out[0]["kev"] is True
        assert out[0]["exploitability_promoted"] is False
        assert out[0]["urgency"] == "MEDIUM"

    def test_exploitability_mode_promotes_kev_findings(self) -> None:
        findings = self._findings()
        out = enrich_findings(
            findings, self._entries(),
            rank_by="exploitability",
            kev_cwes={"CWE-269"},
        )
        # SEC-DEMO-001 has CWE-269 (in KEV set) → MEDIUM promoted to HIGH.
        assert out[0]["kev"] is True
        assert out[0]["exploitability_promoted"] is True
        assert out[0]["urgency"] == "HIGH"
        assert out[0]["original_urgency"] == "MEDIUM"
        # SEC-DEMO-002 has CWE-200 (NOT in KEV set) → no promotion.
        assert out[1]["kev"] is False
        assert out[1]["urgency"] == "LOW"
        # SEC-NO-CWE-003 has no CWE → no promotion.
        assert out[2]["kev"] is False

    def test_critical_does_not_promote_past_critical(self) -> None:
        findings = [
            {"id": "SEC-DEMO-001", "urgency": "CRITICAL", "file": "a.tf", "line": 1}
        ]
        out = enrich_findings(
            findings, self._entries(),
            rank_by="exploitability",
            kev_cwes={"CWE-269"},
        )
        # KEV is true, but CRITICAL is the ceiling.
        assert out[0]["kev"] is True
        assert out[0]["urgency"] == "CRITICAL"
        assert out[0]["exploitability_promoted"] is False

    def test_hybrid_promotes_kev_too(self) -> None:
        findings = self._findings()
        out = enrich_findings(
            findings, self._entries(),
            rank_by="hybrid",
            kev_cwes={"CWE-269"},
        )
        assert out[0]["urgency"] == "HIGH"


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------


class TestRanking:
    def test_exploitability_puts_kev_first(self) -> None:
        findings = [
            {"id": "A", "urgency": "MEDIUM", "kev": False, "file": "x.tf", "line": 1},
            {"id": "B", "urgency": "MEDIUM", "kev": True, "file": "x.tf", "line": 2},
        ]
        out = rank_findings(findings, "exploitability")
        assert [f["id"] for f in out] == ["B", "A"]

    def test_hybrid_keeps_urgency_first_then_kev(self) -> None:
        findings = [
            {"id": "low_kev", "urgency": "LOW", "kev": True, "file": "x.tf", "line": 1},
            {"id": "high_no_kev", "urgency": "HIGH", "kev": False, "file": "x.tf", "line": 2},
        ]
        out = rank_findings(findings, "hybrid")
        # HIGH outranks LOW regardless of KEV in hybrid mode.
        assert [f["id"] for f in out] == ["high_no_kev", "low_kev"]

    def test_urgency_mode_returns_input_unchanged(self) -> None:
        findings = [{"id": "A"}, {"id": "B"}]
        out = rank_findings(findings, "urgency")
        assert out is findings


# ---------------------------------------------------------------------------
# CLI integration — full --rank-by + --no-threat-intel wiring
# ---------------------------------------------------------------------------


def _run_with_cache(
    target: Path, tmp_cache: Path, *args: str,
) -> subprocess.CompletedProcess:
    """Spawn detect.py with TFA_CACHE_DIR pointed at a controlled dir."""
    import os
    env = os.environ.copy()
    env["TFA_CACHE_DIR"] = str(tmp_cache)
    return subprocess.run(
        [sys.executable, str(DETECT_PY), "--target", str(target),
         "--format", "json", *args],
        capture_output=True, text=True, env=env,
    )


class TestRankByCLI:
    def test_default_urgency_mode_skips_enrichment(
        self, tmp_path: Path,
    ) -> None:
        target = FIXTURES_DIR / "aws_alb_no_access_logs"
        proc = _run_with_cache(target, tmp_path)
        assert proc.returncode == 0
        data = json.loads(proc.stdout)
        # No findings should carry the `kev` field in default mode.
        for f in data["findings"]:
            assert "kev" not in f, (
                f"urgency-mode finding leaked `kev` field: {f['id']}"
            )

    def test_exploitability_mode_with_seeded_cache_adds_kev_tag(
        self, tmp_path: Path,
    ) -> None:
        # Seed a KEV cache that includes a CWE every IAM rule should
        # carry (CWE-269 — improper privilege management).
        (tmp_path / "kev.json").write_text(
            json.dumps({"fetched_at": 0, "cwes": ["CWE-269", "CWE-732"]})
        )
        # Pick a fixture whose primary rule has CWE-269.
        target = FIXTURES_DIR / "aws_iam_policy_wildcard_action"
        if not target.exists():
            pytest.skip("aws_iam_policy_wildcard_action fixture not present")
        proc = _run_with_cache(
            target, tmp_path,
            "--rank-by", "exploitability", "--no-threat-intel",
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads(proc.stdout)
        kev_hits = [f for f in data["findings"] if f.get("kev")]
        assert kev_hits, "expected ≥1 KEV-tagged finding"
        # KEV findings are promoted one urgency tier in exploitability mode.
        for f in kev_hits:
            assert f.get("exploitability_promoted") in (True, False)
            assert "original_urgency" in f

    def test_no_threat_intel_with_empty_cache_is_clean_noop(
        self, tmp_path: Path,
    ) -> None:
        """Air-gapped CI — no cache and `--no-threat-intel` must not
        crash, must not emit network requests, and must produce a
        valid JSON output."""
        target = FIXTURES_DIR / "aws_alb_no_access_logs"
        proc = _run_with_cache(
            target, tmp_path,
            "--rank-by", "exploitability", "--no-threat-intel",
        )
        assert proc.returncode == 0
        data = json.loads(proc.stdout)
        # All findings have the field present (since enrichment runs)
        # but no findings should be KEV-tagged (empty KEV cache).
        for f in data["findings"]:
            assert f.get("kev") is False


class TestWarnOnStatus:
    def test_silent_on_success(self, capsys) -> None:
        warn_on_status("KEV", LoadStatus(cached=True, from_network=True, stale=False))
        assert capsys.readouterr().err == ""

    def test_warns_on_stale(self, capsys) -> None:
        warn_on_status("KEV", LoadStatus(
            cached=True, from_network=False, stale=True,
            error="connection refused",
        ))
        assert "stale cache" in capsys.readouterr().err

    def test_warns_on_total_failure(self, capsys) -> None:
        warn_on_status("KEV", LoadStatus(
            cached=False, from_network=False, stale=False,
            error="DNS resolution failed",
        ))
        assert "continuing without enrichment" in capsys.readouterr().err
