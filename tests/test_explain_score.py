"""Tests for `--explain-score` (R30.8).

Locks the score-explanation surface — ranking, projected score
arithmetic, JSON + text emission, and the empty-corpus edge case.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import DETECT_PY, FIXTURES_DIR, REPO_ROOT


sys.path.insert(0, str(REPO_ROOT / "scripts"))
from _scoring import explain_score, render_score_explanation  # type: ignore


class TestExplainScoreFunction:
    def test_orders_by_weight_descending(self) -> None:
        findings = [
            {"id": "A", "urgency": "LOW", "file": "x.tf", "line": 1, "title": "a"},
            {"id": "B", "urgency": "CRITICAL", "file": "x.tf", "line": 2, "title": "b"},
            {"id": "C", "urgency": "MEDIUM", "file": "x.tf", "line": 3, "title": "c"},
            {"id": "D", "urgency": "HIGH", "file": "x.tf", "line": 4, "title": "d"},
        ]
        summary = {"score": 70, "grade": "B-"}
        payload = explain_score(findings, summary, top_n=4)
        # CRITICAL(15) > HIGH(7) > MEDIUM(3) > LOW(1)
        assert [r["id"] for r in payload["top"]] == ["B", "D", "C", "A"]
        assert [r["weight"] for r in payload["top"]] == [15, 7, 3, 1]

    def test_projected_score_is_cumulative_and_capped(self) -> None:
        findings = [
            {"id": "A", "urgency": "CRITICAL", "file": "x.tf", "line": 1},
            {"id": "B", "urgency": "CRITICAL", "file": "x.tf", "line": 2},
        ]
        summary = {"score": 85, "grade": "B"}
        payload = explain_score(findings, summary)
        # 85 + 15 = 100 (cap) for the first, 100 (cap) for the second.
        assert payload["top"][0]["projected_score"] == 100
        assert payload["top"][1]["projected_score"] == 100
        # `perfect_score` is also capped at 100.
        assert payload["perfect_score"] == 100

    def test_info_findings_are_excluded(self) -> None:
        """INFO findings carry weight 0; fixing them does not move the
        score, so they must not appear in the top-N ranking."""
        findings = [
            {"id": "INFO-MOD-1", "urgency": "INFO", "file": "x.tf", "line": 1},
            {"id": "MED-1", "urgency": "MEDIUM", "file": "x.tf", "line": 2},
        ]
        payload = explain_score(findings, {"score": 97, "grade": "A"})
        assert [r["id"] for r in payload["top"]] == ["MED-1"]

    def test_empty_corpus_yields_no_rows(self) -> None:
        payload = explain_score([], {"score": 100, "grade": "A"})
        assert payload["top"] == []
        assert payload["perfect_score"] == 100

    def test_render_text_smoke(self) -> None:
        findings = [
            {"id": "SEC-DEMO-001", "urgency": "HIGH",
             "file": "main.tf", "line": 12, "title": "demo"},
        ]
        payload = explain_score(findings, {"score": 80, "grade": "B"})
        rendered = render_score_explanation(payload)
        assert "--explain-score" in rendered
        assert "SEC-DEMO-001" in rendered
        # Weight is the HIGH tier (7); projected: 80 + 7 = 87.
        assert "−7" in rendered
        assert "87" in rendered

    def test_render_text_empty(self) -> None:
        rendered = render_score_explanation(
            explain_score([], {"score": 100, "grade": "A"})
        )
        assert "no score-affecting findings" in rendered


class TestExplainScoreCLI:
    """Subprocess-based integration: verify the flag wires through both
    text and JSON output surfaces."""

    def test_text_format_emits_block(self) -> None:
        target = FIXTURES_DIR / "aws_alb_no_access_logs"
        proc = subprocess.run(
            [sys.executable, str(DETECT_PY), "--target", str(target),
             "--format", "text", "--explain-score"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0
        assert "--explain-score: top fixes ranked by score impact" in proc.stdout
        assert "SEC-AWS-ALB-001" in proc.stdout

    def test_json_format_emits_structured_field(self) -> None:
        target = FIXTURES_DIR / "aws_alb_no_access_logs"
        proc = subprocess.run(
            [sys.executable, str(DETECT_PY), "--target", str(target),
             "--format", "json", "--explain-score"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0
        data = json.loads(proc.stdout)
        assert "score_explanation" in data
        explanation = data["score_explanation"]
        assert "base_score" in explanation
        assert "base_grade" in explanation
        assert "perfect_score" in explanation
        assert "top" in explanation
        assert isinstance(explanation["top"], list)
        # Ranks are 1-indexed and contiguous.
        assert [r["rank"] for r in explanation["top"]] == list(
            range(1, len(explanation["top"]) + 1)
        )

    def test_flag_off_by_default(self) -> None:
        """`score_explanation` must NOT be in JSON output when the flag
        is absent — guards against silent payload bloat in CI."""
        target = FIXTURES_DIR / "aws_alb_no_access_logs"
        proc = subprocess.run(
            [sys.executable, str(DETECT_PY), "--target", str(target),
             "--format", "json"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0
        data = json.loads(proc.stdout)
        assert "score_explanation" not in data
