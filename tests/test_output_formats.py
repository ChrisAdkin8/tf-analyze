"""Output-format contract tests.

Covers the JSON ``summary`` block (score, grade, counts, scoring_version),
the text header line, and the HTML banner. The summary block is part of
the public CLI contract: changing keys, types, or formula constants is a
breaking change and must bump ``_SCORING_VERSION``.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import detect  # noqa: E402


# ---------------------------------------------------------------------------
# _compute_summary unit tests
# ---------------------------------------------------------------------------


class TestComputeSummary:
    def test_clean_repo_is_a_grade(self):
        s = detect._compute_summary([])
        assert s["score"] == 100
        assert s["grade"] == "A"
        assert s["counts"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        assert s["suppressed_count"] == 0
        assert s["scoring_version"] == 1

    def test_one_critical_lowers_to_b(self):
        # 100 - 15 = 85 (B)
        s = detect._compute_summary([{"id": "X", "urgency": "CRITICAL"}])
        assert s["score"] == 85
        assert s["grade"] == "B"

    def test_skill_md_worked_example_b(self):
        # SKILL.md example: 0 CRITICAL, 0 HIGH, 4 MEDIUM, 6 LOW = 82 (B)
        findings = (
            [{"id": f"M{i}", "urgency": "MEDIUM"} for i in range(4)]
            + [{"id": f"L{i}", "urgency": "LOW"} for i in range(6)]
        )
        s = detect._compute_summary(findings)
        assert s["score"] == 82
        assert s["grade"] == "B"

    def test_skill_md_worked_example_d(self):
        # SKILL.md example: 0 CRITICAL, 4 HIGH, 11 MEDIUM, 6 LOW = 33 (D)
        findings = (
            [{"id": f"H{i}", "urgency": "HIGH"} for i in range(4)]
            + [{"id": f"M{i}", "urgency": "MEDIUM"} for i in range(11)]
            + [{"id": f"L{i}", "urgency": "LOW"} for i in range(6)]
        )
        s = detect._compute_summary(findings)
        assert s["score"] == 33
        assert s["grade"] == "D"

    def test_score_floors_at_zero(self):
        # 10 CRITICAL = 150 penalty, but score must clip to 0
        findings = [{"id": f"C{i}", "urgency": "CRITICAL"} for i in range(10)]
        s = detect._compute_summary(findings)
        assert s["score"] == 0
        assert s["grade"] == "F"

    def test_info_findings_dont_affect_score(self):
        s = detect._compute_summary(
            [{"id": f"I{i}", "urgency": "INFO"} for i in range(50)]
        )
        assert s["score"] == 100
        assert s["counts"]["INFO"] == 50

    def test_suppressed_count_at_half_weight(self):
        # 1 CRITICAL retained = -15. 2 CRITICAL suppressed = -15 (half each).
        # Total = 100 - 15 - 15 = 70 (B-)
        s = detect._compute_summary(
            findings=[{"id": "R", "urgency": "CRITICAL"}],
            suppressed=[
                {"id": "S1", "urgency": "CRITICAL"},
                {"id": "S2", "urgency": "CRITICAL"},
            ],
        )
        assert s["score"] == 70
        assert s["grade"] == "B-"
        assert s["suppressed_count"] == 2

    def test_baseline_suppressed_also_half_weight(self):
        # 2 HIGH retained = -14. 2 HIGH baseline-suppressed = -7 (half each).
        # Total = 100 - 14 - 7 = 79 (B)
        s = detect._compute_summary(
            findings=[{"id": "R1", "urgency": "HIGH"}, {"id": "R2", "urgency": "HIGH"}],
            suppressed_by_baseline=[
                {"id": "B1", "urgency": "HIGH"},
                {"id": "B2", "urgency": "HIGH"},
            ],
        )
        assert s["score"] == 79
        assert s["grade"] == "B"
        assert s["suppressed_count"] == 2

    def test_grade_boundaries(self):
        # Verify each grade tier is reachable.
        # Choose finding mixes that land just inside each tier.
        cases = [
            (100, "A"),
            (90,  "A"),
            (89,  "B"),
            (75,  "B"),
            (74,  "B-"),
            (65,  "B-"),
            (64,  "C"),
            (50,  "C"),
            (49,  "D"),
            (30,  "D"),
            (29,  "F"),
            (0,   "F"),
        ]
        for target, expected_grade in cases:
            assert detect._grade_for_score(target) == expected_grade, (
                f"score {target} should be grade {expected_grade}"
            )

    def test_summary_keys_are_stable(self):
        # JSON consumers pin to these keys; missing or renamed keys is a
        # breaking change and must bump _SCORING_VERSION.
        s = detect._compute_summary([])
        assert set(s.keys()) == {
            "scoring_version",
            "score",
            "grade",
            "counts",
            "suppressed_count",
            "formula",
        }


# ---------------------------------------------------------------------------
# CLI integration: summary appears in JSON and text output
# ---------------------------------------------------------------------------


def _run_cli(*args: str) -> tuple[str, str, int]:
    res = subprocess.run(
        [sys.executable, str(DETECT_PY), *args],
        capture_output=True, text=True, timeout=60,
    )
    return res.stdout, res.stderr, res.returncode


class TestCliSummary:
    def test_json_output_carries_summary_block(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "x" { bucket = "demo" }\n'
        )
        out, _, _ = _run_cli("--target", str(tmp_path), "--format", "json")
        data = json.loads(out)
        assert "summary" in data, "JSON output must always carry a summary block"
        s = data["summary"]
        assert s["scoring_version"] == 1
        assert isinstance(s["score"], int) and 0 <= s["score"] <= 100
        assert s["grade"] in {"A", "B", "B-", "C", "D", "F"}

    def test_text_output_starts_with_score_header(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "x" { bucket = "demo" }\n'
        )
        out, _, _ = _run_cli("--target", str(tmp_path), "--format", "text")
        first = out.strip().splitlines()[0]
        assert first.startswith("# tf-analyze:"), (
            f"Text output should lead with the summary header, got: {first!r}"
        )
        assert "CRITICAL" in first and "HIGH" in first

    def test_html_output_renders_banner(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "x" { bucket = "demo" }\n'
        )
        out, _, _ = _run_cli("--target", str(tmp_path), "--format", "html")
        # Banner is identifiable by the score formula text we ship.
        assert "scoring_version 1" in out
        assert "max(0, 100 - sum(weight * count))" in out

    def test_clean_repo_scores_100(self, tmp_path: Path):
        # An empty workspace with no .tf files should score 100 (A).
        out, _, _ = _run_cli("--target", str(tmp_path), "--format", "json")
        data = json.loads(out)
        assert data["summary"]["score"] == 100
        assert data["summary"]["grade"] == "A"

    def test_attack_graph_lands_in_json(self, tmp_path: Path):
        # `--attack-graph --format json` must emit the graph at top level
        # so JSON consumers (PR comments, web demo, run-task callbacks)
        # don't need a separate HTML render.
        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "data" { bucket = "x" }\n'
            'resource "aws_iam_role" "r" { name = "r" assume_role_policy = "{}" }\n'
            'resource "aws_instance" "web" {\n'
            '  ami = "ami-1"\n  iam_instance_profile = "p"\n  role = aws_iam_role.r.arn\n'
            "}\n"
        )
        out, _, _ = _run_cli(
            "--target", str(tmp_path), "--format", "json", "--attack-graph"
        )
        data = json.loads(out)
        assert "graph" in data, "JSON output must include `graph` when --attack-graph is set"
        assert isinstance(data["graph"].get("nodes"), list)
        assert isinstance(data["graph"].get("edges"), list)


# ---------------------------------------------------------------------------
# JSON / SARIF / HTML basic well-formedness
# ---------------------------------------------------------------------------


@pytest.fixture
def fixture_dir(tmp_path: Path) -> Path:
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "x" { bucket = "demo" }\n'
    )
    return tmp_path


class TestOutputWellFormedness:
    def test_json_is_valid(self, fixture_dir: Path):
        out, _, _ = _run_cli("--target", str(fixture_dir), "--format", "json")
        json.loads(out)  # raises on invalid

    def test_sarif_v210_envelope(self, fixture_dir: Path):
        out, _, _ = _run_cli("--target", str(fixture_dir), "--format", "sarif")
        data = json.loads(out)
        assert "sarif-schema-2.1.0" in data.get("$schema", ""), \
            f"SARIF schema URL changed unexpectedly: {data.get('$schema')!r}"
        assert data.get("version") == "2.1.0"
        assert isinstance(data.get("runs"), list) and data["runs"]

    def test_html_has_doctype_and_body(self, fixture_dir: Path):
        out, _, _ = _run_cli("--target", str(fixture_dir), "--format", "html")
        assert out.startswith("<!doctype html>")
        assert "<body>" in out and "</body>" in out
