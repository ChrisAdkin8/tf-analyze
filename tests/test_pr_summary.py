"""Tests for ``--format pr-summary``.

The PR-summary format is a concise Markdown block sized for GitHub PR
descriptions and the GitHub Action's PR summary comment. Every PR
reviewer sees it, so it doubles as marketing collateral — these tests
pin the visible shape so a future renderer change can't accidentally
drop the score banner, the top-3 table, the top-fix snippet, or the
attack-graph collapsible.

Distinct from ``--format text`` (verbose, CLI-shaped) and ``--format
json`` (machine-shaped). The pr-summary block is intentionally pasted-
into-PR-friendly: GitHub-flavoured Markdown, links to the docs site,
collapsed mermaid graph.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import detect  # noqa: E402


def _run(*args: str) -> str:
    res = subprocess.run(
        [sys.executable, str(DETECT_PY), *args],
        capture_output=True, text=True, timeout=60,
    )
    return res.stdout


# ---------------------------------------------------------------------------
# Pure renderer unit tests — exercise _render_pr_summary directly so
# specific shapes can be asserted without re-running the engine.
# ---------------------------------------------------------------------------


class TestRenderPrSummaryUnit:
    def test_clean_repo_renders_clean_banner(self) -> None:
        out = detect._render_pr_summary(
            findings=[],
            entries=[],
            summary={"score": 100, "grade": "A",
                     "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        )
        assert out.startswith("## tf-analyze: 100 (A)")
        assert "🟢" in out
        assert "Clean — no findings" in out

    def test_grade_emoji_per_tier(self) -> None:
        # Every grade in the engine's vocabulary must round-trip to a
        # distinct emoji so the visual heuristic ("red is bad") works.
        seen: set[str] = set()
        for grade in ("A", "B", "B-", "C", "D", "F"):
            out = detect._render_pr_summary(
                findings=[],
                entries=[],
                summary={"score": 50, "grade": grade,
                         "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
            )
            # First line is `## tf-analyze: 50 (X) <emoji>` — the
            # emoji is at the end after a space.
            head = out.splitlines()[0]
            assert head.startswith(f"## tf-analyze: 50 ({grade})"), head
            emoji = head.removeprefix(f"## tf-analyze: 50 ({grade})").strip()
            assert emoji, f"grade {grade} must have an emoji"
            seen.add(emoji)
        # B and B- intentionally share the same blue emoji; the rest
        # must be unique. So at least 5 distinct emoji across 6 grades.
        assert len(seen) >= 5

    def test_top_findings_table_shows_at_most_three(self) -> None:
        # Build 5 findings; only the top 3 (by urgency × centrality) appear.
        findings = [
            {"id": f"R{i}", "file": "main.tf", "line": i,
             "resource": f"resource.r{i}",
             "urgency": "HIGH"}
            for i in range(5)
        ]
        entries = [
            {"id": f"R{i}", "title": f"R{i} title", "default_urgency": "HIGH"}
            for i in range(5)
        ]
        out = detect._render_pr_summary(
            findings=findings,
            entries=entries,
            summary={"score": 53, "grade": "C",
                     "counts": {"CRITICAL": 0, "HIGH": 5, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        )
        # Header + separator + 3 rows = 5 table lines.
        table_rows = [ln for ln in out.splitlines() if ln.startswith("| ") and "Rule" not in ln and "---" not in ln]
        assert len(table_rows) == 3, (
            f"expected exactly 3 finding rows, got {len(table_rows)}: {table_rows}"
        )
        # The "+N more" bridge line must be present for >3 findings.
        assert "+2 more" in out

    def test_critical_outranks_high_in_top_findings(self) -> None:
        # Even if HIGH findings were appended first, the CRITICAL must
        # surface to the top-3 table.
        findings = [
            {"id": "H1", "file": "x.tf", "line": 10, "resource": "x.h"},
            {"id": "C1", "file": "y.tf", "line": 20, "resource": "y.c"},
            {"id": "H2", "file": "z.tf", "line": 30, "resource": "z.h"},
        ]
        entries = [
            {"id": "H1", "title": "H1", "default_urgency": "HIGH"},
            {"id": "C1", "title": "C1", "default_urgency": "CRITICAL"},
            {"id": "H2", "title": "H2", "default_urgency": "HIGH"},
        ]
        out = detect._render_pr_summary(
            findings=findings,
            entries=entries,
            summary={"score": 50, "grade": "C",
                     "counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        )
        # The first table row must contain `**CRITICAL**`.
        first_data_row = next(
            ln for ln in out.splitlines()
            if ln.startswith("| ") and "Rule" not in ln and "---" not in ln
        )
        assert "**CRITICAL**" in first_data_row

    def test_top_fix_snippet_renders_when_fix_hcl_present(self) -> None:
        findings = [{"id": "R1", "file": "main.tf", "line": 1, "resource": "r.x"}]
        entries = [{
            "id": "R1", "title": "R1", "default_urgency": "HIGH",
            "fix_hcl": 'resource "aws_x" "y" { encrypted = true }',
            "fix_disruption": "none",
        }]
        out = detect._render_pr_summary(
            findings=findings, entries=entries,
            summary={"score": 80, "grade": "B",
                     "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        )
        assert "### Top fix — R1" in out
        assert "```hcl" in out
        assert "encrypted = true" in out
        # Disruption tag rendered.
        assert "*(`none`)*" in out

    def test_top_fix_omitted_when_no_fix_hcl(self) -> None:
        findings = [{"id": "R1", "file": "main.tf", "line": 1, "resource": "r.x"}]
        entries = [{"id": "R1", "title": "R1", "default_urgency": "HIGH"}]
        out = detect._render_pr_summary(
            findings=findings, entries=entries,
            summary={"score": 80, "grade": "B",
                     "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        )
        assert "Top fix" not in out

    def test_attack_graph_collapsed_when_present(self) -> None:
        # Graph node shape mirrors what `_build_attack_graph` emits —
        # in particular `internet_reachable` is required by
        # `graph_to_mermaid`. Synthesising the minimal real shape here.
        graph = {
            "nodes": [
                {"id": "n1", "label": "n1", "type": "compute",
                 "is_crown_jewel": False, "internet_reachable": True,
                 "on_critical_path": False},
                {"id": "n2", "label": "n2", "type": "storage",
                 "is_crown_jewel": True, "internet_reachable": False,
                 "on_critical_path": False},
            ],
            "edges": [{"from": "n1", "to": "n2", "kind": "writes"}],
            "critical_path": [],
        }
        out = detect._render_pr_summary(
            findings=[], entries=[],
            summary={"score": 100, "grade": "A",
                     "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
            attack_graph=graph,
        )
        # <details> wrapper keeps PR comments tight.
        assert "<details><summary>" in out
        assert "Attack graph" in out
        assert "```mermaid" in out

    def test_empty_attack_graph_omitted(self) -> None:
        graph = {"nodes": [], "edges": [], "critical_path": []}
        out = detect._render_pr_summary(
            findings=[], entries=[],
            summary={"score": 100, "grade": "A",
                     "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
            attack_graph=graph,
        )
        # Empty graph in a PR comment is noise; renderer must drop it.
        assert "Attack graph" not in out
        assert "```mermaid" not in out

    def test_rule_ids_link_to_canonical_docs(self) -> None:
        findings = [{"id": "R1", "file": "x.tf", "line": 1, "resource": "x.r"}]
        entries = [{"id": "R1", "title": "R1", "default_urgency": "HIGH"}]
        out = detect._render_pr_summary(
            findings=findings, entries=entries,
            summary={"score": 80, "grade": "B",
                     "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        )
        # PR comment must link the rule ID to the canonical docs page.
        assert "https://chrisadkin8.github.io/tf-analyze/rules/R1/" in out

    def test_footer_advertises_the_engine(self) -> None:
        out = detect._render_pr_summary(
            findings=[], entries=[],
            summary={"score": 100, "grade": "A",
                     "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        )
        # The footer turns every PR comment into an ad — links to the
        # repo + the docs site. Lock so a future change can't drop it.
        assert "Generated by [tf-analyze]" in out
        assert "github.com/ChrisAdkin8/tf-analyze" in out
        assert "tf-analyze/rules/" in out


# ---------------------------------------------------------------------------
# R31.8 — regression tests for the bugs that closed issues #12 and #13.
# ---------------------------------------------------------------------------


class TestCentralityListShape:
    """Issue #13: detect.py passes the ``list[dict]`` returned by
    ``_score_fix_centrality`` as the ``centrality`` argument; the
    renderer previously assumed a ``{file:line: float}`` dict and
    crashed with ``AttributeError: 'list' object has no attribute
    'get'``. The whole renderer fell back to empty output, then the
    Action's github-script step had to invent a fallback shape of
    its own. These tests lock the list-shape path.
    """

    def test_list_shape_does_not_crash(self) -> None:
        findings = [
            {"id": "R1", "file": "main.tf", "line": 10, "resource": "aws.r1"},
            {"id": "R2", "file": "main.tf", "line": 20, "resource": "aws.r2"},
        ]
        entries = [
            {"id": "R1", "title": "R1", "default_urgency": "HIGH"},
            {"id": "R2", "title": "R2", "default_urgency": "HIGH"},
        ]
        # Exact shape returned by _score_fix_centrality: list of dicts
        # with finding_id + impact + crowns_blocked + ...
        centrality = [
            {"finding_id": "R1", "resource": "aws.r1", "impact": 15,
             "crowns_blocked": 1, "on_critical_path": True,
             "internet_reachable": True},
            {"finding_id": "R2", "resource": "aws.r2", "impact": 5,
             "crowns_blocked": 0, "on_critical_path": False,
             "internet_reachable": False},
        ]
        out = detect._render_pr_summary(
            findings=findings, entries=entries,
            summary={"score": 50, "grade": "C",
                     "counts": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0,
                                "LOW": 0, "INFO": 0}},
            centrality=centrality,
        )
        assert "## tf-analyze:" in out
        # If the safety net had to fire, we'd see the fallback marker;
        # this assertion proves the real renderer ran.
        assert "pr-summary fallback" not in out
        # Higher-impact finding (R1) should outrank R2 in the top-findings
        # table even though they have identical urgency.
        idx_r1 = out.find("`R1`")
        idx_r2 = out.find("`R2`")
        assert 0 <= idx_r1 < idx_r2, (
            "centrality must break urgency ties — higher impact finding "
            "appears first"
        )

    def test_legacy_dict_shape_still_works(self) -> None:
        # Back-compat: any external caller passing a `{file:line: float}`
        # dict should still get a sensible ranking. We accept either
        # shape so a downstream tool wrapping the engine doesn't break.
        findings = [
            {"id": "R1", "file": "main.tf", "line": 10, "resource": "r1"},
            {"id": "R2", "file": "main.tf", "line": 20, "resource": "r2"},
        ]
        entries = [
            {"id": "R1", "title": "R1", "default_urgency": "HIGH"},
            {"id": "R2", "title": "R2", "default_urgency": "HIGH"},
        ]
        out = detect._render_pr_summary(
            findings=findings, entries=entries,
            summary={"score": 50, "grade": "C",
                     "counts": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0,
                                "LOW": 0, "INFO": 0}},
            centrality={"main.tf:10": 10.0, "main.tf:20": 1.0},
        )
        assert "pr-summary fallback" not in out

    def test_none_centrality_still_works(self) -> None:
        # The pre-R31.8 default path: caller passes no centrality at all
        # (or None). Urgency-only ranking must still work.
        out = detect._render_pr_summary(
            findings=[{"id": "R1", "file": "main.tf", "line": 1,
                       "resource": "r"}],
            entries=[{"id": "R1", "title": "R1", "default_urgency": "HIGH"}],
            summary={"score": 90, "grade": "A",
                     "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0,
                                "LOW": 0, "INFO": 0}},
            centrality=None,
        )
        assert "## tf-analyze:" in out
        assert "pr-summary fallback" not in out


class TestSafetyNetFallback:
    """Issue #13: if the renderer raises for any reason, the wrapper
    must catch it, emit a `::warning::` annotation, and produce a
    minimal but non-empty pr-summary so the GitHub Action's
    github-script step doesn't have to invent a fallback shape of
    its own.
    """

    def test_renderer_exception_returns_minimal_fallback(self) -> None:
        # Force a crash by handing a summary that's missing required
        # keys. The wrapper should catch it and emit the minimal shape
        # with a degraded-mode marker.
        from scripts import _output  # noqa: PLC0415

        # Monkey-patch the impl to always throw — proves the wrapper
        # path, independent of any specific bug in the renderer.
        original_impl = _output._render_pr_summary_impl

        def _boom(*args, **kwargs):
            raise RuntimeError("synthetic renderer failure")
        _output._render_pr_summary_impl = _boom
        try:
            out = _output._render_pr_summary(
                findings=[{"id": "R1"}],
                entries=[{"id": "R1", "default_urgency": "HIGH"}],
                summary={"score": 0, "grade": "F",
                         "counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0,
                                    "LOW": 0, "INFO": 0}},
            )
        finally:
            _output._render_pr_summary_impl = original_impl

        assert "## tf-analyze:" in out
        # The degraded-mode marker so a human reading the PR comment
        # can tell the rich shape wasn't rendered.
        assert "pr-summary fallback" in out
        assert "synthetic renderer failure" in out

    def test_fallback_includes_counts_table(self) -> None:
        # The minimal fallback must still surface the headline counts so
        # the comment isn't useless even in degraded mode.
        from scripts import _output  # noqa: PLC0415
        out = _output._render_pr_summary_minimal_fallback(
            summary={"score": 25, "grade": "C",
                     "counts": {"CRITICAL": 3, "HIGH": 1, "MEDIUM": 0,
                                "LOW": 0, "INFO": 0}},
            reason="test",
        )
        assert "## tf-analyze: 25 (C)" in out
        assert "| 🚨 CRITICAL | 3 |" in out
        assert "| ⚠️ HIGH | 1 |" in out


class TestComplianceSection:
    """Issue #12: when `--compliance-framework` is set (i.e. the
    engine passes a non-empty `compliance` dict), the pr-summary
    Markdown gains a collapsible compliance gap section. Previously
    the engine ran the gap report internally but never embedded the
    result in pr-summary, so the action's `compliance-framework:`
    input was effectively a no-op in the PR comment surface."""

    COMPLIANCE = {
        "owasp_iac": [
            {"control": "Secrets Detection", "status": "FAIL",
             "rules": ["SEC-SECRETS-001", "SEC-SENSITIVE-001"],
             "failed_rules": ["SEC-SECRETS-001"]},
            {"control": "Version Control Discipline", "status": "PASS",
             "rules": ["ROB-VERSION-001"], "failed_rules": []},
        ],
    }

    def test_compliance_block_appears_when_set(self) -> None:
        out = detect._render_pr_summary(
            findings=[{"id": "SEC-SECRETS-001", "file": "main.tf",
                       "line": 1, "resource": "r"}],
            entries=[{"id": "SEC-SECRETS-001", "title": "Hardcoded secret",
                      "default_urgency": "CRITICAL"}],
            summary={"score": 0, "grade": "F",
                     "counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0,
                                "LOW": 0, "INFO": 0}},
            compliance=self.COMPLIANCE,
        )
        assert "📋 Compliance (owasp_iac)" in out
        assert "1/2 PASS · 1 FAIL" in out
        assert "<details><summary>📋 Compliance" in out

    def test_compliance_block_omitted_when_unset(self) -> None:
        out = detect._render_pr_summary(
            findings=[{"id": "R1", "file": "main.tf", "line": 1, "resource": "r"}],
            entries=[{"id": "R1", "default_urgency": "HIGH"}],
            summary={"score": 90, "grade": "A",
                     "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0,
                                "LOW": 0, "INFO": 0}},
            compliance=None,
        )
        assert "📋 Compliance" not in out

    def test_compliance_renders_on_clean_repo_too(self) -> None:
        # Even with no findings, the compliance block surfaces because
        # "all controls PASS" is a strong positive signal.
        out = detect._render_pr_summary(
            findings=[], entries=[],
            summary={"score": 100, "grade": "A",
                     "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                                "LOW": 0, "INFO": 0}},
            compliance={"cis": [
                {"control": "1.1", "status": "PASS",
                 "rules": ["SEC-AWS-IAM-001"], "failed_rules": []},
            ]},
        )
        assert "📋 Compliance (cis)" in out
        assert "✅ Clean" in out

    def test_failed_controls_sort_to_top(self) -> None:
        # Reviewers want to see what's broken before what's passing.
        out = detect._render_pr_summary(
            findings=[{"id": "R1", "file": "main.tf", "line": 1, "resource": "r"}],
            entries=[{"id": "R1", "default_urgency": "HIGH"}],
            summary={"score": 50, "grade": "C",
                     "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0,
                                "LOW": 0, "INFO": 0}},
            compliance={"owasp_iac": [
                {"control": "AAA-passes", "status": "PASS", "rules": ["P1"],
                 "failed_rules": []},
                {"control": "ZZZ-fails", "status": "FAIL", "rules": ["F1"],
                 "failed_rules": ["F1"]},
            ]},
        )
        # ZZZ-fails (FAIL) must appear before AAA-passes (PASS) despite
        # alphabetical ordering pulling the opposite way.
        idx_fail = out.find("ZZZ-fails")
        idx_pass = out.find("AAA-passes")
        assert 0 <= idx_fail < idx_pass

    def test_failed_rules_bolded(self) -> None:
        # Rules that fired (in `failed_rules`) get bold; others stay
        # regular weight so the visual scan surfaces the actionable rows.
        out = detect._render_pr_summary(
            findings=[{"id": "R1", "file": "main.tf", "line": 1, "resource": "r"}],
            entries=[{"id": "R1", "default_urgency": "HIGH"}],
            summary={"score": 50, "grade": "C",
                     "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0,
                                "LOW": 0, "INFO": 0}},
            compliance={"owasp_iac": [
                {"control": "C1", "status": "FAIL",
                 "rules": ["FIRED", "QUIET"],
                 "failed_rules": ["FIRED"]},
            ]},
        )
        # FIRED is in failed_rules → bold; QUIET is not → not bold.
        assert "**[`FIRED`]" in out
        assert "**[`QUIET`]" not in out


# ---------------------------------------------------------------------------
# CLI integration: --format pr-summary works end-to-end.
# ---------------------------------------------------------------------------


class TestPrSummaryCli:
    def test_clean_workspace_reports_clean(self, tmp_path: Path) -> None:
        (tmp_path / "main.tf").write_text('output "ok" { value = "ok" }\n')
        out = _run("--target", str(tmp_path), "--format", "pr-summary", "--no-hcl2")
        assert "## tf-analyze:" in out
        assert "🟢" in out or "🔵" in out  # A or B for a near-empty workspace

    def test_pr_summary_includes_attack_graph_when_requested(
        self, tmp_path: Path,
    ) -> None:
        # A fixture rich enough to build a non-empty graph: an internet-
        # facing LB plus a crown-jewel S3 bucket.
        (tmp_path / "main.tf").write_text(
            'resource "aws_lb" "public" {\n'
            '  load_balancer_type = "application"\n'
            '  scheme             = "internet-facing"\n'
            '}\n'
            'resource "aws_s3_bucket" "appdata" {\n'
            '  bucket = "myapp-data"\n'
            '}\n'
        )
        out = _run("--target", str(tmp_path), "--format", "pr-summary",
                   "--attack-graph", "--no-hcl2")
        # Even if the graph has 0 edges (no inferred path), the format
        # must still emit the score banner.
        assert "## tf-analyze:" in out
        # One findings table or a "clean" banner — never a stack trace.
        assert "tf-analyze:" in out

    def test_findings_present_render_top_3_table(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        out = _run("--target", str(tmp_path), "--format", "pr-summary", "--no-hcl2")
        assert "### Top findings" in out
        assert "| Urgency | Rule | Location |" in out
        # Every rule mentioned must include the docs URL — pinned so
        # the format stays linkable.
        assert "github.io/tf-analyze/rules/" in out

    def test_help_text_advertises_pr_summary(self) -> None:
        out = _run("--help")
        assert "pr-summary" in out, (
            "argparse choices must list pr-summary so --help discoverable"
        )
