"""Drift gates for ``integrations/github-action.yml``.

The Action is the load-bearing CI surface — it's what most external
users encounter first — so a regression is publish-blocking, not just
embarrassing. Round 30 P0.2 fixed a critical clone-URL bug where the
action pointed at the wrong repo and would have failed on any external
user's CI; these tests guard against that class of mistake by parsing
the YAML and asserting the contract.

Specifically: the engine repo URL, the engine flags actually invoked
(``--format pr-summary`` is the R28.1 contract), and the inputs
declared (R29 added ``compliance-framework`` parity across surfaces;
R26/R27 added ``attack-graph`` / ``show-info`` user controls).

If you're changing the Action intentionally, update the assertions
here in the same commit so the drift gate stays meaningful.
"""
from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).parent.parent
ACTION_YML = REPO_ROOT / "integrations" / "github-action.yml"


@pytest.fixture(scope="module")
def action() -> dict:
    """Parse ``integrations/github-action.yml`` once per module.

    Returns the parsed YAML dict. Note that PyYAML decodes the YAML
    boolean literal ``on:`` as Python ``True``; we don't depend on the
    trigger block in these tests so the quirk is benign here.
    """
    return yaml.safe_load(ACTION_YML.read_text())


@pytest.fixture(scope="module")
def action_text() -> str:
    """Raw YAML text for grep-style assertions on shell-script bodies.

    Inline ``run: |`` scripts are fully-formed strings in the parsed
    structure, so substring assertions on the raw text catch missing
    flags more cleanly than walking the parsed tree.
    """
    return ACTION_YML.read_text()


# ---------------------------------------------------------------------------
# Critical: clone URL points at the right repo.
# ---------------------------------------------------------------------------


class TestCloneURL:
    """Round 30 P0.2 fix-forward.

    The pre-fix action.yml cloned ``anthropics/claude-code-skills`` and
    then symlinked a non-existent path into ``~/.tf-analyze``. Any
    external user adopting the action would have hit
    ``~/.tf-analyze/scripts/detect.py: No such file or directory`` on
    first CI run. This test makes that class of regression impossible
    to land silently.
    """

    def test_clones_chrisadkin8_tf_analyze(self, action_text: str) -> None:
        assert "github.com/ChrisAdkin8/tf-analyze" in action_text, (
            "action.yml must clone https://github.com/ChrisAdkin8/tf-analyze"
        )

    def test_does_not_clone_unrelated_skills_repo(self, action_text: str) -> None:
        # The pre-fix bug — make sure it can't sneak back in.
        assert "anthropics/claude-code-skills" not in action_text, (
            "action.yml previously cloned the wrong repo; do not regress"
        )

    def test_resolves_engine_into_dot_tf_analyze(self, action_text: str) -> None:
        # detect.py invocations all reference ~/.tf-analyze/scripts/detect.py.
        # The clone step must populate that path directly (no symlink to
        # a non-existent intermediate), so the engine actually exists.
        assert "~/.tf-analyze" in action_text


# ---------------------------------------------------------------------------
# R28.1: engine-rendered PR summary is what posts to the comment.
# ---------------------------------------------------------------------------


class TestPRSummaryContract:
    def test_engine_invoked_with_pr_summary_format(self, action_text: str) -> None:
        # The R28.1 promise — PLAN.md says "action.yml posts --format
        # pr-summary blocks". This test enforces it.
        assert "--format pr-summary" in action_text, (
            "Round 28 R28.1 added --format pr-summary; the action must use it"
        )

    def test_summary_file_is_read_back_into_comment_body(
        self, action_text: str,
    ) -> None:
        # The github-script step reads tf-analyze-summary.md into the
        # PR comment body. If this regresses, the engine's pr-summary
        # output is unused dead code.
        assert "tf-analyze-summary.md" in action_text


# ---------------------------------------------------------------------------
# R29 + R26/R27 inputs.
# ---------------------------------------------------------------------------


class TestInputs:
    def _inputs(self, action: dict) -> dict:
        # The reusable-action inputs are at the top level under `inputs:`.
        # `workflow_dispatch.inputs` is a separate block for manual runs.
        return action.get("inputs", {}) or {}

    def test_fail_on_input_present(self, action: dict) -> None:
        assert "fail-on" in self._inputs(action)

    def test_section_input_present(self, action: dict) -> None:
        assert "section" in self._inputs(action)

    def test_compliance_framework_input_present(self, action: dict) -> None:
        # R29 wired compliance_framework through engine, MCP, provider,
        # Run Task. The Action is the last surface that needed it.
        ins = self._inputs(action)
        assert "compliance-framework" in ins
        desc = ins["compliance-framework"].get("description", "")
        # The five accepted values must be advertised so users don't
        # have to read engine source.
        for fw in ("cis", "pci_dss", "soc2", "owasp_iac", "all"):
            assert fw in desc, f"compliance-framework input description should list {fw!r}"

    def test_attack_graph_input_present(self, action: dict) -> None:
        ins = self._inputs(action)
        assert "attack-graph" in ins

    def test_show_info_input_present(self, action: dict) -> None:
        ins = self._inputs(action)
        assert "show-info" in ins

    def test_ref_input_present_for_pinning(self, action: dict) -> None:
        # Letting users pin to a tag/SHA is a hard prerequisite for
        # reproducible CI. Default 'main' is fine for getting started;
        # pinning is opt-in.
        ins = self._inputs(action)
        assert "ref" in ins


# ---------------------------------------------------------------------------
# Engine call shape: each input maps to a flag the engine actually
# understands. This is a narrow contract test — if it fails because the
# engine renamed a flag, fix the engine OR fix the action; don't paper
# over the failure.
# ---------------------------------------------------------------------------


class TestEngineFlagWiring:
    def test_compliance_framework_flag_used_when_input_set(
        self, action_text: str,
    ) -> None:
        assert "--compliance-framework" in action_text

    def test_attack_graph_flag_used_when_input_true(
        self, action_text: str,
    ) -> None:
        assert "--attack-graph" in action_text

    def test_show_info_flag_used_when_input_true(
        self, action_text: str,
    ) -> None:
        assert "--show-info" in action_text

    def test_section_flag_used_when_input_set(
        self, action_text: str,
    ) -> None:
        assert "--section" in action_text


# ---------------------------------------------------------------------------
# Compliance appendix — when compliance-framework is set, the comment
# gains a collapsible compliance section. Substring assertion is the
# right level here; full template-rendering is github-script's problem.
# ---------------------------------------------------------------------------


class TestComplianceAppendix:
    def test_compliance_text_file_referenced(self, action_text: str) -> None:
        assert "tf-analyze-compliance.txt" in action_text

    def test_compliance_section_uses_collapsible_details(
        self, action_text: str,
    ) -> None:
        # Headline summary must stay scannable; the long compliance
        # block goes inside <details>.
        assert "<details>" in action_text and "📋 Compliance" in action_text
