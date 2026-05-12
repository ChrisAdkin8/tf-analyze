"""Tests for the R31.2 auto-remediation PR bot.

Two surfaces under test:

  * **Workflow YAML drift gates** — lock the load-bearing fields of
    `integrations/github-action-bot.yml` (triggers, permissions,
    actor-guard, concurrency group, the engine flag the apply step
    passes) so a refactor can't silently weaken the bot's safety
    posture.

  * **PR-body renderer unit tests** — exercise
    `integrations/github-action-bot/render_pr_body.py:compose_body()`
    against synthetic scan + apply-summary inputs. The renderer is a
    pure function, so we don't need to spin up a real GH Actions
    runtime to test its output shape.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
WORKFLOW = REPO_ROOT / "integrations" / "github-action-bot.yml"
RENDERER = REPO_ROOT / "integrations" / "github-action-bot" / "render_pr_body.py"


# Load the renderer as a module so we can call `compose_body()`
# directly without subprocessing it. Module name is mangled so it
# doesn't clash with anything else in tests/.
spec = importlib.util.spec_from_file_location("_bot_render_pr_body", RENDERER)
assert spec and spec.loader, "could not load renderer module"
_render = importlib.util.module_from_spec(spec)
sys.modules["_bot_render_pr_body"] = _render
spec.loader.exec_module(_render)


# ---------------------------------------------------------------------------
# Workflow YAML drift gates
# ---------------------------------------------------------------------------

class TestWorkflowShape:
    """The bot workflow has load-bearing fields a careless edit could
    silently break — strip the actor-guard, escalate the disruption
    cap, drop the concurrency group, etc. These tests are tripwires."""

    @pytest.fixture(scope="class")
    def yaml_text(self) -> str:
        return WORKFLOW.read_text()

    def test_workflow_exists(self, yaml_text: str) -> None:
        assert yaml_text, "workflow file is empty"
        assert "tf-analyze-bot" in yaml_text

    def test_runs_on_schedule_and_manual(self, yaml_text: str) -> None:
        """Scheduled cron + workflow_dispatch both must be present so
        consumers can either let it run weekly or kick it off manually."""
        assert re.search(r"^\s*schedule:", yaml_text, re.MULTILINE)
        assert re.search(r"cron:\s*\"[^\"]+\"", yaml_text)
        assert "workflow_dispatch:" in yaml_text

    def test_permissions_minimum_set(self, yaml_text: str) -> None:
        """The bot writes a branch + opens a PR. It needs exactly
        contents:write + pull-requests:write — no more (no security-events
        scope, no actions:write). Tripwire against scope creep."""
        assert re.search(r"contents:\s*write", yaml_text)
        assert re.search(r"pull-requests:\s*write", yaml_text)
        # Anything broader would be a security gap — flag it.
        assert "security-events: write" not in yaml_text, (
            "bot doesn't upload SARIF — security-events:write is excess scope"
        )
        # `actions: write` would let the bot rewrite workflow files —
        # explicitly excluded.
        assert "actions: write" not in yaml_text

    def test_actor_guard_prevents_self_retrigger(self, yaml_text: str) -> None:
        """The `if: github.actor != 'tf-analyze-bot[bot]'` guard is the
        only thing stopping a feedback loop if the bot's commits were
        ever to trigger the workflow. Drop the guard, get an apply-loop."""
        assert "github.actor != 'tf-analyze-bot[bot]'" in yaml_text

    def test_concurrency_group_set(self, yaml_text: str) -> None:
        """Concurrency: 'tf-analyze-bot' ensures only one bot run at a
        time across this repo. Two parallel applies racing on the same
        branch would clobber each other."""
        assert "concurrency:" in yaml_text
        assert "group: tf-analyze-bot" in yaml_text

    def test_apply_step_uses_max_disruption_none_by_default(self, yaml_text: str) -> None:
        """The bot ships safe-by-default — the disruption cap must
        default to 'none' even if the workflow_dispatch input is
        omitted. The `${{ ... || 'none' }}` shape is what GitHub
        Actions uses for input defaults; the test asserts that form."""
        assert "--apply-fixes-max-disruption" in yaml_text
        # Default is 'none' both in the input declaration and the shell
        # fallback. Both must be present so neither path opens the
        # disruption cap up.
        assert re.search(r"max-disruption:\s*\n\s+description:[^\n]+\n\s+required:[^\n]+\n\s+default:\s*\"none\"", yaml_text), (
            "max-disruption input default must be 'none'"
        )
        # Shell fallback if the input is unset.
        assert "max-disruption || 'none'" in yaml_text

    def test_force_push_branch_reuse(self, yaml_text: str) -> None:
        """One PR per repo — bot must force-push the same branch each
        run, not spawn a new branch every time."""
        assert "BRANCH=\"tf-analyze-bot/auto-fixes\"" in yaml_text
        assert "git push --force origin" in yaml_text

    def test_pr_is_idempotent_create_or_edit(self, yaml_text: str) -> None:
        """If a PR already exists for the bot branch, the workflow
        edits its body in place rather than creating a duplicate.
        Re-confirms the one-PR-per-repo guarantee."""
        assert "gh pr list --head" in yaml_text
        assert "gh pr create" in yaml_text
        assert "gh pr edit" in yaml_text

    def test_engine_install_pins_ref(self, yaml_text: str) -> None:
        """The bot clones tf-analyze; the ref must come from the
        `ref` input so consumers can pin to a release tag for
        reproducibility. Default is 'main' which is acceptable for
        the bot's auto-update behaviour."""
        assert "ref:" in yaml_text
        assert 'default: "main"' in yaml_text
        assert "git clone --depth 1 --branch \"$ref\"" in yaml_text


# ---------------------------------------------------------------------------
# PR-body renderer
# ---------------------------------------------------------------------------

class TestComposeBody:
    """``render_pr_body.compose_body()`` is the only piece of bot logic
    that's worth more than a YAML regex — it converts scan JSON +
    apply-summary text into the Markdown a reviewer reads. Tests use
    synthetic inputs so they don't depend on the engine running."""

    def _scan(self, findings: list[dict], score: int = 80, grade: str = "B") -> dict:
        return {
            "summary": {
                "score": score, "grade": grade,
                "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": len(findings), "INFO": 0},
            },
            "findings": findings,
        }

    def test_groups_by_family_prefix(self) -> None:
        """`SEC-AWS-IAM-001` and `SEC-AWS-IAM-002` collapse to
        `SEC-AWS-IAM-*` in the table. `ROB-COUNT-NAME-001` lives in
        its own row. The grouping mirrors the per-rule docs site's
        family-backlinks logic."""
        findings = [
            {"id": "SEC-AWS-IAM-001", "fix_disruption": "none"},
            {"id": "SEC-AWS-IAM-002", "fix_disruption": "none"},
            {"id": "ROB-COUNT-NAME-001", "fix_disruption": "none"},
        ]
        body = _render.compose_body(self._scan(findings), "")
        assert "`SEC-AWS-IAM-*` | 2" in body
        assert "`ROB-COUNT-NAME-*` | 1" in body

    def test_headline_uses_apply_summary_when_present(self) -> None:
        """The 'N fixes across M files' headline reads from the
        engine's stderr line, not from the JSON. Files count isn't
        in the JSON, only in the stderr."""
        scan = self._scan([{"id": "SEC-AWS-S3-001", "fix_disruption": "none"}])
        apply = "# apply-fixes: would apply 7 fix(es) across 4 file(s)\n"
        body = _render.compose_body(scan, apply)
        assert "**7 non-disruptive fix(es)**" in body
        assert "across 4 file(s)" in body

    def test_skipped_section_only_when_non_zero(self) -> None:
        """The 'Intentionally skipped' section only renders when the
        engine actually skipped findings above the disruption cap.
        Zero skipped → section omitted entirely."""
        scan = self._scan([{"id": "SEC-AWS-S3-001", "fix_disruption": "none"}])
        body = _render.compose_body(scan, "# apply-fixes: would apply 1 fix(es) across 1 file(s)\n")
        assert "Intentionally skipped" not in body

        body_with_skips = _render.compose_body(
            scan,
            "# apply-fixes: skipping 4 finding(s) above disruption cap 'none' (1 eligible for auto-patch)\n"
            "# apply-fixes: would apply 1 fix(es) across 1 file(s)\n"
        )
        assert "Intentionally skipped" in body_with_skips
        assert "4 additional finding(s)" in body_with_skips

    def test_score_and_grade_in_body(self) -> None:
        """The pre-fix score + grade head the body so reviewers see
        the baseline at a glance."""
        scan = self._scan([{"id": "X-001", "fix_disruption": "none"}], score=42, grade="D")
        body = _render.compose_body(scan, "")
        assert "**42 (D)**" in body

    def test_filters_to_non_disruptive_in_table(self) -> None:
        """Findings whose `fix_disruption` is anything other than
        `none` (or absent → treat as `none` per engine convention)
        must not appear in the by-family table — they weren't fixed."""
        findings = [
            {"id": "SAFE-001", "fix_disruption": "none"},
            {"id": "RISKY-001", "fix_disruption": "forces_replacement"},
            {"id": "PLANIT-001", "fix_disruption": "plan_required"},
        ]
        body = _render.compose_body(self._scan(findings), "")
        # SAFE-001 (none) appears.
        assert "`SAFE-*`" in body
        # The disruptive ones don't.
        assert "`RISKY-*`" not in body
        assert "`PLANIT-*`" not in body

    def test_empty_findings_still_renders_provenance(self) -> None:
        """Zero findings → the headline collapses to 'zero fixes'
        but the provenance footer (workflow path, engine link)
        is still emitted. Defensive: someone might link the body
        URL even on an empty run."""
        body = _render.compose_body(self._scan([]), "")
        assert "Provenance" in body
        assert "tf-analyze-bot/auto-fixes" in body

    def test_family_of_handles_non_numeric_suffix(self) -> None:
        """`family_of("CUSTOM-NO-NUMBER")` should return the input
        verbatim — only strip trailing `-NNN` when present."""
        assert _render.family_of("SEC-AWS-IAM-001") == "SEC-AWS-IAM"
        assert _render.family_of("CUSTOM-NO-NUMBER") == "CUSTOM-NO-NUMBER"
        assert _render.family_of("FOO") == "FOO"
