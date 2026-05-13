"""Drift gates for the published composite action (``action.yml``).

This is a *separate* surface from ``integrations/github-action.yml`` —
the top-level ``action.yml`` is what users consume via
``uses: ChrisAdkin8/tf-analyze@v1``. Round 31 closed a parity gap where
the README advertised ``compliance-framework`` and ``ref`` inputs that
the composite action did not actually accept; this file guards against
that class of regression.

If you add an input here you must also (1) wire it through the run
steps and (2) update the README snippet at L89-95 so the docs stay
honest.
"""
from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).parent.parent
ACTION_YML = REPO_ROOT / "action.yml"


@pytest.fixture(scope="module")
def action() -> dict:
    return yaml.safe_load(ACTION_YML.read_text())


@pytest.fixture(scope="module")
def action_text() -> str:
    return ACTION_YML.read_text()


# ---------------------------------------------------------------------------
# README parity — every input listed in the README snippet must exist.
# ---------------------------------------------------------------------------


class TestReadmeParity:
    """The README snippet at L89-95 is the load-bearing copy-paste — every
    new user encounters it before any other docs. If an advertised input
    is missing from action.yml, GitHub Actions warns at runtime and the
    feature silently no-ops. That's the bug Round 31 fixed; these tests
    keep it fixed."""

    ADVERTISED = {"fail-on", "post-pr-comment", "compliance-framework",
                  "attack-graph", "ref"}

    def test_every_advertised_input_exists(self, action: dict) -> None:
        ins = set(action.get("inputs", {}))
        missing = self.ADVERTISED - ins
        assert not missing, (
            f"README advertises inputs that action.yml doesn't declare: {missing}. "
            f"Either add them to action.yml or remove the README snippet lines."
        )


# ---------------------------------------------------------------------------
# compliance-framework input — present, documented, validated.
# ---------------------------------------------------------------------------


class TestComplianceFrameworkInput:
    def test_input_present(self, action: dict) -> None:
        assert "compliance-framework" in action["inputs"]

    def test_description_lists_all_five_frameworks(self, action: dict) -> None:
        desc = action["inputs"]["compliance-framework"]["description"]
        for fw in ("cis", "pci_dss", "soc2", "owasp_iac", "all"):
            assert fw in desc, (
                f"compliance-framework description must advertise {fw!r} "
                f"so users don't have to read engine source"
            )

    def test_default_is_empty_string(self, action: dict) -> None:
        assert action["inputs"]["compliance-framework"].get("default", "") == ""

    def test_validation_step_present(self, action_text: str) -> None:
        # The run step that rejects unknown framework names. Without this
        # an invalid value silently propagates to detect.py and surfaces
        # as a confusing engine error.
        assert "Validate compliance-framework" in action_text
        assert "cis|pci_dss|soc2|owasp_iac|all" in action_text

    def test_flag_forwarded_to_engine(self, action_text: str) -> None:
        # When set, the input must be appended to the engine args as
        # both --compliance (enable the report) AND --compliance-framework
        # (select the framework). Missing --compliance means the engine
        # ignores the framework selection entirely.
        assert "--compliance --compliance-framework" in action_text


# ---------------------------------------------------------------------------
# ref input — aliases image tag, mutually exclusive with explicit image.
# ---------------------------------------------------------------------------


class TestRefInput:
    def test_input_present(self, action: dict) -> None:
        assert "ref" in action["inputs"]

    def test_default_is_empty_string(self, action: dict) -> None:
        # Empty default = caller pins via `image:` only; `ref:` is opt-in.
        assert action["inputs"]["ref"].get("default", "") == ""

    def test_resolve_image_step_present(self, action_text: str) -> None:
        assert "Resolve image" in action_text

    def test_mutual_exclusion_with_image(self, action_text: str) -> None:
        # Setting both `ref` and a non-default `image` is ambiguous; the
        # action must fail loudly rather than silently picking one.
        assert "mutually exclusive" in action_text

    def test_pull_and_run_use_resolved_image(self, action_text: str) -> None:
        # Both docker pull and docker run must consume the resolved image
        # output, not the raw `inputs.image`. Otherwise `ref:` is wired
        # to nothing.
        assert action_text.count("steps.resolve_image.outputs.image") >= 2


# ---------------------------------------------------------------------------
# R31.6 — `ref` accepts both `v0.2.3` and `0.2.3` forms.
# ---------------------------------------------------------------------------


class TestRefVPrefixHandling:
    """`docker/metadata-action` emits semver image tags WITHOUT a leading
    `v` (`0.2.3`, `0.2`, `latest`). Git tags and every surface a user sees
    (release page, CHANGELOG, marketplace listing) use the `vX.Y.Z` form.
    The action must accept both so a user pasting `ref: v0.2.3` from a
    release URL doesn't 404 when the action tries to pull
    `:v0.2.3` instead of the real `:0.2.3` image."""

    def test_strip_v_guard_pattern_present(self, action_text: str) -> None:
        # The guard prevents non-semver refs like `main` or `vault` from
        # being mangled. The pattern `^v[0-9]` is the stable anchor.
        assert "^v[0-9]" in action_text, (
            "Resolve image step must guard the strip-v rewrite behind "
            "^v[0-9] so non-semver refs (main, vault) aren't truncated"
        )

    def test_strip_v_uses_parameter_expansion(self, action_text: str) -> None:
        # `${TFA_REF#v}` is the idiom for "remove leading v" without
        # spawning a subshell. If this regresses to `sed s/^v//` we
        # lose injection hardening — TFA_REF would be expanded by the
        # external command instead of staying inside bash.
        assert "${TFA_REF#v}" in action_text

    def test_description_advertises_both_forms(self, action: dict) -> None:
        desc = action["inputs"]["ref"]["description"]
        # Description must name both shapes so users don't need to read
        # the action source.
        assert "v0." in desc, "ref description must show the `v`-prefixed form"
        assert "0.2.3" in desc or "0.2.2" in desc, (
            "ref description must show the bare semver form"
        )


# ---------------------------------------------------------------------------
# Hardening — every user-supplied input must flow through `env:` (R5).
# ---------------------------------------------------------------------------


class TestInjectionHardening:
    """Round-5 audit fix #1 moved every user input through `env:` so the
    value is read at runtime instead of templated into the script source.
    The two new inputs must follow the same pattern."""

    def test_compliance_framework_flows_through_env(self, action_text: str) -> None:
        assert "TFA_COMPLIANCE_FW:" in action_text
        assert "${{ inputs.compliance-framework }}" in action_text

    def test_ref_flows_through_env(self, action_text: str) -> None:
        assert "TFA_REF:" in action_text
        assert "${{ inputs.ref }}" in action_text


# ---------------------------------------------------------------------------
# debug-upload-findings input + inline-suggestion logging — R31.9 hardening
# motivated by https://github.com/ChrisAdkin8/tf-analyze/issues/19.
# ---------------------------------------------------------------------------


class TestDebugUploadFindingsInput:
    """Issue #19 surfaced a v0.2.4 → v0.2.5 regression that couldn't be
    diagnosed from the action's existing surfaces: the HTML artifact
    doesn't carry per-finding `line` / `fix_hcl`, and the inline-
    suggestion step had no log output. This input adds an opt-in
    pathway to upload the raw `tf-analyze-findings.json` for debugging.
    """

    def test_input_present(self, action: dict) -> None:
        assert "debug-upload-findings" in action["inputs"]

    def test_default_is_false_string(self, action: dict) -> None:
        # Must be 'false' (string), not False (bool) — GitHub Actions
        # treats inputs as strings and the `== 'true'` guard expects
        # string comparison.
        d = action["inputs"]["debug-upload-findings"].get("default")
        assert d == "false", (
            f"default must be the string 'false' so opt-in semantics hold; "
            f"got {d!r}"
        )

    def test_description_references_issue_19(self, action: dict) -> None:
        # Cross-link to the issue so a future operator hitting a similar
        # zero-comments regression can find the precedent without digging.
        desc = action["inputs"]["debug-upload-findings"]["description"]
        assert "issues/19" in desc, (
            "description must link to issue #19 (the motivating regression) "
            "so future operators find the precedent"
        )

    def test_upload_step_gated_on_input(self, action_text: str) -> None:
        # The step must be conditioned on `inputs.debug-upload-findings == 'true'`
        # so off-by-default semantics actually hold. A missing guard would
        # ship findings.json on every PR run — fine for the demo, bad for
        # private repos using the action.
        assert "inputs.debug-upload-findings == 'true'" in action_text, (
            "upload step must explicitly gate on the input being 'true'"
        )

    def test_upload_step_artifact_named(self, action_text: str) -> None:
        # Distinct artifact name from `tf-analyze-report` (HTML) so the two
        # don't collide and so users can download just the JSON if that's
        # what they need.
        assert "name: tf-analyze-findings-json" in action_text


class TestInlineSuggestionLogging:
    """Issue #19 — the inline-suggestion step posted 0 comments where the
    previous engine version posted 4, and the only signal was the
    summary footer's `_No inline suggestions available_` text. A single
    `core.info()` line with per-skip-reason counters localises the bug
    on next regression without rerunning."""

    def test_skip_reasons_object_emitted(self, action_text: str) -> None:
        # The skipReasons object must enumerate every gate the loop
        # passes through, so a future zero-posted run tells us WHICH
        # gate ate the findings. Bumping a counter without the
        # core.info() at the end would still leave the data unobserved.
        for reason in ("no_fix_hcl", "no_line", "not_in_pr_files",
                       "not_in_diff_hunk", "post_failed"):
            assert reason in action_text, (
                f"skipReasons must track {reason!r} so issue #19-class "
                f"regressions are diagnosable from the log alone"
            )

    def test_summary_line_uses_core_info(self, action_text: str) -> None:
        # core.info() (not console.log) so the line appears in the
        # GitHub Actions log group at INFO level — searchable + grouped
        # consistently with other action steps. core.warning() would be
        # alarming for a steady-state summary line.
        assert "core.info(" in action_text and "inline-suggestion summary" in action_text, (
            "the summary diagnostic must use core.info() and carry the "
            "'inline-suggestion summary' marker so future operators can "
            "grep for it"
        )

    def test_summary_line_grep_friendly(self, action_text: str) -> None:
        # Format must be machine-readable enough for grep + awk on a
        # workflow log dump. Smoke-check key=value pairs are present.
        for key in ("findings=", "posted=", "with_fix_hcl_and_line=",
                    "skipped["):
            assert key in action_text, (
                f"diagnostic line must include {key!r} for greppability"
            )


# ---------------------------------------------------------------------------
# Issue #19 root-cause hardening — diff-mode base-ref pre-fetch.
# ---------------------------------------------------------------------------


class TestDiffBaseHardening:
    """Issue #19 — the demo PR posted 0 inline `suggestion` comments
    because `mode: auto` resolved to `--mode diff` on the PR event, but
    the default ``actions/checkout@v4`` (depth 1) didn't have ``origin/main``
    locally, so the engine's ``_diff.get_diff_files`` returned an empty set
    and the engine scanned 0 files. Restoring ``mode: static`` in the demo
    healed production, but the action itself was the broken contract —
    a caller writing the "obvious" workflow (no ``fetch-depth``, default
    ``mode``) silently got 0 findings on every PR. These tests pin the
    fix: the action now pre-fetches the base ref so diff mode works out
    of the box, and passes an explicit ``--diff-base`` so the engine
    doesn't fall back to its (limited) ``main``/``master`` autodetection."""

    def test_diff_base_step_present(self, action: dict) -> None:
        # The composite must declare a step that ensures the base ref
        # is locally available before running the engine in diff mode.
        # Identified by a stable id; the friendly name is allowed to
        # change but the id is the contract.
        steps = action["runs"]["steps"]
        assert any(s.get("id") == "diff_base" for s in steps), (
            "action.yml must declare a step with id=diff_base that "
            "pre-fetches origin/<base_ref> on PR events when --mode diff "
            "is requested. Without it, default checkout @v4 (depth 1) "
            "users silently get 0 findings on every PR (issue #19)."
        )

    def test_diff_base_step_gated_correctly(self, action: dict) -> None:
        # The pre-fetch must only run when we ACTUALLY need a base ref —
        # i.e., mode resolved to diff AND we're on a pull_request event.
        # Running it unconditionally would (a) waste a fetch on push
        # builds and (b) reference github.base_ref which is empty on
        # non-PR events.
        steps = action["runs"]["steps"]
        step = next(s for s in steps if s.get("id") == "diff_base")
        gate = step.get("if", "")
        assert "diff" in gate and "pull_request" in gate, (
            f"diff_base step `if:` gate must reference both 'diff' mode "
            f"and 'pull_request' event; got {gate!r}"
        )

    def test_diff_base_uses_github_base_ref(self, action_text: str) -> None:
        # The whole point of the step is to fetch the PR's TARGET branch
        # so the engine has something to diff against. github.base_ref
        # is the canonical source — github.ref / GITHUB_REF point at the
        # PR head's merge ref, not the base.
        assert "github.base_ref" in action_text, (
            "action must read github.base_ref to know which branch to "
            "pre-fetch for --mode diff"
        )

    def test_diff_base_emits_warning_on_fetch_failure(self, action_text: str) -> None:
        # If the fetch fails (private fork, network glitch, etc.), the
        # action must SAY SO loudly via ::warning:: rather than continuing
        # silently to a zero-findings scan. The previous failure mode
        # (issue #19) was silent precisely because no warning fired.
        # We also require the issue URL so future operators can pivot
        # quickly to the documented cause.
        assert "::warning::" in action_text and "issues/19" in action_text, (
            "diff_base step must emit a ::warning:: that references "
            "issue #19 when the base-ref fetch fails, so a regressed "
            "fetch surfaces clearly in the workflow log"
        )

    def test_diff_base_passed_to_engine(self, action_text: str) -> None:
        # Pre-fetching is necessary but not sufficient — the engine must
        # be told WHICH ref to diff against. The action's own resolution
        # is `origin/<base_ref>`; the engine's autodetection only checks
        # `main`/`master`, so a workflow targeting `develop` would still
        # miss without this explicit pass-through.
        assert "--diff-base" in action_text, (
            "action must pass --diff-base to detect.py so the engine "
            "doesn't fall back to main/master autodetection"
        )
        assert "TFA_DIFF_BASE" in action_text, (
            "the diff base must flow through an env var (audit fix #1 "
            "pattern) rather than direct ${{ }} interpolation into the "
            "bash array literal"
        )

    def test_diff_base_arg_appended_conditionally(self, action_text: str) -> None:
        # The --diff-base arg must only be appended when the env var is
        # non-empty — otherwise a `mode: static` invocation would get
        # `--diff-base` (empty) and the engine would error on the
        # missing positional. Bash idiom: `if [ -n "${TFA_DIFF_BASE}" ]`.
        assert 'if [ -n "${TFA_DIFF_BASE}" ]' in action_text, (
            "--diff-base must only be added to ARGS when TFA_DIFF_BASE "
            "is non-empty, otherwise static-mode runs would pass an "
            "empty --diff-base and crash"
        )
