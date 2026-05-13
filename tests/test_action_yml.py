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
