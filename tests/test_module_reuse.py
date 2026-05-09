"""Tests for the Module Reuse Advisor's ROI ("lines saved") signal.

The advisor runs `kind: registry_fingerprint` rules: a directory's
resource cluster matches the shape of a public-registry module
(e.g. `terraform-aws-modules/vpc/aws`), and the engine emits an INFO
finding suggesting the user adopt the module.

Without an actionable number ("you'd save N lines / cut maintenance
overhead by X%") the advisor is interesting trivia. These tests pin
the ROI-estimator behaviour:

  * `_module_reuse_roi` produces a `lines_saved` figure derived from
    the bespoke cluster's actual line count vs. the ~12-line module
    call baseline.
  * The MOD-REUSE-* findings emitted by the engine carry a structured
    `roi` field that downstream consumers (VS Code panel, PR comments)
    can render directly.
  * A 200-line VPC cluster shows ≥ 150 lines saved (the headline
    example from PLAN.md§a.1).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"
FIXTURES_DIR = REPO_ROOT / "fixtures"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import detect  # noqa: E402


# ---------------------------------------------------------------------------
# Unit tests on the estimator
# ---------------------------------------------------------------------------


class TestModuleReuseRoi:
    def test_empty_cluster_produces_zero_saved(self) -> None:
        roi = detect._module_reuse_roi([])
        assert roi["bespoke_lines"] == 0
        assert roi["lines_saved"] == 0
        assert roi["pct_saved"] == 0
        assert roi["resource_count"] == 0

    def test_baseline_replacement_lines_pinned(self) -> None:
        # Bumping the baseline silently inflates every match's
        # "lines saved" figure across the board. Lock the constant
        # so the number stays comparable across repos.
        assert detect._MODULE_CALL_BASELINE_LINES == 12

    def test_lines_saved_is_bespoke_minus_baseline(self) -> None:
        # 5 resources × 20 lines each = 100 lines bespoke
        resources = [{"lines": 20} for _ in range(5)]
        roi = detect._module_reuse_roi(resources)
        assert roi["bespoke_lines"] == 100
        assert roi["replacement_lines"] == 12
        assert roi["lines_saved"] == 88
        assert roi["pct_saved"] == 88
        assert roi["resource_count"] == 5

    def test_tiny_cluster_floors_saved_at_zero(self) -> None:
        # A 3-line cluster shouldn't report negative savings.
        resources = [{"lines": 3}]
        roi = detect._module_reuse_roi(resources)
        assert roi["bespoke_lines"] == 3
        assert roi["lines_saved"] == 0
        assert roi["pct_saved"] == 0


# ---------------------------------------------------------------------------
# Integration: end-to-end engine emits roi on the finding
# ---------------------------------------------------------------------------


def _run_detect(target: Path) -> list[dict]:
    res = subprocess.run(
        [sys.executable, str(DETECT_PY), "--target", str(target),
         "--format", "json", "--show-info"],
        capture_output=True, text=True, timeout=60,
    )
    data = json.loads(res.stdout)
    return data.get("findings", []) if isinstance(data, dict) else data


class TestModuleReuseFindingShape:
    def test_aws_vpc_match_has_roi_field(self) -> None:
        findings = _run_detect(FIXTURES_DIR / "mod_reuse_aws_vpc")
        match = next(
            (f for f in findings if f["id"] == "MOD-REUSE-AWS-VPC-001"),
            None,
        )
        assert match is not None, (
            "MOD-REUSE-AWS-VPC-001 did not fire on its positive fixture; "
            "ROI test cannot proceed"
        )
        roi = match.get("roi")
        assert roi is not None, (
            "MOD-REUSE finding is missing structured `roi` field — "
            "downstream consumers (VS Code panel, PR comments) need it"
        )
        for key in ("bespoke_lines", "replacement_lines",
                    "lines_saved", "pct_saved", "resource_count"):
            assert key in roi, f"roi missing required key {key!r}"
        # The fixture has 7 resources spanning ~50 lines — savings
        # should be at least the difference vs. the 12-line baseline.
        assert roi["resource_count"] >= 5
        assert roi["bespoke_lines"] >= 30
        assert roi["lines_saved"] > 0
        assert 0 < roi["pct_saved"] <= 100

    def test_context_string_advertises_lines_saved(self) -> None:
        # Plain-text consumers (the CLI text formatter, PR comment
        # body) read `context`. Embed the ROI hint there so the
        # signal isn't only available to JSON consumers.
        findings = _run_detect(FIXTURES_DIR / "mod_reuse_aws_vpc")
        match = next(f for f in findings if f["id"] == "MOD-REUSE-AWS-VPC-001")
        ctx = match.get("context", "")
        assert "lines saved" in ctx, (
            f"context should advertise lines saved; got: {ctx!r}"
        )


class TestRoiHeadlineScale:
    """The PLAN.md acceptance criterion: 'a 200-line VPC asserts savings ≥ 150 lines'.

    Synthesise a cluster matching the AWS VPC fingerprint at the
    target line count and verify the estimator surfaces the headline
    figure correctly.
    """

    def test_200_line_vpc_asserts_savings_geq_150(self, tmp_path: Path) -> None:
        # Build a VPC cluster whose total line span exceeds 200 lines.
        # The fingerprint for terraform-aws-modules/vpc/aws requires
        # aws_vpc + ≥ 3 supporting types from {aws_subnet,
        # aws_internet_gateway, aws_nat_gateway, aws_route_table,
        # aws_route_table_association, aws_eip, …}.
        #
        # We pad each resource block with comment lines so the total
        # lands at ≥ 200 lines. Comments are part of the AST line
        # span (find_blocks counts every line between the opening and
        # closing braces).
        pad = "\n".join(f"  # comment line {i}" for i in range(28))
        chunks = [
            f'resource "aws_vpc" "main" {{\n  cidr_block = "10.0.0.0/16"\n{pad}\n}}\n',
            f'resource "aws_subnet" "a" {{\n  vpc_id = aws_vpc.main.id\n  cidr_block = "10.0.1.0/24"\n{pad}\n}}\n',
            f'resource "aws_subnet" "b" {{\n  vpc_id = aws_vpc.main.id\n  cidr_block = "10.0.2.0/24"\n{pad}\n}}\n',
            f'resource "aws_internet_gateway" "igw" {{\n  vpc_id = aws_vpc.main.id\n{pad}\n}}\n',
            f'resource "aws_route_table" "public" {{\n  vpc_id = aws_vpc.main.id\n{pad}\n}}\n',
            f'resource "aws_route_table_association" "a" {{\n  subnet_id = aws_subnet.a.id\n  route_table_id = aws_route_table.public.id\n{pad}\n}}\n',
            f'resource "aws_nat_gateway" "ngw" {{\n  subnet_id = aws_subnet.a.id\n{pad}\n}}\n',
        ]
        (tmp_path / "main.tf").write_text("\n".join(chunks))
        # Sanity: the synthetic file is at least 200 lines.
        assert (tmp_path / "main.tf").read_text().count("\n") >= 200

        findings = _run_detect(tmp_path)
        match = next(
            (f for f in findings if f["id"] == "MOD-REUSE-AWS-VPC-001"),
            None,
        )
        assert match is not None, (
            "fingerprint did not match the synthetic 200-line VPC; "
            f"findings fired: {[f['id'] for f in findings]}"
        )
        roi = match["roi"]
        assert roi["bespoke_lines"] >= 200, (
            f"bespoke_lines should be >= 200, got {roi['bespoke_lines']}"
        )
        assert roi["lines_saved"] >= 150, (
            f"PLAN.md acceptance: 200-line VPC must report >= 150 "
            f"lines saved; got {roi['lines_saved']}"
        )
