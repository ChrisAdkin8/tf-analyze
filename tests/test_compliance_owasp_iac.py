"""Tests for the OWASP IaC Cheat Sheet compliance framework.

Pins:
  * `--compliance-framework owasp_iac` is accepted by argparse.
  * `_compliance_gap_report(framework='owasp_iac')` produces a
    `OWASP IaC Cheat Sheet` framework column.
  * The catalogue invariant for `owasp_iac:` shape — every entry
    must be `<Section> / <Item label>` with Section in
    `{Develop and Distribute, Deploy, Runtime}`. Locked here so a
    typo in a future rule edit fails CI.
  * The compliance text renderer auto-sizes the Control column for
    long prose labels (the OWASP cheat sheet uses 30-50-char labels;
    older frameworks use 10-char IDs like `1.2.3`).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"
CATALOG = REPO_ROOT / "catalog"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import detect  # noqa: E402


# ---------------------------------------------------------------------------
# Schema invariants — every owasp_iac: entry parses as <Section> / <Item>.
# ---------------------------------------------------------------------------


_VALID_OWASP_SECTIONS = {"Develop and Distribute", "Deploy", "Runtime"}


class TestOwaspIacCatalogueShape:
    def test_owasp_iac_items_are_well_formed(self) -> None:
        offenders: list[tuple[str, str]] = []
        for path in sorted(CATALOG.glob("*.yaml")):
            data = yaml.safe_load(path.read_text())
            if not isinstance(data, dict):
                continue
            if data.get("status") == "deprecated":
                continue
            owasp = data.get("owasp_iac")
            if not owasp:
                continue
            for item in owasp:
                if " / " not in item:
                    offenders.append((data.get("id", path.stem), item))
                    continue
                section = item.split(" / ", 1)[0]
                if section not in _VALID_OWASP_SECTIONS:
                    offenders.append((data.get("id", path.stem), item))
        assert not offenders, (
            "owasp_iac entries must be `<Section> / <Item>` with Section "
            f"in {sorted(_VALID_OWASP_SECTIONS)}. Offenders: {offenders}"
        )

    def test_at_least_30_rules_have_owasp_iac_mappings(self) -> None:
        # The headline number we promise in the README. If a future
        # change bulk-deletes mappings, this fires before anyone notices
        # the compliance output silently shrunk.
        mapped = 0
        for path in sorted(CATALOG.glob("*.yaml")):
            data = yaml.safe_load(path.read_text())
            if not isinstance(data, dict):
                continue
            if data.get("status") == "deprecated":
                continue
            if data.get("owasp_iac"):
                mapped += 1
        assert mapped >= 30, (
            f"only {mapped} rules carry owasp_iac mappings; expected ≥30. "
            f"A bulk-edit may have stripped the field."
        )


# ---------------------------------------------------------------------------
# Engine wiring — _compliance_gap_report handles owasp_iac.
# ---------------------------------------------------------------------------


class TestComplianceGapReport:
    def _entry(self, *items: str) -> dict:
        return {"id": "TEST-1", "owasp_iac": list(items)}

    def test_owasp_iac_framework_emits_dedicated_column(self) -> None:
        entry = self._entry("Develop and Distribute / Secrets Detection")
        # Finding fires → control should be FAIL.
        report = detect._compliance_gap_report(
            findings=[{"id": "TEST-1"}],
            entries=[entry],
            framework="owasp_iac",
        )
        assert "OWASP IaC Cheat Sheet" in report
        ctrls = report["OWASP IaC Cheat Sheet"]
        assert any(
            c["control"] == "Develop and Distribute / Secrets Detection"
            and c["status"] == "FAIL"
            for c in ctrls
        ), ctrls

    def test_owasp_iac_passes_when_no_finding(self) -> None:
        entry = self._entry("Deploy / Cloud Asset Tagging")
        report = detect._compliance_gap_report(
            findings=[],  # rule didn't fire
            entries=[entry],
            framework="owasp_iac",
        )
        ctrls = report["OWASP IaC Cheat Sheet"]
        assert all(c["status"] == "PASS" for c in ctrls)

    def test_all_framework_combines_owasp_with_others(self) -> None:
        # Same rule mapped to both CIS and OWASP IaC; --framework all
        # must surface both columns.
        entry = {
            "id": "TEST-2",
            "cis": [{"id": "1.2"}],
            "owasp_iac": ["Runtime / Comprehensive Logging Enablement"],
        }
        report = detect._compliance_gap_report(
            findings=[],
            entries=[entry],
            framework="all",
        )
        assert "OWASP IaC Cheat Sheet" in report
        # CIS framework name varies by rule prefix; just assert it's there.
        non_owasp = [k for k in report if k != "OWASP IaC Cheat Sheet"]
        assert non_owasp, (
            "framework=all must combine OWASP IaC with the other "
            f"frameworks; got only {sorted(report)}"
        )

    def test_unmapped_framework_returns_empty(self) -> None:
        # Entry has no owasp_iac field → the framework column shouldn't
        # exist (the renderer prints "no entries mapped" in that case).
        entry = {"id": "TEST-3", "cis": [{"id": "1.1"}]}
        report = detect._compliance_gap_report(
            findings=[],
            entries=[entry],
            framework="owasp_iac",
        )
        assert "OWASP IaC Cheat Sheet" not in report


# ---------------------------------------------------------------------------
# CLI integration — argparse accepts the framework, output renders cleanly.
# ---------------------------------------------------------------------------


def _run(*args: str, cwd: Path | None = None) -> str:
    res = subprocess.run(
        [sys.executable, str(DETECT_PY), *args],
        capture_output=True, text=True, timeout=120,
        cwd=str(cwd) if cwd else None,
    )
    return res.stdout


class TestOwaspIacCli:
    def test_argparse_accepts_owasp_iac_framework(self) -> None:
        out = _run("--help")
        assert "owasp_iac" in out, "argparse choices must list owasp_iac"

    def test_compliance_owasp_iac_runs_clean_on_terragoat(
        self, tmp_path: Path,
    ) -> None:
        # An offending fixture so OWASP-mapped rules fire and render.
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
            'variable "db_password" {\n'
            '  type        = string\n'
            '  description = "missing sensitive=true"\n'
            '}\n'
        )
        out = _run("--target", str(tmp_path),
                   "--format", "compliance",
                   "--compliance-framework", "owasp_iac",
                   "--no-hcl2")
        # Section header must appear.
        assert "OWASP IaC Cheat Sheet" in out, out
        # Long control labels must NOT collide with the Status column —
        # the auto-sized renderer puts at least one space between them.
        for line in out.splitlines():
            if line.startswith("Develop and Distribute") or line.startswith("Deploy") or line.startswith("Runtime"):
                # The Status column is `PASS`/`FAIL`. Find the first one.
                m = re.search(r"\b(PASS|FAIL)\b", line)
                assert m, f"line missing status: {line!r}"
                # Whitespace must precede the status word.
                assert line[m.start() - 1].isspace(), (
                    f"control name collides with status column: {line!r}"
                )

    def test_compliance_html_includes_owasp_iac_section(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "x" {\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        out = _run("--target", str(tmp_path),
                   "--format", "html",
                   "--compliance",
                   "--compliance-framework", "owasp_iac",
                   "--no-hcl2")
        assert "OWASP IaC Cheat Sheet" in out

    def test_compliance_html_escapes_control_and_framework(self) -> None:
        # V2 — control labels (free-text in some frameworks) and framework
        # names (user-supplied via --catalog) must be HTML-escaped, not
        # injected raw into the report.
        out = detect._render_compliance_html({
            "<b>FW</b>": [
                {"control": "<img src=x onerror=alert(1)>",
                 "status": "FAIL", "rules": [], "failed_rules": []},
            ],
        })
        assert "<img src=x onerror=alert(1)>" not in out
        assert "&lt;img src=x onerror=alert(1)&gt;" in out
        assert "<b>FW</b>" not in out
        assert "&lt;b&gt;FW&lt;/b&gt;" in out

    def test_unknown_framework_is_rejected_by_argparse(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "main.tf").write_text("")
        res = subprocess.run(
            [sys.executable, str(DETECT_PY),
             "--target", str(tmp_path),
             "--format", "compliance",
             "--compliance-framework", "made_up"],
            capture_output=True, text=True, timeout=30,
        )
        assert res.returncode != 0
        assert "made_up" in res.stderr or "invalid choice" in res.stderr
