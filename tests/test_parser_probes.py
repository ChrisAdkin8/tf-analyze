"""Parser-migration probes P1–P6 (tasks/hcl-parser-migration.md §1, Appendix A).

Each probe is a small corpus the regex engine gets wrong today. They are
strict xfails: each must keep failing until the migration step named in
its reason fixes it, at which point the step's PR removes the marker.
A probe that starts passing early fails the build, so a fix can't land
unnoticed (and an unrelated change can't silently "fix" one).
"""
from __future__ import annotations

import pytest

from helpers import FIXTURES_DIR, run_detect


def _ids(probe: str) -> dict[str, str]:
    """rule id -> urgency for every finding on the probe fixture."""
    return {
        f["id"]: f.get("urgency", "")
        for f in run_detect(FIXTURES_DIR / f"parser_probe_{probe}", all_rules=True)
    }


@pytest.mark.xfail(strict=True, reason="Step 4: SG-001 rewrite (ingress only)")
def test_p1_egress_only_open_cidr_is_clean() -> None:
    assert "SEC-AWS-SG-001" not in _ids("p1")


@pytest.mark.xfail(strict=True, reason="Step 4: SG-001 rewrite (variable resolution)")
def test_p2_open_ssh_via_variable_default() -> None:
    assert "SEC-AWS-SG-001" in _ids("p2")


@pytest.mark.xfail(strict=True, reason="Step 4: SG-001 covers aws_vpc_security_group_ingress_rule")
def test_p3_vpc_security_group_ingress_rule() -> None:
    assert "SEC-AWS-SG-001" in _ids("p3")


@pytest.mark.xfail(strict=True, reason="Step 4: SG-001 no longer greps string contents")
def test_p4_cidr_text_inside_heredoc_is_clean() -> None:
    assert "SEC-AWS-SG-001" not in _ids("p4")


def test_p5_tags_key_does_not_satisfy_missing_arg() -> None:
    assert "COST-AWS-RISK-001" in _ids("p5")


@pytest.mark.xfail(strict=True, reason="Step 4: structured escalation (port 22/3389)")
def test_p6_open_ssh_escalates_to_critical() -> None:
    assert _ids("p6").get("SEC-AWS-SG-001") == "CRITICAL"
