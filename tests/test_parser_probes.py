"""Parser-migration probes P1–P6 (tasks/hcl-parser-migration.md §1, Appendix A).

Each probe is a small corpus the regex-only engine got wrong. They began
as strict xfails, each removed by the migration step that fixed it (P5 in
Step 2, the rest in Step 4); they now pin the fixed behaviour.
"""
from __future__ import annotations

from helpers import FIXTURES_DIR, run_detect


def _ids(probe: str) -> dict[str, str]:
    """rule id -> urgency for every finding on the probe fixture."""
    return {
        f["id"]: f.get("urgency", "")
        for f in run_detect(FIXTURES_DIR / f"parser_probe_{probe}", all_rules=True)
    }


def test_p1_egress_only_open_cidr_is_clean() -> None:
    assert "SEC-AWS-SG-001" not in _ids("p1")


def test_p2_open_ssh_via_variable_default() -> None:
    assert "SEC-AWS-SG-001" in _ids("p2")


def test_p3_vpc_security_group_ingress_rule() -> None:
    assert "SEC-AWS-SG-001" in _ids("p3")


def test_p4_cidr_text_inside_heredoc_is_clean() -> None:
    assert "SEC-AWS-SG-001" not in _ids("p4")


def test_p5_tags_key_does_not_satisfy_missing_arg() -> None:
    assert "COST-AWS-RISK-001" in _ids("p5")


def test_p6_open_ssh_escalates_to_critical() -> None:
    assert _ids("p6").get("SEC-AWS-SG-001") == "CRITICAL"
