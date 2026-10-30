"""A plan-only scan must find what it can and say what it could not.

In plan-only mode (a Run Task has the plan and no source) every rule
outside five pattern kinds used to be skipped without a word: a plan with
an admin IAM policy, SSH open to the world and a public bucket policy
scored 100 (A), exited 0, and the Run Task said "passed".
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

REPO = Path(__file__).resolve().parents[1]
DETECT = REPO / "scripts" / "detect.py"
sys.path.insert(0, str(REPO / "scripts"))

from _hcl import parse_tf
from _plan_state import (
    PLAN_ONLY_KINDS,
    PLAN_SUPPORTED_KINDS,
    evaluate_against_resources,
    plan_coverage,
    render_resources_hcl,
)

ADMIN = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
PUBLIC = (
    '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"}]}'
)


def _resource(rtype: str, name: str, values: dict, mode: str = "managed") -> dict:
    prefix = "data." if mode == "data" else ""
    return {
        "address": f"{prefix}{rtype}.{name}",
        "mode": mode,
        "type": rtype,
        "name": name,
        "values": values,
    }


def _plan(*resources: dict, **top) -> dict:
    return {
        "format_version": "1.2",
        "planned_values": {"root_module": {"resources": list(resources)}},
        "resource_changes": [],
        **top,
    }


RISKY = _plan(
    _resource("aws_iam_policy", "admin", {"name": "admin", "policy": ADMIN}),
    _resource(
        "aws_security_group",
        "ssh",
        {
            "name": "ssh",
            "ingress": [
                {
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            ],
        },
    ),
    _resource("aws_s3_bucket_policy", "p", {"bucket": "x", "policy": PUBLIC}),
)
QUIET = _plan(
    _resource("aws_ssm_parameter", "p", {"name": "p", "type": "String", "value": "v"})
)


def _scan(
    tmp_path: Path, plan: dict, *flags: str, source: str = ""
) -> subprocess.CompletedProcess:
    target = tmp_path / "t"
    target.mkdir(exist_ok=True)
    if source:
        (target / "main.tf").write_text(source)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    return subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(target),
            "--plan-json",
            str(path),
            "--no-threat-intel",
            *flags,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_risky_plan_produces_findings_and_fails_the_gate(tmp_path) -> None:
    res = _scan(tmp_path, RISKY, "--fail-on", "HIGH", "--format", "json")
    assert res.returncode == 1, res.stderr
    report = json.loads(res.stdout)
    by_resource = {(f["id"], f["resource"]) for f in report["findings"]}
    assert ("SEC-AWS-IAM-JSON-003", "aws_iam_policy.admin") in by_resource
    assert ("SEC-AWS-IAM-JSON-004", "aws_s3_bucket_policy.p") in by_resource
    assert ("SEC-AWS-SG-001", "aws_security_group.ssh") in by_resource
    assert all(
        f["file"] == "<plan>" and f["mode"] == "plan" for f in report["findings"]
    )
    assert report["summary"]["score"] < 100


def test_port_22_keeps_its_escalation(tmp_path) -> None:
    report = json.loads(_scan(tmp_path, RISKY, "--format", "json").stdout)
    sg = [f for f in report["findings"] if f["id"] == "SEC-AWS-SG-001"]
    assert sg and sg[0]["urgency"] == "CRITICAL"


def test_data_source_read_during_planning_is_analysed(tmp_path) -> None:
    """`aws_iam_policy_document` is in `prior_state`, not `planned_values`."""
    plan = _plan(
        prior_state={
            "values": {
                "root_module": {
                    "resources": [
                        _resource(
                            "aws_iam_policy_document",
                            "doc",
                            {
                                "statement": [
                                    {
                                        "effect": "Allow",
                                        "actions": ["*"],
                                        "resources": ["*"],
                                    }
                                ]
                            },
                            "data",
                        )
                    ]
                }
            }
        }
    )
    report = json.loads(_scan(tmp_path, plan, "--format", "json").stdout)
    assert ("SEC-AWS-IAM-POLICY-005", "data.aws_iam_policy_document.doc") in {
        (f["id"], f["resource"]) for f in report["findings"]
    }


def test_findings_keep_the_real_address_of_instances_and_modules(tmp_path) -> None:
    open_sg = {
        "name": "n",
        "ingress": [
            {
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"],
            }
        ],
    }
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        **_resource("aws_security_group", "s", open_sg),
                        "address": "aws_security_group.s[0]",
                    },
                    {
                        **_resource("aws_security_group", "s", open_sg),
                        "address": "aws_security_group.s[1]",
                    },
                ],
                "child_modules": [
                    {
                        "resources": [
                            {
                                **_resource("aws_security_group", "s", open_sg),
                                "address": "module.m.aws_security_group.s",
                            },
                        ]
                    }
                ],
            }
        }
    }
    report = json.loads(_scan(tmp_path, plan, "--format", "json").stdout)
    assert {
        f["resource"] for f in report["findings"] if f["id"] == "SEC-AWS-SG-001"
    } == {
        "aws_security_group.s[0]",
        "aws_security_group.s[1]",
        "module.m.aws_security_group.s",
    }


def test_coverage_is_reported_in_json_and_on_stderr(tmp_path) -> None:
    res = _scan(tmp_path, QUIET, "--format", "json")
    cov = json.loads(res.stdout)["summary"]["coverage"]
    assert cov["partial"] is True and cov["source"] == "plan"
    assert cov["rules_not_evaluated"] == len(cov["not_evaluated_rules"]) > 0
    assert (
        cov["rules_evaluated"]
        + cov["rules_partly_evaluated"]
        + cov["rules_not_evaluated"]
        == cov["rules_total"]
    )
    assert cov["not_evaluated_critical_high"] > 0
    assert "SEC-SECRETS-001" in cov["not_evaluated_rules"]
    assert "WARN: PARTIAL SCAN: plan only" in res.stderr
    assert f"{cov['rules_not_evaluated']} of {cov['rules_total']} rules" in res.stderr


@pytest.mark.parametrize(
    "fmt, marker",
    [
        ("text", "PARTIAL SCAN"),
        ("html", "PARTIAL SCAN"),
        ("pr-summary", "PARTIAL SCAN"),
        ("sarif", "PARTIAL SCAN"),
        ("compliance", "PARTIAL SCAN"),
    ],
)
def test_a_perfect_score_says_it_is_partial_in_every_format(
    tmp_path, fmt, marker
) -> None:
    res = _scan(
        tmp_path,
        QUIET,
        "--format",
        fmt,
        "--show-fixes" if fmt == "html" else "--no-suppress",
    )
    assert marker in res.stdout
    assert "Clean" not in res.stdout or fmt != "pr-summary"


def test_a_scan_with_source_files_is_not_called_partial(tmp_path) -> None:
    res = _scan(
        tmp_path,
        QUIET,
        "--format",
        "json",
        source='resource "aws_ssm_parameter" "p" {\n  name = "p"\n}\n',
    )
    assert "coverage" not in json.loads(res.stdout)["summary"]
    assert "PARTIAL SCAN" not in res.stderr


def test_with_source_files_the_plan_does_not_report_static_kinds_twice(
    tmp_path,
) -> None:
    """The rendered pass is for the plan-only case: alongside source these
    rules ran in static mode, and a second copy would double the penalty."""
    source = (
        'resource "aws_iam_policy" "admin" {\n  name   = "admin"\n'
        '  policy = jsonencode({\n    Statement = [{\n      Effect   = "Allow"\n'
        '      Action   = "*"\n      Resource = "*"\n    }]\n  })\n}\n'
    )
    plan = _plan(
        _resource("aws_iam_policy", "admin", {"name": "admin", "policy": ADMIN})
    )
    report = json.loads(_scan(tmp_path, plan, "--format", "json", source=source).stdout)
    hits = [f for f in report["findings"] if f["id"] == "SEC-AWS-IAM-JSON-003"]
    assert [f["file"] for f in hits] and all(f["file"] != "<plan>" for f in hits)


def test_state_only_scan_gets_the_same_treatment(tmp_path) -> None:
    state = {"values": RISKY["planned_values"]}
    path = tmp_path / "state.json"
    path.write_text(json.dumps(state))
    target = tmp_path / "t"
    target.mkdir()
    res = subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(target),
            "--state-json",
            str(path),
            "--no-threat-intel",
            "--format",
            "json",
            "--fail-on",
            "HIGH",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    report = json.loads(res.stdout)
    assert res.returncode == 1
    assert report["summary"]["coverage"]["source"] == "state"
    assert all(f["mode"] == "state" for f in report["findings"])


# ---- Kinds evaluated natively on a plan-only scan ------------------------------

_COMPANION = {
    "id": "X-1",
    "patterns": [
        {
            "kind": "resource_missing_companion",
            "resource": "aws_vpc",
            "companion": "aws_flow_log",
            "via": "vpc_id",
        }
    ],
}
_ABSENT = {
    "id": "X-2",
    "patterns": [{"kind": "resource_absent", "resource": "aws_cloudtrail"}],
}


def _eval(resources, entries, references=None):
    return [
        f["id"]
        for f in evaluate_against_resources(
            resources,
            entries,
            finding_mode="plan",
            file_marker="<plan>",
            references=references,
            kinds=PLAN_SUPPORTED_KINDS | PLAN_ONLY_KINDS,
        )
    ]


def test_companion_found_through_the_plan_configuration() -> None:
    vpc = _resource("aws_vpc", "v", {})
    log = _resource("aws_flow_log", "f", {})
    assert _eval([vpc], [_COMPANION]) == ["X-1"]
    assert (
        _eval(
            [vpc, log],
            [_COMPANION],
            {"aws_flow_log.f": {"vpc_id": ["aws_vpc.v.id", "aws_vpc.v"]}},
        )
        == []
    )


def test_companion_found_by_id_in_state_where_there_is_no_configuration() -> None:
    vpc = _resource("aws_vpc", "v", {"id": "vpc-1"})
    log = _resource("aws_flow_log", "f", {"vpc_id": "vpc-1"})
    assert _eval([vpc, log], [_COMPANION]) == []


def test_companion_via_a_list_of_arguments() -> None:
    entry = {
        "id": "X-3",
        "patterns": [
            {
                "kind": "resource_missing_companion",
                "resource": "aws_vpc",
                "companion": "aws_flow_log",
                "via": ["vpc_id", "subnet_id"],
            }
        ],
    }
    vpc = _resource("aws_vpc", "v", {"id": "vpc-1"})
    log = _resource("aws_flow_log", "f", {"subnet_id": "vpc-1"})
    assert _eval([vpc, log], [entry]) == []


def test_resource_absent_fires_once_and_only_when_absent() -> None:
    assert _eval([_resource("aws_vpc", "v", {})], [_ABSENT]) == ["X-2"]
    assert _eval([_resource("aws_cloudtrail", "t", {})], [_ABSENT]) == []


def test_a_rule_counts_as_evaluated_only_if_it_really_ran() -> None:
    entries = [
        {
            "id": "A-1",
            "default_urgency": "HIGH",
            "patterns": [{"kind": "resource_arg"}],
        },
        {
            "id": "A-2",
            "default_urgency": "HIGH",
            "patterns": [
                {"kind": "resource_arg"},
                {"kind": "variable_type"},
            ],
        },
        {"id": "A-3", "default_urgency": "CRITICAL", "patterns": [{"kind": "grep"}]},
        {
            "id": "A-4",
            "default_urgency": "LOW",
            "patterns": [{"kind": "module_unused"}],
        },
        {
            "id": "A-5",
            "default_urgency": "HIGH",
            "patterns": [{"kind": "firewall_open_port"}],
        },
    ]
    cov = plan_coverage(entries, "plan")
    assert cov["rules_evaluated"] == 2
    assert cov["rules_partly_evaluated"] == 1
    assert cov["not_evaluated_rules"] == ["A-3", "A-4"]
    assert cov["not_evaluated_critical_high"] == 1


# ---- Rendering --------------------------------------------------------------


def test_template_syntax_in_a_value_stays_literal() -> None:
    policy = '{"Statement":[{"Resource":"arn:aws:s3:::b/${aws:username}/*"}]}'
    text, _ = render_resources_hcl(
        [_resource("aws_iam_policy", "p", {"policy": policy})]
    )
    tree, error = parse_tf(text)
    assert error is None and tree


def test_labels_are_unique_and_map_back() -> None:
    a = _resource("aws_vpc", "v", {})
    b = {**_resource("aws_vpc", "v", {}), "address": "module.m.aws_vpc.v"}
    _, addresses = render_resources_hcl([a, b])
    assert sorted(addresses.values()) == ["aws_vpc.v", "module.m.aws_vpc.v"]


_scalars = (
    st.none() | st.booleans() | st.integers(-(2**40), 2**40) | st.text(max_size=20)
)
_values = st.recursive(
    _scalars,
    lambda inner: (
        st.lists(inner, max_size=3)
        | st.dictionaries(
            st.from_regex(r"[a-z_][a-z0-9_]{0,8}", fullmatch=True), inner, max_size=3
        )
    ),
    max_leaves=8,
)


@settings(max_examples=150, deadline=None)
@given(
    st.dictionaries(
        st.from_regex(r"[a-z_][a-z0-9_]{0,8}", fullmatch=True), _values, max_size=4
    )
)
def test_any_plan_values_render_as_parseable_hcl(values) -> None:
    """A refused rendering stops the scan, so it has to be rare: the values
    are data, and nothing in them may change the shape of the text."""
    text, _ = render_resources_hcl([_resource("aws_vpc", "v", values)])
    assert parse_tf(text)[1] is None, text


# ---- Run Task ---------------------------------------------------------------


def _server():
    pytest.importorskip("fastapi")
    pytest.importorskip("requests")
    path = REPO / "integrations" / "run-task" / "server.py"
    spec = importlib.util.spec_from_file_location("_rt_coverage", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _attributes(server, data: dict, threshold: str = "HIGH") -> dict:
    return server._format_status_body(data, threshold)["data"]["attributes"]


def test_run_task_pass_says_what_was_not_checked(tmp_path) -> None:
    server = _server()
    report = json.loads(_scan(tmp_path, QUIET, "--format", "json").stdout)
    cov = report["summary"]["coverage"]
    attrs = _attributes(server, report)
    assert attrs["status"] == "passed"
    assert "PARTIAL SCAN" in attrs["message"]
    assert (
        f"{cov['rules_not_evaluated']} of {cov['rules_total']} rules"
        in attrs["message"]
    )
    assert "in the rules evaluated" in attrs["message"]


def test_run_task_fails_the_risky_plan_and_still_says_it_is_partial(tmp_path) -> None:
    server = _server()
    report = json.loads(_scan(tmp_path, RISKY, "--format", "json").stdout)
    attrs = _attributes(server, report)
    assert attrs["status"] == "failed"
    assert "PARTIAL SCAN" in attrs["message"]


def test_run_task_without_coverage_data_does_not_read_as_clean() -> None:
    attrs = _attributes(_server(), {"findings": [], "summary": {}})
    assert "PARTIAL SCAN" in attrs["message"] and "unknown" in attrs["message"]
