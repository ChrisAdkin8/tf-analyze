"""Plan-only scans: what a plan can't show, and plans this reader can't trust.

A value unknown until apply is simply missing from `planned_values`, so a
rule looking at it found nothing and counted as evaluated. And a plan whose
sections have moved read as "no resources": score 100, exit 0.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DETECT = REPO / "scripts" / "detect.py"
sys.path.insert(0, str(REPO / "scripts"))

import _plan_state
from _hcl import parse_tf
from _plan_state import (
    PLAN_ONLY_KINDS,
    PLAN_SUPPORTED_KINDS,
    PlanInputError,
    detect_in_plan,
    evaluate_against_resources,
    relevant_args,
    render_resources_hcl,
    unknown_arguments,
)


def _res(rtype, name, values, mode="managed", address=None):
    prefix = "data." if mode == "data" else ""
    return {
        "address": address or f"{prefix}{rtype}.{name}",
        "mode": mode,
        "type": rtype,
        "name": name,
        "values": values,
    }


def _change(rtype, name, unknown, actions=("create",), mode="managed", **extra):
    prefix = "data." if mode == "data" else ""
    return {
        "address": f"{prefix}{rtype}.{name}",
        "mode": mode,
        "type": rtype,
        "name": name,
        "change": {"actions": list(actions), "after_unknown": unknown},
        **extra,
    }


# As `terraform show -json` writes it. A bucket policy written with
# jsonencode() and an unknown ARN is unknown as a whole: the `"*"` beside the
# reference is not in the plan, and the configuration keeps the references.
INLINE = {
    "format_version": "1.2",
    "planned_values": {
        "root_module": {
            "resources": [
                _res("aws_s3_bucket", "b", {"bucket": "b"}),
                _res("aws_s3_bucket_policy", "inline", {}),
                _res(
                    "aws_security_group",
                    "sg",
                    {
                        "name": "sg",
                        "ingress": [
                            {"from_port": 22, "to_port": 22, "protocol": "tcp"},
                        ],
                    },
                ),
            ]
        }
    },
    "resource_changes": [
        _change("aws_s3_bucket", "b", {"arn": True, "id": True, "policy": True}),
        _change(
            "aws_s3_bucket_policy",
            "inline",
            {"policy": True, "bucket": True, "id": True},
        ),
        _change(
            "aws_security_group",
            "sg",
            {
                "id": True,
                "arn": True,
                "ingress": [
                    {"cidr_blocks": True},
                ],
            },
        ),
    ],
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket.b",
                    "expressions": {"bucket": {"constant_value": "b"}},
                },
                {
                    "address": "aws_s3_bucket_policy.inline",
                    "expressions": {
                        "bucket": {"references": ["aws_s3_bucket.b.id"]},
                        "policy": {"references": ["aws_s3_bucket.b.arn"]},
                    },
                },
                {
                    "address": "aws_security_group.sg",
                    "expressions": {
                        "name": {"constant_value": "sg"},
                        "ingress": [{}],
                    },
                },
            ]
        }
    },
}

# A data source that depends on something unknown is read at apply, and its
# statements stay in the plan, the unknown parts as null.
DOCS = {
    "format_version": "1.2",
    "planned_values": {
        "root_module": {
            "resources": [
                _res(
                    "aws_iam_policy_document",
                    "public",
                    {
                        "statement": [
                            {
                                "actions": ["s3:*"],
                                "resources": [None],
                                "principals": [{"type": "*", "identifiers": ["*"]}],
                            }
                        ]
                    },
                    "data",
                ),
                _res(
                    "aws_iam_policy_document",
                    "admin",
                    {
                        "statement": [
                            {
                                "actions": ["*"],
                                "resources": ["*"],
                                "condition": [
                                    {
                                        "test": "StringEquals",
                                        "variable": "aws:x",
                                        "values": [None],
                                    }
                                ],
                            }
                        ]
                    },
                    "data",
                ),
            ]
        }
    },
    "resource_changes": [
        _change(
            "aws_iam_policy_document",
            "public",
            {
                "json": True,
                "statement": [
                    {"resources": [True]},
                ],
            },
            ("read",),
            "data",
        ),
        _change(
            "aws_iam_policy_document",
            "admin",
            {
                "json": True,
                "statement": [
                    {"condition": [{"values": [True]}]},
                ],
            },
            ("read",),
            "data",
        ),
    ],
}


def _scan(tmp_path: Path, plan: dict, *flags: str) -> subprocess.CompletedProcess:
    target = tmp_path / "t"
    target.mkdir(exist_ok=True)
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


def test_an_unknown_resource_does_not_save_a_public_principal(tmp_path) -> None:
    res = _scan(tmp_path, DOCS, "--format", "json", "--fail-on", "HIGH")
    ids = {(f["id"], f["resource"]) for f in json.loads(res.stdout)["findings"]}
    assert ("SEC-AWS-IAM-POLICY-004", "data.aws_iam_policy_document.public") in ids
    assert res.returncode == 1


def test_an_unknown_condition_does_not_hide_an_admin_policy(tmp_path) -> None:
    res = _scan(tmp_path, DOCS, "--format", "json")
    ids = {(f["id"], f["resource"]) for f in json.loads(res.stdout)["findings"]}
    assert ("SEC-AWS-IAM-POLICY-005", "data.aws_iam_policy_document.admin") in ids


def test_unknown_rule_relevant_arguments_are_named(tmp_path) -> None:
    cov = json.loads(_scan(tmp_path, INLINE, "--format", "json").stdout)["summary"][
        "coverage"
    ]
    assert cov["resources_with_unknown_values"] == 2
    assert {"resource": "aws_s3_bucket_policy.inline", "arguments": ["policy"]} in cov[
        "unknown_values"
    ]
    assert {"resource": "aws_security_group.sg", "arguments": ["ingress"]} in cov[
        "unknown_values"
    ]


def test_a_computed_attribute_nobody_set_is_not_named(tmp_path) -> None:
    """`aws_s3_bucket.policy` is unknown on every new bucket."""
    cov = json.loads(_scan(tmp_path, INLINE, "--format", "json").stdout)["summary"][
        "coverage"
    ]
    assert "aws_s3_bucket.b" not in {u["resource"] for u in cov["unknown_values"]}


def test_unknown_values_reach_the_report_line(tmp_path) -> None:
    res = _scan(tmp_path, INLINE, "--format", "text")
    assert "aws_s3_bucket_policy.inline (policy)" in res.stdout
    assert "aws_s3_bucket_policy.inline (policy)" in res.stderr


def test_a_plan_with_no_unknowns_names_none(tmp_path) -> None:
    plan = {
        "planned_values": {"root_module": {"resources": [_res("aws_vpc", "v", {})]}}
    }
    cov = json.loads(_scan(tmp_path, plan, "--format", "json").stdout)["summary"][
        "coverage"
    ]
    assert cov["resources_with_unknown_values"] == 0 and cov["unknown_values"] == []
    assert "unknown until apply" not in _scan(tmp_path, plan, "--format", "text").stdout


def test_an_argument_no_rule_reads_is_not_named() -> None:
    entries = [
        {
            "id": "X-1",
            "patterns": [
                {
                    "kind": "resource_arg",
                    "resource": "aws_x",
                    "arg": "wanted",
                    "regex": "a",
                },
            ],
        }
    ]
    plan = {
        "resource_changes": [_change("aws_x", "y", {"wanted": True, "other": True})]
    }
    assert unknown_arguments(plan, entries) == [
        {"resource": "aws_x.y", "arguments": ["wanted"]}
    ]


def test_relevant_args_cover_the_escalation_too() -> None:
    entries = [
        {
            "id": "X-1",
            "escalation": [{"match": {"name": "x", "ports": [22]}}],
            "patterns": [
                {
                    "kind": "resource_arg",
                    "resource": "aws_x",
                    "arg": "a.b",
                    "regex": "a",
                },
            ],
        }
    ]
    assert relevant_args(entries) == {"aws_x": {"a", "name"}}


# ---- ECS grep rules stay on ECS -----------------------------------------------


def test_ecs_rules_stay_off_other_resources(tmp_path) -> None:
    secret = json.dumps({"privileged": True, "name": "DB_PASSWORD", "value": "x"})
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    _res("aws_ssm_parameter", "p", {"name": "p", "value": secret}),
                    _res(
                        "aws_secretsmanager_secret_version",
                        "s",
                        {"secret_string": secret},
                    ),
                ]
            }
        }
    }
    ids = {
        f["id"]
        for f in json.loads(_scan(tmp_path, plan, "--format", "json").stdout)[
            "findings"
        ]
    }
    assert not ids & {"SEC-AWS-ECS-001", "SEC-AWS-ECS-002"}


def test_ecs_rules_fire_on_container_definitions(tmp_path) -> None:
    defs = json.dumps(
        [
            {
                "name": "app",
                "privileged": True,
                "environment": [
                    {"name": "DB_PASSWORD", "value": "hunter2hunter2"},
                ],
            }
        ]
    )
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    _res(
                        "aws_ecs_task_definition",
                        "t",
                        {"family": "t", "container_definitions": defs},
                    ),
                ]
            }
        }
    }
    ids = {
        f["id"]
        for f in json.loads(_scan(tmp_path, plan, "--format", "json").stdout)[
            "findings"
        ]
    }
    assert {"SEC-AWS-ECS-001", "SEC-AWS-ECS-002"} <= ids


def test_ecs_rules_read_only_that_argument(tmp_path) -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    _res(
                        "aws_ecs_task_definition",
                        "t",
                        {
                            "family": "t",
                            "container_definitions": "[]",
                            "tags": {"note": json.dumps({"privileged": True})},
                        },
                    ),
                ]
            }
        }
    }
    ids = {
        f["id"]
        for f in json.loads(_scan(tmp_path, plan, "--format", "json").stdout)[
            "findings"
        ]
    }
    assert "SEC-AWS-ECS-002" not in ids


# ---- PARTIAL SCAN everywhere ---------------------------------------------------


def test_mitre_output_is_marked_partial(tmp_path) -> None:
    res = _scan(tmp_path, DOCS, "--format", "mitre")
    assert "PARTIAL SCAN" in res.stdout


def test_oscal_does_not_pass_a_control_whose_rules_did_not_run(tmp_path) -> None:
    out = tmp_path / "o.json"
    _scan(tmp_path, DOCS, "--compliance", "--oscal", str(out), "--format", "json")
    doc = json.loads(out.read_text())["assessment-results"]
    statuses = {f["status"] for f in doc["results"][0]["findings"]}
    assert "not-evaluated" in statuses
    assert "PARTIAL SCAN" in doc["metadata"]["remarks"]


def test_a_control_with_a_skipped_rule_is_not_pass() -> None:
    from _output import _compliance_gap_report

    entries = [
        {"id": "AWS-A-001", "cis": ["1.1"]},
        {"id": "AWS-B-001", "cis": ["1.1"]},
        {"id": "AWS-C-001", "cis": ["2.1"]},
        {"id": "AWS-D-001", "cis": ["3.1"]},
    ]
    report = _compliance_gap_report(
        [{"id": "AWS-D-001"}],
        entries,
        "cis",
        not_evaluated=["AWS-B-001", "AWS-D-001"],
    )
    status = {c["control"]: c["status"] for cs in report.values() for c in cs}
    assert status == {"1.1": "NOT-EVALUATED", "2.1": "PASS", "3.1": "FAIL"}


def test_compliance_text_and_html_count_three_states() -> None:
    from _output import _render_compliance_html, _render_compliance_text

    by_fw = {
        "CIS": [
            {
                "control": "1",
                "rules": ["A"],
                "failed_rules": [],
                "status": "NOT-EVALUATED",
            },
            {"control": "2", "rules": ["B"], "failed_rules": [], "status": "PASS"},
        ]
    }
    assert "1/2 PASS, 0 FAIL, 1 NOT-EVALUATED" in _render_compliance_text(by_fw)
    assert ">NOT-EVALUATED<" in _render_compliance_html(by_fw)


# ---- Plans that can't be trusted -----------------------------------------------


def test_an_unknown_major_format_fails_closed(tmp_path) -> None:
    plan = {
        "format_version": "2.0",
        "planned_values": {"root_module": {"resources": []}},
    }
    res = _scan(tmp_path, plan, "--fail-on", "HIGH")
    assert res.returncode == 2
    assert "format_version" in res.stderr


def test_a_lost_section_fails_closed(tmp_path) -> None:
    plan = {
        "format_version": "1.2",
        "planned_values": {"root": {"resources": []}},
        "resource_changes": [_change("aws_iam_policy", "p", {})],
    }
    res = _scan(tmp_path, plan, "--fail-on", "HIGH")
    assert res.returncode == 2
    assert "aws_iam_policy.p" in res.stderr


@pytest.mark.parametrize(
    "change",
    [
        _change("aws_x", "gone", {}, ("delete",)),
        _change("aws_x", "same", {}, ("no-op",)),
        _change("aws_x", "d", {}, ("read",), "data"),
        _change("aws_x", "old", {}, ("create",), deposed="abc"),
    ],
)
def test_changes_that_are_not_in_planned_values_by_nature(tmp_path, change) -> None:
    plan = {
        "format_version": "1.2",
        "planned_values": {"root_module": {"resources": []}},
        "resource_changes": [change],
    }
    assert _scan(tmp_path, plan).returncode == 0


def test_a_state_of_an_unknown_format_fails_closed(tmp_path) -> None:
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"format_version": "9.0", "values": {}}))
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
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 2


# ---- The renderer's guards -----------------------------------------------------


def test_template_syntax_is_escaped() -> None:
    text, _ = render_resources_hcl([_res("aws_x", "y", {
        "a": "${aws:username}", "b": "%{ if x }", "c": '{"k": "${v}"}',
    })])
    assert '"$${aws:username}"' in text and '"%%{ if x }"' in text
    assert '"k": "\\u0024{v}"' in text


def test_a_value_holding_the_heredoc_marker_cannot_end_it() -> None:
    value = 'line one\nTF_ANALYZE_EOT\nresource "aws_evil" "x" {}\n'
    text, _ = render_resources_hcl([_res("aws_x", "y", {"user_data": value})])
    tree, error = parse_tf(text)
    assert error is None
    assert 'resource "aws_evil"' in text and "TF_ANALYZE_EOT_" in text
    assert [list(r) for r in tree["resource"]] == [["aws_x"]]


def test_carriage_returns_are_stripped_from_heredocs() -> None:
    text, _ = render_resources_hcl([_res("aws_x", "y", {"user_data": "a\r\nb\r\n"})])
    assert "\r" not in text


def test_a_refused_rendering_stops_the_scan(tmp_path, monkeypatch) -> None:
    path = tmp_path / "plan.json"
    path.write_text(
        json.dumps(
            {
                "planned_values": {
                    "root_module": {
                        "resources": [
                            _res(
                                "aws_security_group",
                                "s",
                                {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
                            ),
                        ]
                    }
                }
            }
        )
    )
    monkeypatch.setattr(_plan_state, "parse_tf", lambda text: (None, "boom"))
    entries = [
        {
            "id": "X-1",
            "patterns": [
                {"kind": "firewall_open_port", "resource": "aws_security_group"},
            ],
        }
    ]
    with pytest.raises(PlanInputError, match="boom"):
        detect_in_plan(path, entries, lambda text, rendered: [])


def test_only_resources_a_rule_can_act_on_are_rendered(tmp_path) -> None:
    seen: list[str] = []

    def scan(text, rendered):
        seen.append(text)
        return []

    policy = (
        '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:x"}]}'
    )
    path = tmp_path / "plan.json"
    path.write_text(
        json.dumps(
            {
                "planned_values": {
                    "root_module": {
                        "resources": [
                            _res("aws_instance", "i", {"ami": "a"}),
                            _res("aws_iam_policy", "narrow", {"policy": policy}),
                            _res(
                                "aws_iam_policy",
                                "wild",
                                {"policy": policy.replace("s3:GetObject", "*")},
                            ),
                            _res(
                                "aws_security_group",
                                "closed",
                                {"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]},
                            ),
                            _res(
                                "aws_security_group",
                                "open",
                                {"ingress": [{"cidr_blocks": ["1.2.3.4/0"]}]},
                            ),
                        ]
                    }
                }
            }
        )
    )
    entries = [
        {
            "id": "X-1",
            "patterns": [
                {"kind": "firewall_open_port", "resource": "aws_security_group"}
            ],
        },
        {
            "id": "X-2",
            "patterns": [
                {"kind": "iam_json_policy_analysis", "check": "wildcard_action"}
            ],
        },
    ]
    detect_in_plan(path, entries, scan)
    assert '"wild"' in seen[0] and '"open"' in seen[0] and '"closed"' in seen[0]
    assert '"narrow"' not in seen[0] and "aws_instance" not in seen[0]


@pytest.mark.parametrize(
    "policy",
    [
        '{"Statement":[{"Effect":"Allow","NotAction":"s3:GetObject","Resource":"x"}]}',
        '{"Statement":[{"Effect":"Allow","Action":"\\u002a","Resource":"x"}]}',
    ],
)
def test_the_prefilter_keeps_what_a_policy_check_could_flag(tmp_path, policy) -> None:
    seen: list[str] = []
    path = tmp_path / "plan.json"
    path.write_text(
        json.dumps(
            {
                "planned_values": {
                    "root_module": {
                        "resources": [
                            _res("aws_iam_policy", "p", {"policy": policy}),
                        ]
                    }
                }
            }
        )
    )
    entries = [
        {
            "id": "X-2",
            "patterns": [
                {"kind": "iam_json_policy_analysis", "check": "wildcard_action"}
            ],
        }
    ]
    detect_in_plan(path, entries, lambda text, rendered: seen.append(text) or [])
    assert seen and '"p"' in seen[0]


# ---- Near-linear on large plans -------------------------------------------------


def _timed(fn) -> float:
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start


def test_rendering_same_named_instances_is_near_linear() -> None:
    def run(n):
        return lambda: render_resources_hcl(
            [_res("aws_x", "r", {"a": 1}, address=f"aws_x.r[{i}]") for i in range(n)]
        )

    small, large = _timed(run(5_000)), _timed(run(40_000))
    assert large < max(small * 20, 1.0), (small, large)


def test_companions_are_found_near_linearly() -> None:
    entry = {
        "id": "X-1",
        "patterns": [
            {
                "kind": "resource_missing_companion",
                "resource": "aws_a",
                "companion": "aws_b",
                "via": "bucket",
            }
        ],
    }

    def run(n):
        resources = [_res("aws_a", f"a{i}", {"bucket": f"b{i}"}) for i in range(n)]
        resources += [_res("aws_b", f"b{i}", {"bucket": f"b{i}"}) for i in range(n)]
        return lambda: evaluate_against_resources(
            resources,
            [entry],
            finding_mode="plan",
            file_marker="<plan>",
            kinds=PLAN_SUPPORTED_KINDS | PLAN_ONLY_KINDS,
        )

    small, large = _timed(run(2_000)), _timed(run(16_000))
    assert large < max(small * 20, 1.0), (small, large)


def test_a_30000_resource_plan_is_well_inside_the_run_task_timeout(tmp_path) -> None:
    resources = []
    for i in range(30_000):
        kind = (
            "aws_s3_bucket",
            "aws_security_group",
            "aws_iam_policy",
            "aws_instance",
        )[i % 4]
        values = {"tags": {"Name": f"n{i}"}, "name": f"n{i}"}
        if kind == "aws_iam_policy":
            values["policy"] = (
                '{"Statement":[{"Effect":"Allow","Action":"s3:Get","Resource":"arn"}]}'
            )
        if kind == "aws_security_group":
            values["ingress"] = [
                {"from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]}
            ]
        resources.append(_res(kind, "r", values, address=f"{kind}.r[{i}]"))
    plan = {
        "format_version": "1.2",
        "planned_values": {"root_module": {"resources": resources}},
    }
    start = time.perf_counter()
    res = _scan(tmp_path, plan, "--format", "json")
    assert res.returncode == 0, res.stderr[-300:]
    assert time.perf_counter() - start < 60


# ---- Run Task -------------------------------------------------------------------


def _server():
    pytest.importorskip("fastapi")
    pytest.importorskip("requests")
    path = REPO / "integrations" / "run-task" / "server.py"
    spec = importlib.util.spec_from_file_location("_rt_unknowns", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _attrs(server, data, *args):
    return server._format_status_body(data, "HIGH", *args)["data"]["attributes"]


def test_run_task_names_unknown_values(tmp_path) -> None:
    server = _server()
    report = json.loads(_scan(tmp_path, INLINE, "--format", "json").stdout)
    message = _attrs(server, report)["message"]
    assert "aws_s3_bucket_policy.inline (policy)" in message
    assert "Unknown until apply" in message


def test_run_task_a_rule_timeout_is_not_passed() -> None:
    server = _server()
    data = {
        "findings": [],
        "summary": {"rule_timeouts": [{"rule": "X", "file": "<plan>"}]},
    }
    attrs = _attrs(server, data)
    assert attrs["status"] == "failed"
    assert "ran out of time" in attrs["message"]


def test_run_task_a_failed_gate_is_not_passed() -> None:
    attrs = _attrs(_server(), {"findings": [], "summary": {}}, 1)
    assert attrs["status"] == "failed"
    assert "gate failed" in attrs["message"]


def test_run_task_exit_zero_with_nothing_found_passes() -> None:
    data = {
        "findings": [],
        "summary": {
            "coverage": {
                "rules_not_evaluated": 1,
                "rules_total": 2,
                "not_evaluated_critical_high": 0,
            }
        },
    }
    attrs = _attrs(_server(), data, 0)
    assert attrs["status"] == "passed"
    assert "1 of 2 rules" in attrs["message"]


def test_run_task_counts_controls_not_evaluated() -> None:
    server = _server()
    data = {
        "compliance": {
            "CIS": [{"status": "FAIL"}, {"status": "NOT-EVALUATED"}, {"status": "PASS"}]
        }
    }
    assert (
        server._compliance_summary(data, "cis")
        == "compliance: cis 1/3 controls failing, 1 not evaluated."
    )
