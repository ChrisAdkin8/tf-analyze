"""What a plan-only scan renders must mean what the plan meant.

A policy with `\\"` in a string went into a heredoc, stopped decoding, and an
admin policy passed. A prefilter assumed every open firewall has a `/0`
source. Terraform leaves `dynamic` blocks out of `configuration`.
"""

from __future__ import annotations

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

import _plan_state as ps
import detect
from _hcl import normalise_attrs, parse_tf, resource_subtrees
from _iam_policy import decode_policy


def _res(rtype, name, values, mode="managed"):
    prefix = "data." if mode == "data" else ""
    return {
        "address": f"{prefix}{rtype}.{name}",
        "mode": mode,
        "type": rtype,
        "name": name,
        "values": values,
    }


def _scan(
    tmp_path: Path, plan: dict, *flags: str, kind: str = "plan"
) -> subprocess.CompletedProcess:
    target = tmp_path / "t"
    target.mkdir(exist_ok=True)
    path = tmp_path / "p.json"
    path.write_text(json.dumps(plan))
    return subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(target),
            f"--{kind}-json",
            str(path),
            "--no-threat-intel",
            "--format",
            "json",
            *flags,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _plan(*resources):
    return {
        "format_version": "1.2",
        "planned_values": {"root_module": {"resources": list(resources)}},
    }


def _ids(res) -> set:
    return {f["id"] for f in json.loads(res.stdout)["findings"]}


# ---- JSON documents ------------------------------------------------------------


def _through_the_parser(document: dict):
    text, _ = ps.render_resources_hcl(
        [_res("aws_x", "y", {"policy": json.dumps(document)})]
    )
    tree, error = parse_tf(text)
    assert error is None, text
    return decode_policy(
        normalise_attrs(resource_subtrees(tree)[("aws_x", "y")][0])["policy"]
    )


_json = st.recursive(
    st.none() | st.booleans() | st.integers(-(10**9), 10**9) | st.text(max_size=12),
    lambda inner: (
        st.lists(inner, max_size=3)
        | st.dictionaries(st.text(max_size=6), inner, max_size=3)
    ),
    max_leaves=10,
)


@settings(max_examples=300, deadline=None)
@given(st.dictionaries(st.text(max_size=6), _json, min_size=1, max_size=4))
def test_any_json_document_survives_the_render(document) -> None:
    assert _through_the_parser(document) == document


@pytest.mark.parametrize(
    "value",
    [
        'a"b',
        "a\nb",
        "a\\b",
        "tab\there",
        "${aws:username}",
        "%{ if }",
        "é   🔥",
        "}",
        "{",
        "EOT",
    ],
)
def test_awkward_strings_in_a_policy(value) -> None:
    document = {
        "Statement": [{"Sid": value, "Action": "*", "Resource": "*", "Effect": "Allow"}]
    }
    assert _through_the_parser(document) == document


def test_an_admin_policy_with_a_quote_in_a_condition_is_found(tmp_path) -> None:
    policy = json.dumps(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringLike": {"aws:UserAgent": 'a"b'}},
                }
            ]
        }
    )
    res = _scan(
        tmp_path,
        _plan(_res("aws_iam_policy", "p", {"policy": policy})),
        "--fail-on",
        "HIGH",
    )
    assert res.returncode == 1
    assert "SEC-AWS-IAM-JSON-003" in _ids(res)


@pytest.mark.parametrize("sid", ['say "hi"', "line\nbreak"])
def test_a_trust_policy_keeps_its_finding(tmp_path, sid) -> None:
    trust = json.dumps(
        {
            "Statement": [
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole",
                }
            ]
        }
    )
    res = _scan(
        tmp_path, _plan(_res("aws_iam_role", "r", {"assume_role_policy": trust}))
    )
    assert "SEC-AWS-IAM-002" in _ids(res)


def test_ecs_rules_still_read_the_document(tmp_path) -> None:
    defs = json.dumps([{"name": 'a"b', "privileged": True}])
    res = _scan(
        tmp_path,
        _plan(_res("aws_ecs_task_definition", "t", {"container_definitions": defs})),
    )
    assert "SEC-AWS-ECS-002" in _ids(res)


# ---- dynamic blocks ------------------------------------------------------------


def _change(address, rtype, unknown, mode="managed"):
    return {
        "address": address,
        "type": rtype,
        "mode": mode,
        "name": "n",
        "change": {"actions": ["create"], "after_unknown": unknown},
    }


ENTRIES = [
    {
        "id": "X-1",
        "patterns": [
            {
                "kind": "iam_json_policy_analysis",
                "check": "wildcard_action",
                "resources": ["aws_iam_role"],
            }
        ],
    },
    {
        "id": "X-2",
        "patterns": [{"kind": "iam_policy_analysis", "check": "wildcard_action"}],
    },
]


def test_a_dynamic_block_with_an_unknown_value_is_named() -> None:
    plan = {
        "resource_changes": [
            _change(
                "aws_iam_role.dyn",
                "aws_iam_role",
                {"inline_policy": [{"policy": True}]},
            ),
            _change(
                "data.aws_iam_policy_document.dyn",
                "aws_iam_policy_document",
                {"json": True, "statement": [{"resources": [True]}]},
                "data",
            ),
        ],
        "configuration": {
            "root_module": {
                "resources": [
                    {"address": "aws_iam_role.dyn", "expressions": {"name": {}}},
                    {"address": "data.aws_iam_policy_document.dyn", "expressions": {}},
                ]
            }
        },
    }
    assert ps.unknown_arguments(plan, ENTRIES) == [
        {"resource": "aws_iam_role.dyn", "arguments": ["inline_policy"]},
        {"resource": "data.aws_iam_policy_document.dyn", "arguments": ["statement"]},
    ]


def test_a_bare_computed_attribute_stays_out() -> None:
    plan = {
        "resource_changes": [
            _change("aws_iam_role.r", "aws_iam_role", {"inline_policy": True})
        ],
        "configuration": {
            "root_module": {
                "resources": [
                    {"address": "aws_iam_role.r", "expressions": {"name": {}}},
                ]
            }
        },
    }
    assert ps.unknown_arguments(plan, ENTRIES) == []


def test_with_no_configuration_section_it_is_named() -> None:
    plan = {
        "resource_changes": [
            _change("aws_iam_role.r", "aws_iam_role", {"inline_policy": True})
        ]
    }
    assert ps.unknown_arguments(plan, ENTRIES)


# ---- prefilters ----------------------------------------------------------------


def test_a_gcp_firewall_with_no_source_is_open_to_the_world(tmp_path) -> None:
    firewall = _res(
        "google_compute_firewall",
        "f",
        {
            "name": "f",
            "network": "default",
            "source_ranges": None,
            "allow": [{"protocol": "tcp", "ports": ["22"]}],
        },
    )
    assert "SEC-GCP-NETWORK-001" in _ids(_scan(tmp_path, _plan(firewall)))


@pytest.mark.parametrize(
    "cidr", ["0.0.0.0/0", "::/0", "1.2.3.4/0", "0.0.0.0/0.0.0.0"]
)
def test_every_spelling_of_the_whole_internet(tmp_path, cidr) -> None:
    group = _res(
        "aws_security_group",
        "s",
        {
            "ingress": [
                {
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": [cidr],
                }
            ]
        },
    )
    assert "SEC-AWS-SG-001" in _ids(_scan(tmp_path, _plan(group)))


def _values(value):
    if isinstance(value, dict):
        return {
            k: _values(v)
            for k, v in value.items()
            if k not in ("__start_line__", "__end_line__")
        }
    if isinstance(value, list):
        return [_values(v) for v in value]
    if isinstance(value, str) and value.startswith("${jsonencode("):
        document = decode_policy(value)
        return value if document is None else json.dumps(document)
    return value


def _fixture_resources(path: Path):
    tree = parse_tf(path.read_text(errors="replace"))[0] or {}
    out = {"resource": [], "data": []}
    for keyword, mode in (("resource", "managed"), ("data", "data")):
        for block in tree.get(keyword) or []:
            for rtype, named in block.items():
                for name, attrs in named.items():
                    out[keyword].append(_res(rtype, name, _values(attrs), mode))
    return out["resource"], out["data"]


def _rendered_scan(text, rendered):
    fp = Path("plan-values.tf")
    return detect.detect_in_file(fp, text, rendered) + detect.detect_corpus(
        Path("."), {fp: text}, rendered
    )


def test_prefilters_never_change_a_result(monkeypatch) -> None:
    """Across every fixture and example, read as plan values."""
    entries = detect.load_catalog(Path(detect._default_catalog_dir()))
    files = [*(REPO / "fixtures").rglob("*.tf"), *(REPO / "examples").rglob("*.tf")]
    checked = found = 0
    for path in files:
        resources, data = _fixture_resources(path)
        if not resources and not data:
            continue

        def run():
            return {
                (f["id"], f["resource"])
                for f in ps._scan_values_as_hcl(
                    resources,
                    data,
                    entries,
                    finding_mode="plan",
                    file_marker="<plan>",
                    scan_rendered=_rendered_scan,
                )
            }

        with_filter = run()
        with monkeypatch.context() as patched:
            patched.setattr(ps, "_prefilters", lambda rendered: {})
            without = run()
        assert with_filter == without, path
        checked += 1
        found += len(without)
    assert checked > 300 and found > 50


# ---- format versions -----------------------------------------------------------


@pytest.mark.parametrize("version", ["0.1", "0.2", "1.0", "1.2"])
@pytest.mark.parametrize("kind", ["plan", "state"])
def test_real_format_versions_are_accepted(tmp_path, version, kind) -> None:
    body = {"planned_values": {}} if kind == "plan" else {"values": {}}
    res = _scan(tmp_path, {"format_version": version, **body}, kind=kind)
    assert res.returncode == 0, res.stderr


@pytest.mark.parametrize("kind", ["plan", "state"])
def test_a_later_major_is_refused(tmp_path, kind) -> None:
    body = {"planned_values": {}} if kind == "plan" else {"values": {}}
    assert _scan(tmp_path, {"format_version": "2.0", **body}, kind=kind).returncode == 2
