"""A value's shape must not hide it from a rule.

Each of these got a misconfiguration past the scanner with a clean exit:
parentheses or a trivial ``${...}`` around a literal, parentheses around
``jsonencode``, a construct the parser rejects anywhere in the file (the
regex fallback read ``policy = jsonencode(`` only), and a shared module's
ninth distinct caller (contexts past eight were dropped without a word).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import _hcl
import detect

REPO = Path(__file__).resolve().parents[1]
CATALOG = {e["id"]: e for e in detect.load_catalog(REPO / "catalog")}


@pytest.fixture(autouse=True)
def _real_parser(monkeypatch):
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)


@pytest.fixture(params=["tree", "fallback"])
def path_mode(request, monkeypatch):
    if request.param == "fallback":
        monkeypatch.setenv("TF_ANALYZE_TEST_FORCE_FALLBACK", "1")
    return request.param


def _fires(
    text: str, rule_id: str, tmp_path: Path, var_defaults: dict | None = None
) -> bool:
    fp = tmp_path / "main.tf"
    fp.write_text(text)
    return bool(
        detect.detect_in_file(fp, text, [CATALOG[rule_id]], var_defaults=var_defaults)
    )


def _cli(target: Path, *args: str) -> tuple[set[str], int, str]:
    env = {k: v for k, v in os.environ.items() if k != "TF_ANALYZE_TEST_FORCE_FALLBACK"}
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--format",
            "json",
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    return (
        {f["id"] for f in json.loads(out.stdout)["findings"]},
        out.returncode,
        out.stderr,
    )


# ---- (a) a literal behind parentheses or `${...}` ------------------------------

ACL_RULE = "SEC-AWS-S3-PUBLIC-001"
ACL = 'resource "aws_s3_bucket_acl" "x" {\n  bucket = "b"\n  acl = %s\n}\n'
SG_RULE = "SEC-AWS-SG-001"
SG = """resource "aws_security_group" "x" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = %s
  }
}
"""


@pytest.mark.parametrize(
    "value",
    [
        '"public-read"',
        '("public-read")',
        '(("public-read"))',
        '( ( "public-read" ) )',
        '"${"public-read"}"',
        '"${("public-read")}"',
        '("${"public-read"}")',
        '"${"${"public-read"}"}"',
        '(\n    # the name is "x)"\n    "public-read" // why\n  )',
    ],
)
def test_wrapped_literal_reads_like_the_literal(value, path_mode, tmp_path) -> None:
    assert _fires(ACL % value, ACL_RULE, tmp_path)


@pytest.mark.parametrize("value", ['("private")', '"${"private"}"', '(("private"))'])
def test_wrapped_safe_literal_stays_safe(value, path_mode, tmp_path) -> None:
    assert not _fires(ACL % value, ACL_RULE, tmp_path)


@pytest.mark.parametrize(
    "value",
    [
        '["0.0.0.0/0"]',
        '(["0.0.0.0/0"])',
        '((["0.0.0.0/0"]))',
        '["${"0.0.0.0/0"}"]',
        '[("0.0.0.0/0")]',
        '("0.0.0.0/0")',
        '(["10.0.0.0/8", "0.0.0.0/0"])',
    ],
)
def test_wrapped_world_open_cidr_list(value, path_mode, tmp_path) -> None:
    assert _fires(SG % value, SG_RULE, tmp_path)


def test_wrapped_port_and_protocol(path_mode, tmp_path) -> None:
    text = (SG % '["0.0.0.0/0"]').replace("= 22", "= (22)").replace('"tcp"', '("tcp")')
    assert _fires(text, SG_RULE, tmp_path)


def test_wrapped_private_cidr_list_stays_quiet(path_mode, tmp_path) -> None:
    assert not _fires(SG % '(["10.0.0.0/8"])', SG_RULE, tmp_path)


def test_wrapped_default_of_a_variable(path_mode, tmp_path) -> None:
    text = 'variable "a" {\n  default = ("public-read")\n}\n' + ACL % "var.a"
    fp = tmp_path / "main.tf"
    fp.write_text(text)
    vd = detect._extract_var_defaults_by_dir({str(fp): text})[str(tmp_path)]
    assert _fires(text, ACL_RULE, tmp_path, vd)


def test_wrapped_caller_input_reaches_the_child(tmp_path) -> None:
    (tmp_path / "child").mkdir()
    (tmp_path / "child" / "main.tf").write_text(
        'variable "acl" {\n  default = "private"\n}\n' + ACL % "var.acl"
    )
    (tmp_path / "main.tf").write_text(
        'module "m" {\n  source = "./child"\n  acl    = ("public-read")\n}\n'
    )
    assert ACL_RULE in _cli(tmp_path)[0]


def test_wrapped_helm_value(path_mode, tmp_path) -> None:
    text = """resource "helm_release" "x" {
  set {
    name  = ("service.type")
    value = ("LoadBalancer")
  }
}
"""
    assert _fires(text, "SEC-K8S-HELM-001", tmp_path)


@pytest.mark.parametrize(
    ("val", "want"),
    [
        ('("x")', "x"),
        ('"${"x"}"', "x"),
        ('${"x"}', "x"),
        ('${(("x"))}', "x"),
        ("(true)", "true"),
        ("${(True)}", "true"),
        ("${(False)}", "false"),
        ("${(None)}", "null"),
        ("${(5)}", "5"),
        ("(-1)", "-1"),
        ("${(['0.0.0.0/0'])}", '["0.0.0.0/0"]'),
        ("${(['a', '${var.x}'])}", '["a", var.x]'),
        ('(["a", var.x])', '["a", var.x]'),
        ("${({'a': 1})}", "{a = 1}"),
        ('("a${var.x}")', "a${var.x}"),
        ('("$${x}")', "$${x}"),
        ("(['https://a#b'])", '["https://a#b"]'),
    ],
)
def test_resolve_literal_text(val, want) -> None:
    assert _hcl.resolve_value_text(val, {}) == want


@pytest.mark.parametrize(
    "val",
    [
        "x",
        "(x)",
        "(aws_s3_bucket.b.arn)",
        '("a") == ("b")',
        '("a" == "b")',
        '("a") + ("b")',
        '(var.x ? "a" : "b")',
        '("a")[0]',
        '(["a"])[0]',
        '(lookup(var.m, "k"))',
        "([for x in var.y : x])",
        '${"a"}${"b"}',
        '${"a"}-b',
        "${var.a}-${var.b}",
        "$${x}",
        "(unbalanced",
    ],
)
def test_resolve_keeps_a_non_literal_unchanged(val) -> None:
    assert _hcl.resolve_value_text(val, {}) == val


def test_resolve_follows_a_wrapped_reference() -> None:
    assert _hcl.resolve_value_text('("${(var.x)}")', {"x": "v"}) == "v"


def test_wrapped_reference_cycle_stays_unresolved() -> None:
    table = {"__local__a": '("${local.b}")', "__local__b": '("${local.a}")'}
    assert _hcl.resolve_value_text("local.a", table) == "local.a"


def test_parenthesised_count_zero_is_not_created(path_mode, tmp_path) -> None:
    text = (ACL % '"public-read"').replace(
        'bucket = "b"', 'bucket = "b"\n  count = (0)'
    )
    assert not _fires(text, ACL_RULE, tmp_path)


# ---- (b) a parenthesised `jsonencode` policy ------------------------------------

ADMIN = 'Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]'
ADMIN_JSON = '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
ADMIN_ESCAPED = ADMIN_JSON.replace('"', '\\"')
ADMIN_RULE = "SEC-AWS-IAM-JSON-003"
POLICY = 'resource "aws_iam_policy" "p" {\n  policy = %s\n}\n'


@pytest.mark.parametrize(
    "value",
    [
        f"jsonencode({{ {ADMIN} }})",
        f"(jsonencode({{ {ADMIN} }}))",
        f"((jsonencode({{ {ADMIN} }})))",
        f"( jsonencode({{ {ADMIN} }}) )",
        # What `terraform fmt` leaves of a parenthesised call.
        f"(jsonencode({{\n    {ADMIN}\n  }}))",
        f"(\n    jsonencode({{\n      {ADMIN}\n    }})\n  )",
        f'"${{jsonencode({{ {ADMIN} }})}}"',
        f'"${{(jsonencode({{ {ADMIN} }}))}}"',
        f"jsonencode(({{ {ADMIN} }}))",
        f"(jsonencode({{\n    # note\n    {ADMIN} // tail\n  }})) # end",
        f"(<<POL\n{ADMIN_JSON}\nPOL\n  )",
        f'("{ADMIN_ESCAPED}")',
        f'"${{"{ADMIN_ESCAPED}"}}"',
        'jsonencode({ Statement = ([{ Effect = "Allow", Action = "*", Resource = "*" }]) })',
        'jsonencode({ Statement = [{ Effect = ("Allow"), Action = ("*"), Resource = ("*") }] })',
        'jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = (["*"]) }] })',
        'jsonencode({ Statement = [({ Effect = "Allow", Action = "*", Resource = "*" })] })',
    ],
)
def test_every_wrapped_policy_is_read(value, path_mode, tmp_path) -> None:
    assert _fires(POLICY % value, ADMIN_RULE, tmp_path)


def test_issue_input_fails_the_gate(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(POLICY % f"(jsonencode({{ {ADMIN} }}))")
    ids, code, _ = _cli(tmp_path, "--fail-on", "CRITICAL")
    assert ADMIN_RULE in ids
    assert code == 1


@pytest.mark.parametrize(
    "value",
    [
        '(jsonencode({ Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::b/*" }] }))',
        '(jsonencode({ Statement = [{ Effect = ("Deny"), Action = "*", Resource = "*" }] }))',
        "(jsonencode(var.policy))",
        '(jsonencode({ Statement = [{ Effect = "Allow", Action = var.a, Resource = "*" }] }))',
    ],
)
def test_wrapped_policy_without_the_problem_stays_quiet(
    value, path_mode, tmp_path
) -> None:
    assert not _fires(POLICY % value, ADMIN_RULE, tmp_path)


def test_wrapped_public_principal(path_mode, tmp_path) -> None:
    text = """resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = (jsonencode({
    Statement = [{ Effect = "Allow", Principal = ({ AWS = "*" }), Action = "s3:GetObject", Resource = "x" }]
  }))
}
"""
    assert _fires(text, "SEC-AWS-IAM-JSON-004", tmp_path)


def test_wrapped_policy_document_lists(path_mode, tmp_path) -> None:
    text = """data "aws_iam_policy_document" "d" {
  statement {
    effect    = ("Allow")
    actions   = (["*"])
    resources = (["*"])
  }
}
"""
    assert _fires(text, "SEC-AWS-IAM-POLICY-005", tmp_path)


# ---- (c) the regex fallback reads every policy form -----------------------------

TRIGGERS = {
    "leading_operator": "locals {\n  flag = (var.a\n    || var.b)\n}\n",
    "interpolation_newline": 'locals {\n  x = "${\n    var.a}"\n}\n',
    "comment_between_labels": 'resource "aws_vpc" /* main */ "v" {\n  cidr_block = "10.0.0.0/16"\n}\n',
    "non_ascii_identifier": 'locals {\n  étiquette = "x"\n}\n',
}
HEREDOC = f"<<POL\n{ADMIN_JSON}\nPOL"
INDENTED_HEREDOC = f"<<-POL\n    {ADMIN_JSON}\n    POL"
ROLE = """resource "aws_iam_role" "r" {
  assume_role_policy = "{}"
  inline_policy {
    name   = "i"
    policy = %s
  }
}
"""
BUCKET_POLICY_HEREDOC = """resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = <<POL
{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"x"}]}
POL
}
"""
TRUST_HEREDOC = """resource "aws_iam_role" "r" {
  assume_role_policy = <<POL
{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}
POL
}
"""
DOCUMENTS = """data "aws_iam_policy_document" "d" {
  dynamic "statement" {
    for_each = var.s
    content {
      actions   = ["*:*"]
      resources = ["*"]
    }
  }
}
"""
SHAPES = {
    "heredoc": (POLICY % HEREDOC, ADMIN_RULE),
    "indented_heredoc": (POLICY % INDENTED_HEREDOC, ADMIN_RULE),
    "quoted_json": (POLICY % f'"{ADMIN_ESCAPED}"', ADMIN_RULE),
    "jsonencode": (POLICY % f"jsonencode({{ {ADMIN} }})", ADMIN_RULE),
    "parenthesised": (POLICY % f"(jsonencode({{ {ADMIN} }}))", ADMIN_RULE),
    "multiline_interpolation": (
        POLICY % f'"${{\n    jsonencode({{ {ADMIN} }})\n  }}"',
        ADMIN_RULE,
    ),
    "inline_policy_heredoc": (ROLE % HEREDOC, ADMIN_RULE),
    "inline_policy_quoted": (ROLE % f'"{ADMIN_ESCAPED}"', ADMIN_RULE),
    "bucket_policy_heredoc": (BUCKET_POLICY_HEREDOC, "SEC-AWS-IAM-JSON-004"),
    "trust_policy_heredoc": (TRUST_HEREDOC, "SEC-AWS-IAM-002"),
    "dynamic_statement": (DOCUMENTS, "SEC-AWS-IAM-POLICY-005"),
}


@pytest.mark.parametrize("trigger", TRIGGERS)
@pytest.mark.parametrize("shape", SHAPES)
def test_rejected_file_still_reads_the_policy(trigger, shape, tmp_path) -> None:
    text, rule = SHAPES[shape]
    text = TRIGGERS[trigger] + text
    assert _hcl.parse_tf(text)[0] is None
    assert _fires(text, rule, tmp_path)


@pytest.mark.parametrize("shape", SHAPES)
def test_forced_fallback_reads_the_policy(shape, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("TF_ANALYZE_TEST_FORCE_FALLBACK", "1")
    text, rule = SHAPES[shape]
    assert _fires(text, rule, tmp_path)


def test_a_construct_inside_the_policys_own_block(tmp_path) -> None:
    text = (POLICY % HEREDOC).replace("policy =", 'name = "${\n    var.a}"\n  policy =')
    assert _hcl.parse_tf(text)[0] is None
    assert _fires(text, ADMIN_RULE, tmp_path)


def test_a_comment_between_the_policys_own_labels(tmp_path) -> None:
    text = (POLICY % HEREDOC).replace(
        '"aws_iam_policy" "p"', '"aws_iam_policy" /* x */ "p"'
    )
    assert _hcl.parse_tf(text)[0] is None
    assert _fires(text, ADMIN_RULE, tmp_path)


@pytest.mark.parametrize(
    "policy",
    [
        '{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}',
        '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"x"}]}',
    ],
)
def test_rejected_file_keeps_a_safe_policy_quiet(policy, tmp_path) -> None:
    text = TRIGGERS["leading_operator"] + POLICY % f"<<POL\n{policy}\nPOL"
    assert not _fires(text, ADMIN_RULE, tmp_path)


def test_a_policy_in_a_comment_is_not_read(tmp_path) -> None:
    text = TRIGGERS["leading_operator"] + (
        'resource "aws_iam_policy" "p" {\n'
        f'  # policy = "{ADMIN_ESCAPED}"\n'
        '  policy = "{}"\n'
        "}\n"
    )
    assert not _fires(text, ADMIN_RULE, tmp_path)


def test_document_line_numbers_survive_the_fragment_parse(tmp_path) -> None:
    text = TRIGGERS["leading_operator"] + DOCUMENTS
    fp = tmp_path / "main.tf"
    fp.write_text(text)
    found = detect.detect_in_file(fp, text, [CATALOG["SEC-AWS-IAM-POLICY-005"]])
    assert [f["line"] for f in found] == [text[: text.index("content")].count("\n") + 1]


def test_issue_input_fails_the_gate_with_a_warning(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(TRIGGERS["leading_operator"] + POLICY % HEREDOC)
    ids, code, err = _cli(tmp_path, "--fail-on", "CRITICAL")
    assert ADMIN_RULE in ids
    assert code == 1
    assert "scanned in fallback mode" in err


def test_arg_source_stops_at_the_value() -> None:
    body = (
        '\n  # policy = "no"\n'
        "  policy = <<A\nx = 1\nA\n"
        '  other = ("a",\n    "b") # note\n'
        '  third = "${\n  var.x}" // c\n'
        "  fourth == 1\n"
    )
    assert _hcl.arg_source(body, "policy") == "<<A\nx = 1\nA"
    assert _hcl.arg_source(body, "other") == '("a",\n    "b")'
    assert _hcl.arg_source(body, "third") == '"${\n  var.x}"'
    assert _hcl.arg_source(body, "fourth") is None
    assert _hcl.arg_source(body, "absent") is None


# ---- (d) every caller of a shared module ----------------------------------------


def _shared_module(root: Path, calls: list[str]) -> None:
    (root / "child").mkdir()
    (root / "child" / "main.tf").write_text(
        'variable "name" {}\n'
        'variable "acl" {\n  default = "private"\n}\n'
        'resource "aws_s3_bucket_acl" "x" {\n  bucket = var.name\n  acl    = var.acl\n}\n'
    )
    (root / "main.tf").write_text(
        "".join(
            f'module "b{i}" {{\n  source = "./child"\n  {inputs}\n}}\n'
            for i, inputs in enumerate(calls)
        )
    )


def _names(n: int) -> list[str]:
    return [f'name = "bucket-{i}"' for i in range(n)]


@pytest.mark.parametrize("position", [0, 8, 69])
def test_a_lone_public_caller_is_scanned_wherever_it_is(position, tmp_path) -> None:
    calls = _names(70)
    calls[position] += '\n  acl = "public-read"'
    _shared_module(tmp_path, calls)
    ids, _, err = _cli(tmp_path)
    assert ACL_RULE in ids
    assert "WARN: module " in err
    assert str((tmp_path / "child").resolve()) in err
    assert "6 of 70 distinct sets of caller inputs not scanned" in err


def test_ninth_caller_is_scanned_without_a_warning(tmp_path) -> None:
    calls = _names(9)
    calls[8] += '\n  acl = "public-read"'
    _shared_module(tmp_path, calls)
    ids, _, err = _cli(tmp_path)
    assert ACL_RULE in ids
    assert "not scanned" not in err


def test_pick_keeps_all_contexts_within_the_limit() -> None:
    contexts = [{"a": str(i)} for i in range(4)]
    assert detect._pick_var_contexts(contexts, 4) == contexts


def test_pick_covers_every_value_of_every_input() -> None:
    contexts = [{"name": f"n{i}", "acl": "private", "tier": "a"} for i in range(30)]
    contexts[7]["acl"] = "public-read"
    contexts[20]["tier"] = "b"
    contexts[29]["acl"] = "public-read-write"
    picked = detect._pick_var_contexts(contexts, 5)
    assert len(picked) == 5
    assert {c["acl"] for c in picked} == {"private", "public-read", "public-read-write"}
    assert {c["tier"] for c in picked} == {"a", "b"}


def test_pick_covers_an_input_only_some_callers_set() -> None:
    contexts = [{"name": f"n{i}"} for i in range(30)]
    contexts[15]["acl"] = "public-read"
    assert contexts[15] in detect._pick_var_contexts(contexts, 2)


def test_pick_fills_the_limit_with_other_combinations() -> None:
    contexts = [{"a": str(i % 2), "b": str(i % 3)} for i in range(6)]
    picked = detect._pick_var_contexts(contexts, 5)
    assert len(picked) == 5
    assert len({frozenset(c.items()) for c in picked}) == 5


def test_pick_prefers_settings_to_identifiers_at_a_tight_limit() -> None:
    contexts = [{"name": f"n{i}", "acl": f"a{i % 3}"} for i in range(30)]
    assert {c["acl"] for c in detect._pick_var_contexts(contexts, 3)} == {
        "a0",
        "a1",
        "a2",
    }


def test_nested_modules_stay_within_the_limit(tmp_path, capsys) -> None:
    (tmp_path / "mid").mkdir()
    (tmp_path / "leaf").mkdir()
    root = tmp_path / "main.tf"
    mid = tmp_path / "mid" / "main.tf"
    leaf = tmp_path / "leaf" / "main.tf"
    root.write_text(
        "".join(
            f'module "a{i}" {{\n  source = "./mid"\n  n = "{i}"\n}}\n'
            for i in range(40)
        )
    )
    mid.write_text(
        'variable "n" {}\n'
        + "".join(
            f'module "b{i}" {{\n  source = "../leaf"\n  n = var.n\n  m = "{i}"\n}}\n'
            for i in range(40)
        )
    )
    leaf.write_text('variable "n" {}\nvariable "m" {}\n')
    files = {p: p.read_text() for p in (root, mid, leaf)}
    contexts = detect._extract_var_contexts_by_dir(files)
    assert len(contexts[str(tmp_path.resolve() / "leaf")]) == detect._MAX_VAR_CONTEXTS
    assert capsys.readouterr().err.count("not scanned") == 1
