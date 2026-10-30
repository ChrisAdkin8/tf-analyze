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
import _iam_policy
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
    ids, _, err = _cli(tmp_path, "--max-module-contexts", "16")
    assert ACL_RULE in ids
    assert "WARN: module " in err
    assert str((tmp_path / "child").resolve()) in err
    assert "54 of 70 distinct sets of caller inputs not scanned" in err


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


def test_nested_modules_stay_within_the_limit(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.setattr(detect, "UNSCANNED_CONTEXTS", [])
    monkeypatch.setattr(detect, "MAX_MODULE_CONTEXTS", 64)
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
    leaf.write_text('variable "n" {}\nvariable "m" {}\nlocals {\n  v = "${var.n}-${var.m}"\n}\n')
    files = {p: p.read_text() for p in (root, mid, leaf)}
    contexts = detect._extract_var_contexts_by_dir(files)
    assert len(contexts[str(tmp_path.resolve() / "leaf")]) == 64
    assert capsys.readouterr().err.count("not scanned") == 1


# ---- one odd field never loses a policy ------------------------------------------

ADMIN_STMT = '{ Effect = "Allow", Action = "*", Resource = "*" }'
COND_LIST = '{ Effect = "Allow", Action = var.w ? ["a"] : ["b"], Resource = "x" }'


@pytest.mark.parametrize(
    "statements",
    [
        f'{{ Sid = format("s-%s", var.n), Effect = "Allow", Action = "*", Resource = "*" }}, {COND_LIST}',
        f'{{ Sid = lookup(var.m, "k"), Effect = "Allow", Action = "*", Resource = "*" }}, {COND_LIST}',
        f'{{ Effect = var.e ? "Allow" : "Deny", Action = "a", Resource = "x" }}, {COND_LIST}, {ADMIN_STMT}',
        '{ Effect = ("Allow"), Action = "*", Resource = (["*"]) }',
        '{ Effect = ("Allow"), Action = ("*"), Resource = (["*"]) }',
        '{ Sid = format("}"), Effect = ("Allow"), Action = "*", Resource = (["*"]) }',
    ],
)
def test_mixed_expression_quotes_keep_the_policy(statements, path_mode, tmp_path) -> None:
    text = POLICY % f"jsonencode({{ Statement = [{statements}] }})"
    assert _fires(text, ADMIN_RULE, tmp_path)


def test_mixed_quotes_public_principal(path_mode, tmp_path) -> None:
    text = """resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = jsonencode({
    Statement = [{ Effect = ("Allow"), Principal = ({ AWS = ("*") }), Action = "a", Resource = "x" }]
  })
}
"""
    assert _fires(text, "SEC-AWS-IAM-JSON-004", tmp_path)


def test_mixed_quotes_deny_stays_a_deny(path_mode, tmp_path) -> None:
    text = POLICY % 'jsonencode({ Statement = [{ Effect = ("Deny"), Action = "*", Resource = (["*"]) }] })'
    assert not _fires(text, ADMIN_RULE, tmp_path)


@pytest.mark.parametrize(
    ("value", "warns"),
    [
        ("<<POL\n{ not json\nPOL", True),
        ('jsonencode({ Statement = ["${(]" })', False),  # the parser rejects it: no value
        ("data.aws_iam_policy_document.d.json", False),
        ('file("p.json")', False),
        ("jsonencode(var.p)", False),
        ("var.p", False),
    ],
)
def test_warn_when_a_written_out_policy_cannot_be_decoded(value, warns, tmp_path, capsys) -> None:
    fp = tmp_path / "main.tf"
    text = POLICY % value
    fp.write_text(text)
    detect.detect_in_file(fp, text, [CATALOG[ADMIN_RULE], CATALOG["SEC-AWS-IAM-JSON-001"]])
    err = capsys.readouterr().err
    assert err.count("policy could not be decoded") == (1 if warns else 0), err
    if warns:
        assert "aws_iam_policy.p" in err


def test_warn_in_a_rejected_file(tmp_path, capsys) -> None:
    text = TRIGGERS["leading_operator"] + POLICY % '"${jsonencode({ Statement = [ ) })}"'
    fp = tmp_path / "main.tf"
    fp.write_text(text)
    detect.detect_in_file(fp, text, [CATALOG[ADMIN_RULE]])
    assert "policy could not be decoded" in capsys.readouterr().err


# ---- `inline_policy = [{...}]` and parenthesised objects -------------------------

ROLE_LIST = """resource "aws_iam_role" "r" {
  assume_role_policy = "{}"
  inline_policy = %s
}
"""
LISTED = f'[{{ name = "i", policy = jsonencode({{ {ADMIN} }}) }}]'


@pytest.mark.parametrize("value", [LISTED, f"({LISTED})"])
def test_inline_policy_list(value, path_mode, tmp_path) -> None:
    assert _fires(ROLE_LIST % value, ADMIN_RULE, tmp_path)


def test_inline_policy_list_heredoc_in_a_rejected_file(tmp_path) -> None:
    text = TRIGGERS["leading_operator"] + ROLE_LIST % f'[{{ name = "i", policy = {HEREDOC}\n  }}]'
    assert _hcl.parse_tf(text)[0] is None
    assert _fires(text, ADMIN_RULE, tmp_path)


INSTANCE = 'resource "aws_instance" "x" {\n  ami = "a"\n  instance_type = "t3.micro"\n  metadata_options = (%s)\n}\n'


def test_parenthesised_object_at_resource_level(tmp_path) -> None:
    assert _fires(INSTANCE % '{ http_tokens = "optional" }', "SEC-AWS-SSRF-001", tmp_path)
    assert not _fires(INSTANCE % '{ http_tokens = "required" }', "SEC-AWS-SSRF-001", tmp_path)


@pytest.mark.parametrize("cidr", ['["0.0.0.0/0"]', '(["0.0.0.0/0"])'])
def test_parenthesised_list_of_objects_at_resource_level(cidr, tmp_path) -> None:
    text = (
        'resource "aws_security_group" "x" {\n'
        f'  ingress = ([{{ from_port = 22, to_port = 22, protocol = ("tcp"), cidr_blocks = {cidr} }}])\n'
        "}\n"
    )
    assert _fires(text, SG_RULE, tmp_path)


def test_normalise_leaves_expressions_alone() -> None:
    attrs = {"a": "${(var.x)}", "b": "${(['a'])[0]}", "c": "${(['a'])}", "d": ["${({'k': 1})}"]}
    assert _hcl.normalise_attrs(attrs) == {
        "a": "${(var.x)}",
        "b": "${(['a'])[0]}",
        "c": ["a"],
        "d": [{"k": 1}],
    }


# ---- false positives on wrapped values --------------------------------------------


def test_parenthesised_sensitive_counts(tmp_path) -> None:
    text = 'variable "db_password" {\n  sensitive = (true)\n}\n'
    assert not _fires(text, "SEC-SENSITIVE-PATTERN-001", tmp_path)


@pytest.mark.parametrize(
    ("line", "fires"),
    [
        ('ssl_mode     = ("ENCRYPTED_ONLY")', False),
        ('ssl_mode = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"', False),
        ('# ssl_mode = "ENCRYPTED_ONLY"', True),
        ('ssl_mode = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"', True),
    ],
)
def test_cloudsql_ssl_mode_is_read_not_grepped(line, fires, path_mode, tmp_path) -> None:
    text = (
        'resource "google_sql_database_instance" "x" {\n  settings {\n'
        f"    ip_configuration {{\n      {line}\n    }}\n  }}\n}}\n"
    )
    assert _fires(text, "STK-GCP-CLOUDSQL-004", tmp_path) is fires


# ---- callers past the limit fail the gate ------------------------------------------

CHILD = """variable "name" {}
variable "public" {
  default = false
}
variable "acl" {
  default = "private"
}
variable "cidr" {
  default = "10.0.0.0/8"
}
resource "aws_s3_bucket_acl" "x" {
  bucket = var.name
  acl    = var.public ? var.acl : "private"
}
resource "aws_security_group" "s" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.cidr]
  }
}
"""


def _write_callers(root: Path, child: str, calls: list[str]) -> None:
    (root / "child").mkdir()
    (root / "child" / "main.tf").write_text(child)
    (root / "main.tf").write_text(
        "".join(
            f'module "b{i}" {{\n  source = "./child"\n  {c}\n}}\n' for i, c in enumerate(calls)
        )
    )


def _report(target: Path, *args: str) -> tuple[dict, int, str]:
    env = {k: v for k, v in os.environ.items() if k != "TF_ANALYZE_TEST_FORCE_FALLBACK"}
    out = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"), "--target", str(target),
         "--format", "json", *args],
        capture_output=True, text=True, check=False, env=env,
    )
    return json.loads(out.stdout), out.returncode, out.stderr


def test_high_cardinality_input_past_the_limit_fails_the_gate(tmp_path) -> None:
    calls = [f'name = "n{i}"\n  cidr = "10.{i}.0.0/16"' for i in range(100)]
    calls[90] = 'name = "n90"\n  cidr = "0.0.0.0/0"'
    _write_callers(tmp_path, CHILD, calls)
    report, code, err = _report(tmp_path, "--fail-on", "CRITICAL", "--max-module-contexts", "64")
    assert code == 1
    child = str((tmp_path / "child").resolve())
    assert f"ERROR: module {child}: " in err
    assert "raise --max-module-contexts" in err
    entry = report["summary"]["unscanned_contexts"][0]
    assert entry["module"] == child
    assert (entry["scanned"], entry["distinct"]) == (64, 100)
    assert entry["unscanned_values"] and "cidr" in entry["inputs"]


def test_combination_past_the_limit_fails_the_gate(tmp_path) -> None:
    calls = [
        f'name = "n{i}"\n  public = {"true" if i % 2 else "false"}\n'
        f'  acl = "{"public-read" if i % 4 == 0 else "private"}"'
        for i in range(99)
    ]
    calls.append('name = "n99"\n  public = true\n  acl = "public-read"')
    _write_callers(tmp_path, CHILD, calls)
    report, code, _ = _report(tmp_path, "--fail-on", "CRITICAL", "--max-module-contexts", "64")
    assert code == 1
    assert report["summary"]["unscanned_contexts"]


def test_warm_cache_still_fails_the_gate(tmp_path) -> None:
    calls = [f'name = "n{i}"\n  cidr = "10.{i}.0.0/16"' for i in range(70)]
    _write_callers(tmp_path, CHILD, calls)
    cache = tmp_path / "scan.cache"
    for _ in range(2):
        _, code, _ = _report(
            tmp_path, "--cache", "--cache-file", str(cache), "--fail-on", "CRITICAL",
            "--max-module-contexts", "64",
        )
        assert code == 1


def test_input_only_a_tag_reads_does_not_count(tmp_path) -> None:
    child = (
        'variable "name" {}\nvariable "acl" {\n  default = "private"\n}\n'
        'resource "aws_s3_bucket_acl" "x" {\n  bucket = "b"\n  acl    = var.acl\n'
        "  tags = {\n    Name = var.name\n  }\n}\n"
    )
    calls = [f'name = "n{i}"' for i in range(100)]
    calls[70] += '\n  acl = "public-read"'
    _write_callers(tmp_path, child, calls)
    report, code, err = _report(tmp_path, "--fail-on", "CRITICAL", "--max-module-contexts", "64")
    assert ACL_RULE in {f["id"] for f in report["findings"]}
    assert code == 0
    assert "unscanned_contexts" not in report["summary"]
    assert "not scanned" not in err


def test_inputs_in_use() -> None:
    text = """# var.commented
variable "v" {
  default = "x"
}
resource "a" "b" {
  x    = var.kept
  foo  = var.both
  tags = merge(var.tags, { Name = var.both })
  labels = {
    a = var.label
  }
  nested {
    tags = var.nested
  }
}
locals {
  l = var.local_use
}
module "m" {
  n = var.passed
}
"""
    assert detect._inputs_in_use([text], skip_tags=True) == {
        "kept", "both", "nested", "local_use", "passed",
    }
    assert {"tags", "label"} < detect._inputs_in_use([text], skip_tags=False)


# ---- a large repo is not a failed gate ---------------------------------------------


def _no_unscanned(report: dict) -> bool:
    return not ({"unscanned_contexts", "unscanned_combinations"} & report["summary"].keys())


def test_unknown_expressions_do_not_separate_contexts(tmp_path) -> None:
    child = (
        'variable "subnet_id" {}\nvariable "acl" {\n  default = "private"\n}\n'
        'resource "aws_instance" "i" {\n  subnet_id = var.subnet_id\n}\n'
        'resource "aws_s3_bucket_acl" "x" {\n  bucket = "b"\n  acl    = var.acl\n}\n'
    )
    files = {
        tmp_path / "child" / "main.tf": child,
        tmp_path / "main.tf": "".join(
            f'module "m{i}" {{\n  source    = "./child"\n  subnet_id = aws_subnet.s{i}.id\n}}\n'
            for i in range(500)
        ),
    }
    contexts = detect._extract_var_contexts_by_dir(files)[str(tmp_path.resolve() / "child")]
    assert [c["subnet_id"] for c in contexts] == ["aws_subnet.s0.id"]


def test_unknown_expression_keeps_the_default_hidden(tmp_path) -> None:
    (tmp_path / "child").mkdir()
    (tmp_path / "child" / "main.tf").write_text(
        'variable "acl" {\n  default = "public-read"\n}\n' + ACL % "var.acl"
    )
    (tmp_path / "main.tf").write_text(
        'module "m" {\n  source = "./child"\n  acl    = aws_thing.x.acl\n}\n'
    )
    assert ACL_RULE not in _cli(tmp_path)[0]


def test_a_literal_beside_unknown_callers_stays_distinct(tmp_path) -> None:
    (tmp_path / "child").mkdir()
    (tmp_path / "child" / "main.tf").write_text('variable "acl" {}\n' + ACL % "var.acl")
    calls = [f"aws_thing.x{i}.acl" for i in range(30)] + ['"a.b"', '"public-read"']
    (tmp_path / "main.tf").write_text(
        "".join(
            f'module "m{i}" {{\n  source = "./child"\n  acl    = {c}\n}}\n'
            for i, c in enumerate(calls)
        )
    )
    assert ACL_RULE in _cli(tmp_path)[0]
    files = {p: p.read_text() for p in tmp_path.rglob("*.tf")}
    assert len(detect._extract_var_contexts_by_dir(files)[str(tmp_path.resolve() / "child")]) == 3


def test_unknown_input_stays_unknown_through_a_nested_module(tmp_path) -> None:
    (tmp_path / "mid").mkdir()
    (tmp_path / "leaf").mkdir()
    (tmp_path / "leaf" / "main.tf").write_text('variable "s" {}\nlocals {\n  x = var.s\n}\n')
    (tmp_path / "mid" / "main.tf").write_text(
        'variable "s" {}\nmodule "l" {\n  source = "../leaf"\n  s      = var.s\n}\n'
    )
    (tmp_path / "main.tf").write_text(
        "".join(f'module "m{i}" {{\n  source = "./mid"\n  s = aws_s.s{i}.id\n}}\n' for i in range(40))
    )
    files = {p: p.read_text() for p in tmp_path.rglob("*.tf")}
    assert len(detect._extract_var_contexts_by_dir(files)[str(tmp_path.resolve() / "leaf")]) == 1


@pytest.mark.parametrize(
    ("source", "resolved", "unknown"),
    [
        ("aws_subnet.a.id", "aws_subnet.a.id", True),
        ("module.x.id", "module.x.id", True),
        ('"${aws_subnet.a.id}"', "${aws_subnet.a.id}", True),
        ("(aws_subnet.a.id)", "(aws_subnet.a.id)", True),
        ("aws_x.y[0].id", "aws_x.y[0].id", True),
        ('"${each.key}"', "${each.key}", True),
        ("var.hidden", "aws_subnet.a.id", True),
        ("[aws_subnet.a.id, aws_subnet.b.id]", "[aws_subnet.a.id, aws_subnet.b.id]", True),
        ("[\n  aws_subnet.a.id,\n  aws_subnet.b.id,\n]", "[\n  aws_subnet.a.id,\n  aws_subnet.b.id,\n]", True),
        ("{ a = aws_x.y.id }", "{ a = aws_x.y.id }", True),
        ('{\n  a = aws_x.y.id\n  "b" = aws_x.z.id\n}', '{\n  a = aws_x.y.id\n  "b" = aws_x.z.id\n}', True),
        ('["0.0.0.0/0", aws_x.y.id]', '["0.0.0.0/0", aws_x.y.id]', False),
        ("[aws_x.y.id, 5]", "[aws_x.y.id, 5]", False),
        ("[aws_x.y.id, var.z]", "[aws_x.y.id, var.z]", False),
        ("[local.a]", "[local.a]", False),
        ('{ a = aws_x.y.id, b = "public" }', '{ a = aws_x.y.id, b = "public" }', False),
        ("{}", "{}", False),
        ("try(aws_x.y.id, null)", "try(aws_x.y.id, null)", False),
        ('"${each.key}${each.value}"', "${each.key}${each.value}", False),
        ('"public-read"', "public-read", False),
        ('"a.b"', "a.b", False),
        ('"${"a.b"}"', "a.b", False),
        ('"svc-${var.env}"', "svc-${var.env}", False),
        ("5", "5", False),
        ("1.5", "1.5", False),
        ("true", "true", False),
        ("[]", "[]", False),
        ("local.x", "aws_subnet.a.id", False),
        ("var.known", "public-read", False),
        ('var.p ? "public-read" : "private"', "public-read", False),
        ("var.p ? aws_a.b.c : aws_d.e.f", "var.p ? aws_a.b.c : aws_d.e.f", False),
        ('"${var.p ? "public-read" : "private"}"', "public-read", False),
    ],
)
def test_input_is_unknown(source, resolved, unknown) -> None:
    assert detect._input_is_unknown(source, resolved, {"hidden"}) is unknown


def test_many_bucket_callers_fit_the_budget(tmp_path) -> None:
    calls = _names(500)
    calls[400] += '\n  acl = "public-read"'
    _shared_module(tmp_path, calls)
    report, code, _ = _report(tmp_path, "--fail-on", "CRITICAL")
    assert ACL_RULE in {f["id"] for f in report["findings"]}
    assert code == 0
    assert _no_unscanned(report)


def test_nesting_multiplies_inside_the_budget(tmp_path) -> None:
    mid = 'variable "name" {}\n' + "".join(
        f'module "{r}" {{\n  source = "./leaf"\n  name = var.name\n  role = "{r}"\n}}\n'
        for r in "abc"
    )
    leaf = (
        'variable "name" {}\nvariable "role" {}\n'
        'resource "aws_iam_role" "r" {\n  name = "${var.name}-${var.role}"\n}\n'
    )
    (tmp_path / "m" / "leaf").mkdir(parents=True)
    (tmp_path / "m" / "main.tf").write_text(mid)
    (tmp_path / "m" / "leaf" / "main.tf").write_text(leaf)
    (tmp_path / "main.tf").write_text(
        "".join(f'module "s{i}" {{\n  source = "./m"\n  name = "svc-{i}"\n}}\n' for i in range(23))
    )
    files = {p: p.read_text() for p in tmp_path.rglob("*.tf")}
    assert len(detect._extract_var_contexts_by_dir(files)[str(tmp_path.resolve() / "m" / "leaf")]) == 69


@pytest.mark.parametrize(
    ("resources", "repo_left", "limit"),
    [
        (1, 1_000_000, 200_000),
        (5, 1_000_000, 40_000),
        (5, 500, 100),
        (100_000, 1_000_000, 8),
        (0, 1_000_000, 200_000),
        (10, 0, 8),
    ],
)
def test_context_limit(resources, repo_left, limit) -> None:
    assert detect._context_limit(resources, repo_left) == limit


def test_flag_replaces_the_budget(monkeypatch) -> None:
    monkeypatch.setattr(detect, "MAX_MODULE_CONTEXTS", 3)
    assert detect._context_limit(1, 0) == 3


def test_repo_budget_spans_modules(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(detect, "UNSCANNED_CONTEXTS", [])
    monkeypatch.setattr(detect, "UNSCANNED_COMBINATIONS", [])
    monkeypatch.setattr(detect, "REPO_CONTEXT_BUDGET", 60)
    monkeypatch.setattr(detect, "_MIN_VAR_CONTEXTS", 1)
    root = ""
    files = {}
    for name in ("a", "b"):
        files[tmp_path / name / "main.tf"] = (
            'variable "c" {}\nresource "x" "y" {\n  c = var.c\n}\n'
        )
        root += "".join(
            f'module "{name}{i}" {{\n  source = "./{name}"\n  c = "{i}"\n}}\n' for i in range(40)
        )
    files[tmp_path / "main.tf"] = root
    contexts = detect._extract_var_contexts_by_dir(files)
    assert len(contexts[str(tmp_path.resolve() / "a")]) == 40
    assert len(contexts[str(tmp_path.resolve() / "b")]) == 20
    assert [e["distinct"] for e in detect.UNSCANNED_CONTEXTS] == [40]


def test_max_module_contexts_must_be_positive(tmp_path) -> None:
    out = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"), "--target", str(tmp_path),
         "--max-module-contexts", "0"],
        capture_output=True, text=True, check=False,
    )
    assert out.returncode == 2
    assert "must be at least 1" in out.stderr


def test_every_value_scanned_gives_only_a_warning(tmp_path) -> None:
    calls = [
        'name = "b"\n  public = true\n  acl = "private"',
        'name = "b"\n  public = false\n  acl = "public-read"',
        'name = "b"\n  public = true\n  acl = "public-read"',
    ]
    _write_callers(tmp_path, CHILD, calls)
    report, code, err = _report(tmp_path, "--fail-on", "CRITICAL", "--max-module-contexts", "2")
    assert code == 0
    assert "unscanned_contexts" not in report["summary"]
    assert report["summary"]["unscanned_combinations"][0]["distinct"] == 3
    assert "every input value was, but not every combination" in err
    assert "ERROR" not in err


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=cwd, check=True, capture_output=True,
    )


@pytest.mark.parametrize(
    ("changed", "code"),
    [("other/a.tf", 0), ("child/extra.tf", 1), ("main.tf", 1)],
)
def test_diff_mode_gates_only_on_modules_it_touches(changed, code, tmp_path) -> None:
    calls = [f'name = "n{i}"\n  cidr = "10.{i}.0.0/16"' for i in range(100)]
    _write_callers(tmp_path, CHILD, calls)
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "b.tf").write_text('locals {\n  b = 1\n}\n')
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "base")
    _git(tmp_path, "switch", "-q", "-c", "pr")
    path = tmp_path / changed
    path.write_text(path.read_text() + '\nlocals {\n  added = 1\n}\n' if path.exists()
                    else 'locals {\n  added = 1\n}\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "change")
    report, got, err = _report(
        tmp_path, "--mode", "diff", "--diff-base", "main", "--fail-on", "CRITICAL",
        "--max-module-contexts", "8",
    )
    assert got == code, err
    assert ("unscanned_contexts" in report["summary"]) is bool(code)


# ---- --mode verify-fixed ------------------------------------------------------------


def _sg_module(root: Path, cidrs: list[str]) -> None:
    (root / "child").mkdir(exist_ok=True)
    (root / "child" / "main.tf").write_text(
        'variable "cidr" {}\n' + (SG % "[var.cidr]")
    )
    (root / "main.tf").write_text(
        "".join(
            f'module "m{i}" {{\n  source = "./child"\n  cidr = "{c}"\n}}\n'
            for i, c in enumerate(cidrs)
        )
    )


def test_verify_fixed_does_not_call_a_live_finding_resolved(tmp_path) -> None:
    prior = tmp_path / "prior.json"
    target = tmp_path / "tf"
    target.mkdir()
    _sg_module(target, ["0.0.0.0/0"])
    report, _, _ = _report(target, "--no-suppress")
    prior.write_text(json.dumps(report))
    _sg_module(target, [f"10.0.{i}.0/24" for i in range(30)] + ["0.0.0.0/0"])
    env = {k: v for k, v in os.environ.items() if k != "TF_ANALYZE_TEST_FORCE_FALLBACK"}
    out = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"), "--target", str(target),
         "--mode", "verify-fixed", "--prior-report", str(prior), "--fail-on", "CRITICAL",
         "--format", "json", "--max-module-contexts", "8"],
        capture_output=True, text=True, check=False, env=env,
    )
    results = json.loads(out.stdout)["results"]
    assert out.returncode == 1, out.stderr
    assert SG_RULE not in {f["id"] for f in results["RESOLVED"]}
    assert SG_RULE in {f["id"] for f in results["UNREADABLE"]}


# ---- which inputs count ----------------------------------------------------------------


def test_cutting_tags_leaves_the_same_text_elsewhere(tmp_path) -> None:
    child = (
        'variable "acl" {\n  default = "x"\n}\nvariable "name" {}\n'
        'variable "acl_mode" {\n  default = "private"\n}\n'
        'resource "aws_s3_bucket_acl" "b" {\n  bucket = "b"\n  acl    = var.acl_mode\n'
        "  tags   = var.acl\n}\n"
        'resource "aws_s3_bucket" "c" {\n  bucket = "c"\n  tags   = { Name = var.name }\n}\n'
    )
    calls = [f'name = "t{i}"\n  acl_mode = "{"public-read" if i == 69 else "private"}"' for i in range(70)]
    _write_callers(tmp_path, child, calls)
    report, _, _ = _report(tmp_path, "--max-module-contexts", "8")
    assert ACL_RULE in {f["id"] for f in report["findings"]}
    assert "acl_mode" in detect._inputs_in_use([child], skip_tags=True)
    assert "acl" not in detect._inputs_in_use([child], skip_tags=True)


CUSTOM_TAG_RULE = """id: X-TAG-001
title: "public data class tag"
section: security
impact: x
default_urgency: HIGH
blast_radius: single-resource
status: active
recommendation: fix
verification: check
patterns:
  - kind: resource_arg
    resource: aws_s3_bucket
    arg: tags
    regex: 'public'
"""


def test_custom_rule_on_tag_values_keeps_tag_inputs(tmp_path) -> None:
    (tmp_path / "cat").mkdir()
    (tmp_path / "cat" / "X-TAG-001.yaml").write_text(CUSTOM_TAG_RULE)
    (tmp_path / "tf").mkdir()
    child = 'variable "t" {\n  default = ""\n}\nresource "aws_s3_bucket" "b" {\n  bucket = "b"\n  tags   = var.t\n}\n'
    calls = [f't = "{"public" if i == 69 else f"t{i}"}"' for i in range(70)]
    _write_callers(tmp_path / "tf", child, calls)
    flags = ("--max-module-contexts", "8", "--fail-on", "CRITICAL")
    report, code, _ = _report(tmp_path / "tf", "--catalog", str(tmp_path / "cat"), *flags)
    assert code == 1
    assert report["summary"]["unscanned_contexts"]
    report, code, _ = _report(tmp_path / "tf", *flags)
    assert code == 0
    assert _no_unscanned(report)


def test_builtin_rules_do_not_read_tag_values() -> None:
    assert not detect._rules_read_tag_values(list(CATALOG.values()))


@pytest.mark.parametrize(
    "pat",
    [
        {"kind": "resource_arg", "arg": "tags", "regex": "x"},
        {"kind": "hcl_attr", "path": "labels.env", "not_equal": "x"},
        {"kind": "resource_missing_arg", "arg": "x", "suppress_if": {"arg": "tags.a", "equals": "b"}},
        {"kind": "resource_missing_arg", "arg": "x", "suppress_if": [{"arg": "labels", "regex": "b"}]},
        {"kind": "policy", "forbid": 'resource.tags.env == "x"'},
    ],
)
def test_rules_that_read_tag_values(pat) -> None:
    assert detect._rules_read_tag_values([{"patterns": [pat]}])


def test_presence_of_tags_does_not_read_a_value() -> None:
    assert not detect._rules_read_tag_values(
        [{"patterns": [{"kind": "resource_missing_arg", "arg": "tags"}]}]
    )


# ---- statement objects inside expressions ------------------------------------------

A_STMT = '{Effect="Allow",Action="*",Resource="*"}'
D_STMT = '{Effect="Deny",Action="*",Resource="*"}'


@pytest.mark.parametrize(
    "value",
    [
        f"jsonencode({{Statement=concat(local.b,[{A_STMT}])}})",
        f"jsonencode(merge(var.x,{{Statement=[{A_STMT}]}}))",
        f"jsonencode({{Statement=flatten([[{A_STMT}]])}})",
        'jsonencode({Statement=[{Sid=format("\\"%s",var.n),Effect="Allow",Action="*",Resource="*"}]})',
        'jsonencode({Statement=[{Sid=replace(var.n,"/[\\"]/",""),Effect="Allow",Action="*",Resource="*"}]})',
        f'var.a ? jsonencode({{Statement=[{A_STMT}]}}) : "{{}}"',
        f"tostring(jsonencode({{Statement=[{A_STMT}]}}))",
        '<<EOT\n{"Statement":[%{ if var.x }{"Effect":"Allow","Action":"*","Resource":"*"}%{ endif }]}\nEOT',
    ],
)
def test_statement_inside_an_expression_is_read(value, path_mode, tmp_path) -> None:
    assert _fires(POLICY % value, ADMIN_RULE, tmp_path)


@pytest.mark.parametrize(
    "value",
    [
        f"jsonencode({{Statement=concat(local.b,[{D_STMT}])}})",
        f"jsonencode(merge(var.x,{{Statement=[{D_STMT}]}}))",
        f'var.a ? jsonencode({{Statement=[{D_STMT}]}}) : "{{}}"',
    ],
)
def test_deny_inside_an_expression_stays_a_deny(value, path_mode, tmp_path) -> None:
    assert not _fires(POLICY % value, ADMIN_RULE, tmp_path)


def test_unread_statement_string_warns() -> None:
    assert _iam_policy._unread_statements({"Statement": "${concat(a, [{ nope }])}"})
    assert _iam_policy._unread_statements({"Statement": ["${f({ nope })}"]})
    assert not _iam_policy._unread_statements({"Statement": "${var.s}"})
    assert not _iam_policy._unread_statements({"Statement": [{"Effect": "Allow"}]})


def test_a_template_warns_even_when_a_statement_is_found(tmp_path, capsys) -> None:
    text = POLICY % '<<EOT\n{"Statement":[%{ if var.x }{"Effect":"Allow","Action":"s3:Get","Resource":"x"}%{ endif }]}\nEOT'
    _fires(text, ADMIN_RULE, tmp_path)
    assert "policy could not be decoded" in capsys.readouterr().err


def test_a_written_field_in_an_unread_call_warns() -> None:
    assert _iam_policy._is_written_out('${f(Statement = g())}')
    assert not _iam_policy._is_written_out("${jsonencode(var.p)}")
    assert not _iam_policy._is_written_out("${data.aws_iam_policy_document.d.json}")


# ---- suppress_if on hcl_attr ---------------------------------------------------------


@pytest.mark.parametrize(("mode", "fires"), [("ENCRYPTED_ONLY", False), ("OTHER", True)])
def test_hcl_attr_honours_suppress_if(mode, fires, path_mode, tmp_path) -> None:
    text = (
        'resource "google_sql_database_instance" "x" {\n  settings {\n    ip_configuration {\n'
        f'      require_ssl = false\n      ssl_mode    = "{mode}"\n    }}\n  }}\n}}\n'
    )
    assert _fires(text, "STK-GCP-CLOUDSQL-004", tmp_path) is fires


# ---- fleet --------------------------------------------------------------------------


def test_fleet_report_lists_unscanned_values(tmp_path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    calls = [f'name = "n{i}"\n  cidr = "10.{i}.0.0/16"' for i in range(30)]
    _write_callers(tmp_path / "a", CHILD, calls)
    (tmp_path / "b" / "main.tf").write_text("locals {\n  x = 1\n}\n")
    env = {k: v for k, v in os.environ.items() if k != "TF_ANALYZE_TEST_FORCE_FALLBACK"}
    out = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"), "--mode", "fleet", "--format", "json",
         "--target", str(tmp_path / "a"), "--target", str(tmp_path / "b"),
         "--max-module-contexts", "8", "--fail-on", "CRITICAL"],
        capture_output=True, text=True, check=False, env=env,
    )
    assert out.returncode == 1
    assert json.loads(out.stdout)["unscanned_contexts"]


def test_action_passes_max_module_contexts_to_the_engine() -> None:
    action = (REPO / "action.yml").read_text()
    assert "max-module-contexts:\n" in action
    assert "TFA_MAX_MODULE_CONTEXTS: ${{ inputs.max-module-contexts }}" in action
    assert 'ARGS+=(--max-module-contexts "${TFA_MAX_MODULE_CONTEXTS}")' in action


# ---- a folded value is a value, not an unknown ---------------------------------------

REF_CALLER = "aws_thing.x.val"
FOLDED = [
    '"${var.public ? "public-read" : "private"}"',
    'var.public ? "public-read" : "private"',
    "local.t ? local.a : local.b",
    "var.vt ? var.va : var.vb",
    "(var.public ? local.a : local.b)",
    '"${var.vt ? var.va : var.vb}"',
    '"${true ? "public-read" : "private"}"',
    '"${"public-read"}"',
    '("${"public-read"}")',
    '("public-read")',
]
ROOT_VARS = """variable "public" {
  default = true
}
variable "vt" {
  default = true
}
variable "va" {
  default = "public-read"
}
variable "vb" {
  default = "private"
}
locals {
  t = true
  a = "public-read"
  b = "private"
}
"""


def _callers_of_child(root: Path, child: str, values: list[str], preamble: str = ROOT_VARS) -> None:
    (root / "child").mkdir(parents=True)
    (root / "child" / "main.tf").write_text(child)
    (root / "main.tf").write_text(
        preamble
        + "".join(
            f'module "m{i}" {{\n  source = "./child"\n  v = {v}\n}}\n' for i, v in enumerate(values)
        )
    )


def _in_process_ids(root: Path, rule: str) -> bool:
    files = {p.resolve(): p.read_text() for p in root.rglob("*.tf")}
    scan = detect._file_scanner(files, [CATALOG[rule]])
    return any(f["id"] == rule for fp, text in files.items() for f in scan(fp, text, [CATALOG[rule]]))


@pytest.mark.parametrize("value", FOLDED)
@pytest.mark.parametrize("order", ["ref_first", "ref_last"])
def test_a_folded_value_beside_a_reference_is_scanned(value, order, path_mode, tmp_path) -> None:
    values = [REF_CALLER, value] if order == "ref_first" else [value, REF_CALLER]
    _callers_of_child(tmp_path, 'variable "v" {}\n' + ACL % "var.v", values)
    assert _in_process_ids(tmp_path, ACL_RULE)


def test_conditional_on_a_list_beside_a_reference(path_mode, tmp_path) -> None:
    preamble = 'locals {\n  t  = true\n  cl = ["0.0.0.0/0"]\n}\n'
    _callers_of_child(
        tmp_path, 'variable "v" {}\n' + SG % "var.v", [REF_CALLER, "local.t ? local.cl : []"], preamble,
    )
    assert _in_process_ids(tmp_path, SG_RULE)


@pytest.mark.parametrize("swap", [False, True])
def test_conditionals_do_not_merge_with_each_other(swap, path_mode, tmp_path) -> None:
    preamble = 'locals {\n  pub = true\n  a   = "public-read"\n  b   = "private"\n}\n'
    values = ["local.pub ? local.b : local.a", "local.pub ? local.a : local.b"]
    _callers_of_child(tmp_path, 'variable "v" {}\n' + ACL % "var.v", values[::-1] if swap else values, preamble)
    assert _in_process_ids(tmp_path, ACL_RULE)


def test_issue_input_exits_one(tmp_path) -> None:
    _callers_of_child(
        tmp_path, 'variable "v" {}\n' + ACL % "var.v",
        [REF_CALLER, '"${var.public ? "public-read" : "private"}"'],
    )
    assert ACL_RULE in _cli(tmp_path)[0]


@pytest.mark.parametrize(
    ("value", "regex"),
    [
        ("5", "^5$"),
        ("true", "^true$"),
        ('tomap({ class = "public" })', "public"),
        ('{ class = "public" }', "public"),
        ('["a", "public"]', "public"),
    ],
)
def test_values_flow_through_a_real_caller(value, regex, path_mode, tmp_path) -> None:
    entry = {
        "id": "X-FLOW-001",
        "patterns": [{"kind": "resource_arg", "resource": "aws_s3_bucket", "arg": "tags", "regex": regex}],
    }
    child = 'variable "v" {}\nresource "aws_s3_bucket" "b" {\n  bucket = "b"\n  tags   = var.v\n}\n'
    _callers_of_child(tmp_path, child, [REF_CALLER, value], "")
    files = {p.resolve(): p.read_text() for p in tmp_path.rglob("*.tf")}
    scan = detect._file_scanner(files, [entry])
    assert any(scan(fp, text, [entry]) for fp, text in files.items())
    values = [c.get("v") for c in detect._extract_var_contexts_by_dir(files)[str(tmp_path.resolve() / "child")]]
    assert len(values) == 2


# ---- --cache and a limit ----------------------------------------------------------------


def _six_callers(root: Path) -> list[str]:
    calls = _names(6)
    calls[5] += '\n  acl = "public-read"'
    _shared_module(root, calls)
    return ["--cache", "--cache-file", str(root / "c.json")]


def test_a_partial_scan_is_not_cached(tmp_path) -> None:
    flags = _six_callers(tmp_path)
    _report(tmp_path, *flags, "--max-module-contexts", "1")
    assert not (tmp_path / "c.json").exists()


def test_a_scan_missing_only_combinations_is_not_cached(tmp_path) -> None:
    calls = [
        'name = "b"\n  public = true\n  acl = "private"',
        'name = "b"\n  public = false\n  acl = "public-read"',
        'name = "b"\n  public = true\n  acl = "public-read"',
    ]
    _write_callers(tmp_path, CHILD, calls)
    cache = tmp_path / "c.json"
    report, _, _ = _report(
        tmp_path, "--cache", "--cache-file", str(cache), "--max-module-contexts", "2",
    )
    assert report["summary"]["unscanned_combinations"]
    assert not cache.exists()


def test_raising_the_limit_is_not_a_cache_hit(tmp_path) -> None:
    flags = _six_callers(tmp_path)
    report, _, _ = _report(tmp_path, *flags, "--max-module-contexts", "1")
    assert report["summary"]["unscanned_contexts"]
    report, _, err = _report(tmp_path, *flags, "--max-module-contexts", "100")
    assert "cache hit" not in err
    assert ACL_RULE in {f["id"] for f in report["findings"]}


def test_the_limit_is_part_of_the_cache_key(tmp_path) -> None:
    flags = _six_callers(tmp_path)
    _report(tmp_path, *flags, "--max-module-contexts", "100")
    assert (tmp_path / "c.json").exists()
    assert "cache hit" in _report(tmp_path, *flags, "--max-module-contexts", "100")[2]
    assert "cache hit" not in _report(tmp_path, *flags, "--max-module-contexts", "50")[2]


# ---- verify-fixed below a cut module -------------------------------------------------------

MID = """variable "acl" {
  default = "private"
}
variable "public" {
  default = false
}
module "l" {
  source = "../leaf"
  acl    = var.public ? var.acl : "private"
}
"""
LEAF = 'variable "acl" {}\n' + ACL % "var.acl"
BAD_CALLER = 'module "z" {\n  source = "./mid"\n  acl    = "public-read"\n  public = true\n}\n'


def _nested_verify(root: Path, callers: str, limit: str) -> dict:
    target = root / "tf"
    (target / "mid").mkdir(parents=True)
    (target / "leaf").mkdir()
    (target / "mid" / "main.tf").write_text(MID)
    (target / "leaf" / "main.tf").write_text(LEAF)
    (target / "main.tf").write_text(BAD_CALLER)
    prior = root / "prior.json"
    prior.write_text(json.dumps(_report(target, "--no-suppress")[0]))
    (target / "main.tf").write_text(callers + BAD_CALLER)
    env = {k: v for k, v in os.environ.items() if k != "TF_ANALYZE_TEST_FORCE_FALLBACK"}
    out = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"), "--target", str(target),
         "--mode", "verify-fixed", "--prior-report", str(prior), "--format", "json",
         "--max-module-contexts", limit],
        capture_output=True, text=True, check=False, env=env,
    )
    return json.loads(out.stdout)["results"]


def test_verify_fixed_covers_a_module_below_one_cut_for_a_combination(tmp_path) -> None:
    callers = (
        'module "x" {\n  source = "./mid"\n  acl    = "public-read"\n  public = false\n}\n'
        'module "y" {\n  source = "./mid"\n  acl    = "private"\n  public = true\n}\n'
    )
    results = _nested_verify(tmp_path, callers, "2")
    assert ACL_RULE not in {f["id"] for f in results["RESOLVED"]}
    assert ACL_RULE in {f["id"] for f in results["UNREADABLE"]}


def test_verify_fixed_covers_a_module_below_one_cut_for_a_value(tmp_path) -> None:
    callers = "".join(
        f'module "m{i}" {{\n  source = "./mid"\n  acl    = "a{i}"\n  public = true\n}}\n'
        for i in range(5)
    )
    results = _nested_verify(tmp_path, callers, "1")
    assert ACL_RULE not in {f["id"] for f in results["RESOLVED"]}


# ---- merge() is one object ------------------------------------------------------------------

LOCAL_DENY = (
    'locals {\n  deny = { Effect = "Deny" }\n  allow = { Effect = "Allow" }\n  empty = {}\n}\n'
)


@pytest.mark.parametrize(
    ("statement", "fires"),
    [
        ('merge({ Effect = "Allow", Action = "*", Resource = "*" }, { Effect = "Deny" })', False),
        ('merge({ Effect = "Deny", Action = "*", Resource = "*" }, { Effect = "Allow" })', True),
        ('merge({ Effect = "Allow" }, { Action = "*", Resource = "*" })', True),
        ('merge({ Action = "*", Resource = "*" }, { Effect = "Deny" })', False),
        ('merge(merge({ Effect = "Deny" }, { Action = "*" }), { Resource = "*" })', False),
        ('merge(var.x, { Effect = "Allow", Action = "*", Resource = "*" })', True),
        ('merge({ Effect = "Allow", Action = "*", Resource = "*" }, var.x)', True),
        ('merge({ Effect = "Allow", Action = "*", Resource = "*" }, var.x, local.other)', True),
        ('merge({ Effect = "Allow", Action = "*", Resource = "*" }, var.x, { Effect = "Deny" })', False),
        ('merge(merge(var.x, { Action = "*", Resource = "*" }), { Effect = "Allow" })', True),
        ('merge(merge(var.x, { Action = "*", Resource = "*" }), { Effect = "Deny" })', False),
        ('merge({ Effect = "Deny", Action = "*", Resource = "*" }, var.x, { Effect = "Allow" })', True),
    ],
)
def test_merge_is_one_statement(statement, fires, path_mode, tmp_path) -> None:
    text = POLICY % f"jsonencode({{ Statement = [{statement}] }})"
    assert _fires(text, ADMIN_RULE, tmp_path) is fires


@pytest.mark.parametrize(
    "statement",
    [
        'merge(local.unknown, { Action = "*", Resource = "*" })',
        'merge(local.deny, { Action = "*", Resource = "*" })',
        'merge(local.allow, { Action = "*", Resource = "*" })',
        'merge({ Effect = "Deny", Action = "*", Resource = "*" }, local.empty)',
        'merge({ Effect = "Deny", Action = "*", Resource = "*" }, var.x)',
        'merge(merge({ Effect = "Deny", Action = "*", Resource = "*" }, var.x), { Sid = "s" })',
        'merge(merge({ Action = "*", Resource = "*" }, var.x), { Sid = "s" })',
        'merge({ Action = "*", Resource = "*" }, var.x)',
    ],
)
def test_unknown_effect_warns_and_does_not_fire(statement, path_mode, tmp_path, capsys) -> None:
    text = LOCAL_DENY + POLICY % f"jsonencode({{ Statement = [{statement}] }})"
    fp = tmp_path / "main.tf"
    fp.write_text(text)
    vd = detect._extract_var_defaults_by_dir({str(fp): text})[str(tmp_path)]
    assert not _fires(text, ADMIN_RULE, tmp_path, vd)
    assert "policy could not be decoded" in capsys.readouterr().err


def test_call_arguments() -> None:
    assert _iam_policy._call_arguments('{"a": "x,y"}, f(1, 2), [3, 4]') == [
        '{"a": "x,y"}', " f(1, 2)", " [3, 4]",
    ]


def test_a_merge_of_nothing_written_out_stays_quiet(tmp_path, capsys) -> None:
    assert not _fires(POLICY % "jsonencode(merge(var.a, var.b))", ADMIN_RULE, tmp_path)
    assert "could not be decoded" not in capsys.readouterr().err


def test_hitting_the_object_limit_warns(path_mode, tmp_path, capsys) -> None:
    empties = ",".join(["{}"] * 1100)
    statements = f'concat([{empties}],[{{ Effect = "Allow", Action = "*", Resource = "*" }}])'
    _fires(POLICY % f"jsonencode({{ Statement = {statements} }})", ADMIN_RULE, tmp_path)
    assert "policy could not be decoded" in capsys.readouterr().err


def test_under_the_object_limit_does_not_warn(tmp_path, capsys) -> None:
    empties = ",".join(["{}"] * 900)
    statements = f'concat([{empties}],[{{ Effect = "Allow", Action = "*", Resource = "*" }}])'
    assert _fires(POLICY % f"jsonencode({{ Statement = {statements} }})", ADMIN_RULE, tmp_path)
    assert "could not be decoded" not in capsys.readouterr().err


# ---- what scanned code writes can't steer the analysis ------------------------------

ADMIN_FIELDS = 'Effect = "Allow", Action = "*", Resource = "*"'


@pytest.mark.parametrize(
    "statement",
    [
        f"{{ __objects_cut__ = true, {ADMIN_FIELDS} }}",
        f"{{ __effect_unknown__ = true, {ADMIN_FIELDS} }}",
        f"{{ __unread__ = true, {ADMIN_FIELDS} }}",
        f"merge({{ __effect_unknown__ = true, {ADMIN_FIELDS} }})",
        f"merge({{ __objects_cut__ = true }}, {{ {ADMIN_FIELDS} }})",
    ],
)
def test_old_marker_text_in_a_policy_changes_nothing(statement, path_mode, tmp_path) -> None:
    assert _fires(POLICY % f"jsonencode({{ Statement = [{statement}] }})", ADMIN_RULE, tmp_path)


def test_a_heredoc_with_old_marker_text_is_analysed(path_mode, tmp_path) -> None:
    policy = '{"Statement":[{"__objects_cut__":true,"__effect_unknown__":true,"Effect":"Allow","Action":"*","Resource":"*"}]}'
    assert _fires(POLICY % f"<<POL\n{policy}\nPOL", ADMIN_RULE, tmp_path)


def test_the_word_unknown_is_not_an_unknown_effect(path_mode, tmp_path) -> None:
    text = POLICY % 'jsonencode({ Statement = [{ Effect = "unknown", Action = "*", Resource = "*" }] })'
    assert _fires(text, ADMIN_RULE, tmp_path)


def test_markers_are_private_objects() -> None:
    assert not any(
        isinstance(m, str)
        for m in (_iam_policy._EFFECT_UNKNOWN, _iam_policy._UNREAD, _iam_policy._OBJECTS_CUT)
    )


def test_the_limit_marker_is_not_a_statement() -> None:
    doc = {"Statement": [_iam_policy._OBJECTS_CUT, {"Effect": "Allow", "Action": "*"}]}
    assert len(_iam_policy.json_statements(doc)) == 1
    assert _iam_policy._unread_statements(doc)


def test_a_caller_cannot_mark_its_input_unknown(tmp_path) -> None:
    (tmp_path / "mid").mkdir()
    (tmp_path / "child").mkdir()
    (tmp_path / "child" / "main.tf").write_text('variable "acl" {}\n' + ACL % "var.acl")
    (tmp_path / "mid" / "main.tf").write_text(
        'variable "acl" {}\nmodule "c" {\n  source = "../child"\n  acl    = var.acl\n}\n'
    )
    (tmp_path / "main.tf").write_text(
        'module "a" {\n  source = "./mid"\n  acl    = aws_thing.x.val\n}\n'
        'module "b" {\n  source = "./mid"\n  __unknown_inputs__ = "acl"\n  acl    = "public-read"\n}\n'
    )
    assert ACL_RULE in _cli(tmp_path)[0]


# ---- merge() follows no references ---------------------------------------------------

AD = 'Effect = "Allow", Action = "*", Resource = "*"'
MERGE_ALLOW_VAR = POLICY % f"jsonencode({{ Statement = [merge({{ {AD} }}, var.x)] }})"


def _gated(target: Path) -> tuple[set[str], int, str]:
    return _cli(target, "--fail-on", "CRITICAL")


@pytest.mark.parametrize(
    "files",
    [
        {
            "main.tf": 'variable "x" {\n  default = {}\n}\nmodule "c" {\n  source = "./c"\n  x = merge(var.x, { Sid = "a" })\n}\n',
            "c/main.tf": 'variable "x" {\n  default = {}\n}\n' + MERGE_ALLOW_VAR,
        },
        {
            "main.tf": 'variable "y" {}\nlocals {\n  x = merge(var.y, { Sid = "a" })\n}\nmodule "c" {\n  source = "./c"\n  y = local.x\n}\n',
            "c/main.tf": 'variable "y" {}\n' + MERGE_ALLOW_VAR.replace("var.x", "var.y"),
        },
        {"main.tf": 'locals {\n  a = merge(local.a, { Sid = "x" })\n}\n' + MERGE_ALLOW_VAR.replace("var.x", "local.a")},
        {"main.tf": 'locals {\n  a = merge(local.b)\n  b = merge(local.a)\n}\n' + MERGE_ALLOW_VAR.replace("var.x", "local.a")},
        {
            "main.tf": "locals {\n  a0 = { Sid = \"x\" }\n"
            + "".join(f"  a{i} = merge(local.a{i - 1}, local.a{i - 1})\n" for i in range(1, 21))
            + "}\n"
            + MERGE_ALLOW_VAR.replace("var.x", "local.a20")
        },
    ],
    ids=["pass_through_var", "pass_through_local", "self_local", "two_locals", "fan_out"],
)
def test_valid_terraform_does_not_crash_the_scan(files, tmp_path) -> None:
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(exist_ok=True)
        (tmp_path / name).write_text(text)
    ids, code, err = _gated(tmp_path)
    assert code == 1, err
    assert ADMIN_RULE in ids
    assert "Traceback" not in err
    assert "exceeded" not in err


def test_a_thousand_nested_merges_warn_and_do_not_crash(tmp_path) -> None:
    expr = f"{{ {AD} }}"
    for _ in range(1000):
        expr = f"merge({expr})"
    (tmp_path / "main.tf").write_text(POLICY % f"jsonencode({{ Statement = [{expr}] }})")
    ids, code, err = _gated(tmp_path)
    assert code in (0, 1)
    assert "Traceback" not in err
    assert "policy could not be decoded" in err or ADMIN_RULE in ids


@pytest.mark.parametrize("layers", [1, 2, 8, 30])
def test_nested_literal_merges_still_read(layers, path_mode, tmp_path) -> None:
    expr = f"{{ {AD} }}"
    for _ in range(layers):
        expr = f"merge({expr})"
    assert _fires(POLICY % f"jsonencode({{ Statement = [{expr}] }})", ADMIN_RULE, tmp_path)


DEFAULT_DENY = 'variable "x" {\n  default = { Effect = "Deny" }\n}\n'


def test_a_default_deny_does_not_cancel_an_allow(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(DEFAULT_DENY + MERGE_ALLOW_VAR)
    ids, code, _ = _gated(tmp_path)
    assert ADMIN_RULE in ids
    assert code == 1


@pytest.mark.parametrize("caller", ["data.external.p.result", "aws_x.y.z", "var.u", "{}"])
def test_a_default_deny_in_a_child_does_not_cancel_an_allow(caller, tmp_path) -> None:
    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "main.tf").write_text(DEFAULT_DENY + MERGE_ALLOW_VAR)
    (tmp_path / "main.tf").write_text(
        f'variable "u" {{}}\nmodule "c" {{\n  source = "./c"\n  x = {caller}\n}}\n'
    )
    ids, code, _ = _gated(tmp_path)
    assert ADMIN_RULE in ids
    assert code == 1


@pytest.mark.parametrize(
    ("statement", "fires"),
    [
        (f'merge(tomap({{ {AD} }}), {{ Resource = "*" }})', True),
        (f'merge(var.x ? {{ {AD} }} : {{}}, {{ Resource = "*" }})', True),
        (f'merge(try({{ {AD} }}, {{}}), {{ Action = "*" }})', True),
        (f'merge(tomap({{ {AD} }}), {{ Sid = "x" }})', True),
        (f'merge(tomap({{ {AD} }}), {{ Effect = "Deny" }})', False),
        (f'merge(tomap({{ {AD} }}), {{ Action = "s3:GetObject" }})', False),
        ('merge({ Effect = "Deny" }, tomap({ Action = "*", Resource = "*" }))', False),
        ('merge({ Effect = "Allow" }, tomap({ Action = "*", Resource = "*" }))', True),
        ('merge(tomap({ Action = "*", Resource = "*" }), var.x)', False),
    ],
)
def test_a_wrapper_does_not_hide_a_literal(statement, fires, path_mode, tmp_path) -> None:
    assert _fires(POLICY % f"jsonencode({{ Statement = [{statement}] }})", ADMIN_RULE, tmp_path) is fires


# ---- text in a string stays text ---------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        f'merge({{ {AD}, Condition = {{ StringNotEquals = {{ "aws:PrincipalTag/x" = "}}}}}}, {{\\"Effect\\": \\"Deny\\"}})" }} }} }})',
        f'merge({{ {AD} }}, {{ Condition = {{ StringEquals = {{ "a:b" = "}}}}}}, {{\\"Effect\\":\\"Deny\\"}})" }} }} }})',
        'merge({ Effect = "Deny", Action = "*", Resource = "*", Condition = { StringEquals = { "aws:x" = "say \\"hi\\"" } } }, { Effect = "Allow" })',
        f'merge({{ {AD}, Condition = {{ StringEquals = {{ "aws:x" = "say \\"hi\\"" }} }} }}, {{ Sid = "a" }})',
        f'merge({{ {AD}, Condition = {{ StringEquals = {{ "a:b" = ")" }} }} }}, {{ Sid = "a" }})',
    ],
)
def test_string_text_is_not_read_as_code(statement, path_mode, tmp_path) -> None:
    assert _fires(POLICY % f"jsonencode({{ Statement = [{statement}] }})", ADMIN_RULE, tmp_path)


def test_a_deny_with_quotes_in_its_condition_stays_a_deny(path_mode, tmp_path) -> None:
    statement = 'merge({ Effect = "Deny", Action = "*", Resource = "*", Condition = { StringEquals = { "aws:x" = "a\\"b" } } }, { Sid = "x" })'
    assert not _fires(POLICY % f"jsonencode({{ Statement = [{statement}] }})", ADMIN_RULE, tmp_path)


def test_an_unclosed_call_warns() -> None:
    assert _iam_policy._embedded_statements("merge({") == [_iam_policy._OBJECTS_CUT]


# ---- engine keys in the variable table -----------------------------------------------------

LOCAL_ACL = 'locals {\n  a = "public-read"\n}\n' + ACL % "local.a"
TAG_RULE = "OPS-AWS-TAGS-001"
BARE_BUCKET = 'resource "aws_s3_bucket" "x" {\n  bucket = "b"\n}\n'


def test_tfvars_cannot_set_a_local(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(LOCAL_ACL)
    (tmp_path / "terraform.tfvars").write_text('__local__a = "private"\n')
    assert ACL_RULE in _cli(tmp_path)[0]


def test_tfvars_json_cannot_set_a_local(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(LOCAL_ACL)
    (tmp_path / "terraform.tfvars.json").write_text('{"__local__a": "private"}')
    assert ACL_RULE in _cli(tmp_path)[0]


@pytest.mark.parametrize("default", [True, False])
def test_a_caller_cannot_set_a_local(default, tmp_path) -> None:
    (tmp_path / "c").mkdir()
    declared = 'variable "__local__a" {\n  default = "private"\n}\n' if default else ""
    (tmp_path / "c" / "main.tf").write_text(declared + LOCAL_ACL)
    (tmp_path / "main.tf").write_text(
        'module "c" {\n  source = "./c"\n  __local__a = "private"\n}\n'
    )
    assert ACL_RULE in _cli(tmp_path)[0]


@pytest.mark.parametrize(
    "key", ["__aws_default_tags__", "__aws_default_tags_providers__"],
)
def test_tfvars_cannot_switch_off_tag_rules(key, tmp_path) -> None:
    (tmp_path / "main.tf").write_text(BARE_BUCKET)
    assert TAG_RULE in _cli(tmp_path)[0]
    (tmp_path / "terraform.tfvars").write_text(f'{key} = "true"\n')
    assert TAG_RULE in _cli(tmp_path)[0]


def test_a_caller_cannot_switch_off_tag_rules(tmp_path) -> None:
    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "main.tf").write_text(BARE_BUCKET)
    (tmp_path / "main.tf").write_text(
        'module "c" {\n  source = "./c"\n  __aws_default_tags__ = "true"\n}\n'
    )
    assert TAG_RULE in _cli(tmp_path)[0]


def test_tfvars_cannot_fake_a_resource_in_the_repo(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(BARE_BUCKET)
    (tmp_path / "terraform.tfvars").write_text('__repo_has__ = "aws_ebs_encryption_by_default"\n')
    files = {tmp_path / "main.tf": BARE_BUCKET}
    table = detect._extract_var_contexts_by_dir(files)[str(tmp_path)][0]
    assert "aws_ebs_encryption_by_default" not in table.get(_hcl.REPO_HAS_KEY, "")


def test_real_default_tags_still_work(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(
        'provider "aws" {\n  default_tags {\n    tags = { a = "b" }\n  }\n}\n' + BARE_BUCKET
    )
    assert TAG_RULE not in _cli(tmp_path)[0]


# ---- lists of references ---------------------------------------------------------------------


def test_lists_of_references_do_not_fail_a_large_repo(tmp_path) -> None:
    child = 'variable "ids" {}\n' + "".join(
        f'resource "aws_lb" "l{i}" {{\n  subnets = var.ids\n}}\n' for i in range(300)
    )
    (tmp_path / "child").mkdir()
    (tmp_path / "child" / "main.tf").write_text(child)
    (tmp_path / "main.tf").write_text(
        "".join(
            f'module "m{i}" {{\n  source = "./child"\n  ids = [aws_subnet.s{i}.id]\n}}\n'
            for i in range(700)
        )
    )
    files = {p.resolve(): p.read_text() for p in tmp_path.rglob("*.tf")}
    assert len(detect._extract_var_contexts_by_dir(files)[str(tmp_path.resolve() / "child")]) == 1


def test_a_list_with_a_literal_stays_distinct(path_mode, tmp_path) -> None:
    _callers_of_child(
        tmp_path, 'variable "v" {}\n' + SG % "var.v",
        ["[aws_x.a.id]", "[aws_x.b.id]", '["0.0.0.0/0", aws_x.c.id]'], "",
    )
    assert _in_process_ids(tmp_path, SG_RULE)


def test_defaults_table_starts_each_scan_clean(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(detect, "UNSCANNED_CONTEXTS", [{"module": "/old"}])
    monkeypatch.setattr(detect, "UNSCANNED_COMBINATIONS", [{"module": "/old"}])
    monkeypatch.setattr(detect, "_PARTIAL_MODULES", {"/old"})
    detect._extract_var_defaults_by_dir({str(tmp_path / "main.tf"): "locals {\n  a = 1\n}\n"})
    assert not detect.UNSCANNED_CONTEXTS
    assert not detect.UNSCANNED_COMBINATIONS
    assert not detect._PARTIAL_MODULES


# ---- a user's __local__x is an ordinary variable ----------------------------------------


def test_variable_named_like_an_engine_key_is_read(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(
        'variable "__local__acl" {\n  default = "public-read"\n}\n' + ACL % "var.__local__acl"
    )
    assert ACL_RULE in _cli(tmp_path)[0]


def test_tfvars_value_named_like_an_engine_key_is_read(tmp_path) -> None:
    (tmp_path / "main.tf").write_text('variable "__local__acl" {}\n' + ACL % "var.__local__acl")
    (tmp_path / "terraform.tfvars").write_text('__local__acl = "public-read"\n')
    assert ACL_RULE in _cli(tmp_path)[0]


def test_caller_input_named_like_an_engine_key_is_read(tmp_path) -> None:
    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "main.tf").write_text('variable "__local__acl" {}\n' + ACL % "var.__local__acl")
    (tmp_path / "main.tf").write_text(
        'module "c" {\n  source = "./c"\n  __local__acl = "public-read"\n}\n'
    )
    assert ACL_RULE in _cli(tmp_path)[0]


def test_var_named_like_a_local_key_does_not_read_the_local(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(
        'locals {\n  acl = "public-read"\n}\n'
        'variable "__local__acl" {\n  default = "private"\n}\n' + ACL % "var.__local__acl"
    )
    assert ACL_RULE not in _cli(tmp_path)[0]


def test_engine_keys_cannot_be_identifiers() -> None:
    for key in (_hcl.LOCAL_KEY_PREFIX, _hcl.AWS_DEFAULT_TAGS_KEY, _hcl.REPO_HAS_KEY):
        assert key.startswith("\0")


# ---- text in a string is not a statement --------------------------------------------------

SPOOF = '"${var.x}}, {\\"Effect\\": \\"Deny\\"}"'
KEYS_SPOOF = '"${var.x}\\", \\"Effect\\": \\"Deny\\", \\"q\\": \\"y"'
REALISTIC = '"{\\"env\\": \\"${var.x}\\"}"'


@pytest.mark.parametrize(
    "statement",
    [
        f'{{ {AD}, Condition = {{ StringLike = {{ "a:b" = {SPOOF} }} }} }}',
        f"{{ {AD}, Sid = {SPOOF} }}",
        f"merge({{ {AD}, Sid = {SPOOF} }})",
        f"merge({{ {AD}, Sid = {SPOOF} }}, var.x)",
        f"{{ {AD}, Sid = {KEYS_SPOOF} }}",
        f'{{ {AD}, Condition = {{ StringLike = {{ "a:b" = {REALISTIC} }} }} }}',
        f"{{ Sid = {SPOOF}, {AD} }}",
    ],
)
def test_string_text_cannot_hide_a_statement(statement, path_mode, tmp_path, capsys) -> None:
    text = 'variable "x" {}\n' + POLICY % f"jsonencode({{ Statement = [{statement}] }})"
    assert _fires(text, ADMIN_RULE, tmp_path)
    assert "could not be decoded" in capsys.readouterr().err


def test_a_deny_with_such_a_string_stays_a_deny(path_mode, tmp_path) -> None:
    deny = 'Effect = "Deny", Action = "*", Resource = "*"'
    text = POLICY % f"jsonencode({{ Statement = [{{ {deny}, Sid = {SPOOF} }}] }})"
    assert not _fires(text, ADMIN_RULE, tmp_path)


def test_a_quoted_policy_with_an_interpolation_is_not_masked(path_mode, tmp_path, capsys) -> None:
    text = POLICY % '"{\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"*\\",\\"Resource\\":\\"*\\",\\"Sid\\":\\"${var.x}\\"}]}"'
    assert _fires(text, ADMIN_RULE, tmp_path)
    assert "could not be decoded" not in capsys.readouterr().err


def test_a_plain_interpolation_gives_no_warning(path_mode, tmp_path, capsys) -> None:
    text = POLICY % f'jsonencode({{ Statement = [{{ {AD}, Sid = "a-${{var.x}}" }}] }})'
    assert _fires(text, ADMIN_RULE, tmp_path)
    assert "could not be decoded" not in capsys.readouterr().err


def test_mask_leaves_a_whole_string_alone() -> None:
    assert _iam_policy._mask_escaped_expressions('"{\\"a\\": \\"${x}\\"}"')[1] is False
    assert _iam_policy._mask_escaped_expressions('f("${x}")')[1] is False
    assert _iam_policy._mask_escaped_expressions('f("\\"")')[1] is False
    assert _iam_policy._mask_escaped_expressions('f("${x}\\"")')[1] is True


def test_the_scan_steps_over_strings() -> None:
    assert _iam_policy._next_object('"{" ${a} {', 0) == (9, "{")
    assert _iam_policy._next_object('"merge(" merge(', 0) == (9, "merge")
    assert _iam_policy._next_object('"{"', 0)[0] == -1


def test_an_unreadable_object_is_a_partial_read() -> None:
    assert _iam_policy._OBJECTS_CUT in _iam_policy._embedded_statements('{ nope } {"Effect": "Allow"}')


def test_merge_of_a_wrapped_deny_and_an_unknown_warns(path_mode, tmp_path, capsys) -> None:
    deny = 'Effect = "Deny", Action = "*", Resource = "*"'
    text = POLICY % f"jsonencode({{ Statement = [merge(tomap({{ {deny} }}), var.x)] }})"
    assert not _fires(text, ADMIN_RULE, tmp_path)
    assert "could not be decoded" in capsys.readouterr().err
