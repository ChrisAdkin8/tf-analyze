"""IAM policy rules read policies from the parse tree (`_iam_policy`), so
every common way of writing a policy is analysed — not only the comma
style the old regex HCL→JSON conversion understood."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import _iam_policy
import pytest

REPO = Path(__file__).resolve().parents[1]


def _ids(tmp_path: Path, text: str) -> set[str]:
    (tmp_path / "main.tf").write_text(text)
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return {f["id"] for f in json.loads(out.stdout)["findings"]}


@pytest.fixture(autouse=True)
def _real_parser(monkeypatch):
    # These tests are about the tree path; the forced-fallback CI job
    # would route them through the legacy text path instead.
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)


ADMIN_FMT_STYLE = """resource "aws_iam_policy" "p" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
"""


# ---- every policy form is read ---------------------------------------------------


def test_terraform_fmt_style_without_commas(tmp_path) -> None:
    ids = _ids(tmp_path, ADMIN_FMT_STYLE)
    assert {"SEC-AWS-IAM-JSON-001", "SEC-AWS-IAM-JSON-003"} <= ids


def test_reference_in_another_statement_does_not_hide_the_policy(tmp_path) -> None:
    text = ADMIN_FMT_STYLE.replace(
        "    }]\n",
        '    }, {\n      Effect   = "Allow"\n      Action   = ["s3:GetObject"]\n'
        "      Resource = aws_s3_bucket.b.arn\n    }]\n",
    )
    assert "SEC-AWS-IAM-JSON-003" in _ids(tmp_path, text)


def test_heredoc_and_quoted_json_policies(tmp_path) -> None:
    doc = '{"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}'
    heredoc = (
        f'resource "aws_iam_role_policy" "h" {{\n  policy = <<EOT\n{doc}\nEOT\n}}\n'
    )
    assert "SEC-AWS-IAM-JSON-002" in _ids(tmp_path, heredoc)
    quoted = (
        f'resource "aws_iam_role_policy" "q" {{\n  policy = {json.dumps(doc)}\n}}\n'
    )
    assert "SEC-AWS-IAM-JSON-002" in _ids(tmp_path, quoted)


def test_inline_policy_block_on_a_role(tmp_path) -> None:
    text = """resource "aws_iam_role" "r" {
  assume_role_policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  inline_policy {
    name   = "admin"
    policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
  }
}
"""
    ids = _ids(tmp_path, text)
    assert {"SEC-AWS-IAM-JSON-001", "SEC-AWS-IAM-JSON-003"} <= ids
    assert "SEC-AWS-IAM-002" not in ids  # trust policy: a service principal


def test_dynamic_statement_in_policy_document(tmp_path) -> None:
    text = """data "aws_iam_policy_document" "d" {
  dynamic "statement" {
    for_each = var.statements
    content {
      actions   = ["*"]
      resources = ["*"]
    }
  }
}
"""
    assert "SEC-AWS-IAM-POLICY-005" in _ids(tmp_path, text)


def test_policy_document_finding_points_at_the_statement(tmp_path) -> None:
    text = (
        'data "aws_iam_policy_document" "d" {\n'
        '  statement {\n    actions = ["s3:GetObject"]\n    resources = ["arn:x"]\n  }\n'
        '  statement {\n    actions = ["*"]\n    resources = ["arn:y"]\n  }\n'
        "}\n"
    )
    (tmp_path / "main.tf").write_text(text)
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    [f] = [
        f
        for f in json.loads(out.stdout)["findings"]
        if f["id"] == "SEC-AWS-IAM-POLICY-001"
    ]
    assert f["line"] == 6


# ---- public principals --------------------------------------------------------------


@pytest.mark.parametrize("principal", ['"*"', '{ AWS = "*" }', '{ AWS = ["*"] }'])
def test_trust_policy_with_public_principal(tmp_path, principal) -> None:
    text = f"""resource "aws_iam_role" "r" {{
  assume_role_policy = jsonencode({{
    Statement = [{{
      Effect    = "Allow"
      Principal = {principal}
      Action    = "sts:AssumeRole"
    }}]
  }})
}}
"""
    assert "SEC-AWS-IAM-002" in _ids(tmp_path, text)


def test_bucket_policy_with_public_principal(tmp_path) -> None:
    text = """resource "aws_s3_bucket_policy" "b" {
  bucket = aws_s3_bucket.b.id
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.b.arn}/*"
    }]
  })
}
"""
    assert "SEC-AWS-IAM-JSON-004" in _ids(tmp_path, text)


# ---- what must not fire -------------------------------------------------------------


def test_deny_statement_and_variable_wildcards_do_not_fire(tmp_path) -> None:
    text = """resource "aws_iam_policy" "p" {
  policy = jsonencode({
    Statement = [
      { Effect = "Deny", Action = "*", Resource = "*" },
      { Effect = "Allow", Action = var.admin ? "*" : "s3:GetObject", Resource = "*" },
    ]
  })
}
"""
    ids = _ids(tmp_path, text)
    assert "SEC-AWS-IAM-JSON-001" not in ids
    assert "SEC-AWS-IAM-JSON-003" not in ids


# ---- the decoder --------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, action",
    [
        ('${jsonencode({"Statement": [{"Action": "*"}]})}', "*"),
        # Not valid JSON once rendered (quotes inside the expression): read as HCL.
        (
            '${jsonencode({"Statement": [{"Action": "${var.a ? "*" : "x"}"}]})}',
            '${var.a ? "*" : "x"}',
        ),
        ('{"Statement": {"Action": "*"}}', "*"),
    ],
)
def test_decode_policy_forms(value, action) -> None:
    doc = _iam_policy.decode_policy(value)
    [st] = _iam_policy.json_statements(doc)
    assert st.actions == [action]


@pytest.mark.parametrize(
    "value",
    [
        "${data.aws_iam_policy_document.d.json}",
        '${file("policy.json")}',
        "${var.policy}",
        "not json",
        None,
    ],
)
def test_decode_policy_unanalysable(value) -> None:
    assert _iam_policy.decode_policy(value) is None


# ---- regex fallback (file the parser could not read) ----------------------------

def test_fallback_converter_reads_fmt_style() -> None:
    import _hcl

    doc = _hcl._hcl_object_to_json('''{
    Statement = [{
      Effect    = "Allow"   # comment
      Action    = ["s3:GetObject", "*"]
      Resource  = aws_s3_bucket.b.arn
      Principal = { AWS = "*" }
      Condition = { Bool = { "aws:SecureTransport" = false } }
    }]
  }''')
    [st] = _iam_policy.json_statements(doc)
    assert st.actions == ["s3:GetObject", "*"]
    assert st.resources == ["${aws_s3_bucket.b.arn}"]
    assert st.principals == ["*"]
