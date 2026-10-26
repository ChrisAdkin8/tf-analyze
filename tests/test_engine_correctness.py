"""Engine bugs that made rules miss real problems or fire on comments
(critical review, engine findings). Each case pairs the shape that was
mishandled with a control that already worked."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from _catalog import load_yaml
from _hcl import _parse_tf_cached, brace_walk, strip_hcl_context

REPO = Path(__file__).resolve().parents[1]


def _ids(target: Path) -> list[tuple[str, str, str]]:
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--format",
            "json",
            "--show-info",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return [
        (f["id"], f.get("resource", ""), Path(f.get("file", "")).parent.name)
        for f in json.loads(proc.stdout)["findings"]
    ]


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _fires(tmp_path: Path, rule: str, text: str) -> bool:
    return any(i == rule for i, _, _ in _ids(_write(tmp_path, {"main.tf": text})))


# ---- same address in two modules ------------------------------------------------


def test_same_address_in_two_modules_is_checked_in_both(tmp_path) -> None:
    table = 'resource "aws_dynamodb_table" "this" {\n  name     = "t"\n  hash_key = "id"\n}\n'
    _write(tmp_path, {"orders/main.tf": table, "users/main.tf": table})
    dirs = {d for i, r, d in _ids(tmp_path) if i == "SEC-AWS-DDB-001"}
    assert dirs == {"orders", "users"}


# ---- escaped backslash and heredocs in the lexers ---------------------------------


def test_escaped_backslash_closes_the_string() -> None:
    assert brace_walk('{ v = "C:\\\\" }') == len('{ v = "C:\\\\" }')
    stripped = strip_hcl_context('x = "C:\\\\"\n# password = "p"\n')
    assert "password" not in stripped


def test_quote_in_a_heredoc_does_not_flip_comment_state() -> None:
    stripped = strip_hcl_context('u = <<EOF\nsed s/"//g\nEOF\n# db_password = "p"\n')
    assert "db_password" not in stripped
    assert 'sed s/"//g' in stripped  # heredoc text is kept for secret scanning


def test_commented_secret_after_a_backslash_string_is_not_reported(tmp_path) -> None:
    text = 'locals {\n  dir = "C:\\\\"\n}\n# password = "examplepassword"\n'
    assert not _fires(tmp_path, "SEC-SECRETS-001", text)


# ---- precondition ----------------------------------------------------------------


def test_precondition_with_backslash_string_is_still_checked(tmp_path) -> None:
    text = (
        'resource "terraform_data" "x" {\n  lifecycle {\n    precondition {\n'
        '      condition = var.p != "C:\\\\"\n    }\n  }\n}\n'
    )
    assert _fires(tmp_path, "ROB-PRECONDITION-001", text)


def test_precondition_in_a_block_comment_is_ignored(tmp_path) -> None:
    text = "/*\nprecondition {\n  condition = true\n}\n*/\nlocals {\n  x = 1\n}\n"
    assert not _fires(tmp_path, "ROB-PRECONDITION-001", text)


# ---- ignore_changes ---------------------------------------------------------------


@pytest.mark.parametrize(
    "lifecycle",
    [
        '    precondition {\n      condition     = true\n      error_message = "x"\n    }\n'
        "    ignore_changes = [ami, user_data, tags, instance_type, subnet_id, key_name, volume_tags]\n",
        '    ignore_changes = [tags["Owner"], tags["Team"], ami, user_data, instance_type, subnet_id, key_name]\n',
    ],
)
def test_ignore_changes_items_are_counted_past_nested_blocks_and_indexes(
    tmp_path, lifecycle
) -> None:
    text = f'resource "aws_instance" "a" {{\n  ami = "ami-1"\n  lifecycle {{\n{lifecycle}  }}\n}}\n'
    assert _fires(tmp_path, "ROB-DRIFT-003", text)


# ---- default_tags -------------------------------------------------------------------

TABLE = 'resource "aws_dynamodb_table" "q" {\n  name     = "q"\n  hash_key = "id"\n}\n'


def test_default_tags_in_a_comment_does_not_silence_tag_rules(tmp_path) -> None:
    provider = (
        'provider "aws" {\n  region = "eu-west-2"\n  # TODO: add default_tags\n}\n'
    )
    assert _fires(tmp_path, "OPS-AWS-TAGS-001", provider + TABLE)


def test_a_real_default_tags_block_still_satisfies_tag_rules(tmp_path) -> None:
    provider = (
        'provider "aws" {\n  region = "eu-west-2"\n  default_tags {\n'
        '    tags = {\n      Owner = "platform"\n    }\n  }\n}\n'
    )
    assert not _fires(tmp_path, "OPS-AWS-TAGS-001", provider + TABLE)


# ---- IAM heredoc with a bare interpolation ----------------------------------------------


def test_heredoc_policy_with_bare_interpolation_is_analysed(tmp_path, monkeypatch) -> None:
    # Parse-tree behaviour: run with the parser even in the forced-fallback job.
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)
    text = (
        'resource "aws_iam_policy" "p" {\n  name   = "p"\n  policy = <<-EOT\n'
        '    {\n      "Version": "2012-10-17",\n      "Statement": [{\n'
        '        "Effect": "Allow",\n        "Action": "*",\n'
        '        "Resource": ${jsonencode(var.arns)}\n      }]\n    }\n  EOT\n}\n'
    )
    assert _fires(tmp_path, "SEC-AWS-IAM-JSON-001", text)


# ---- helm provider v3 `set = [...]` -----------------------------------------------------

HELM_V3 = (
    'resource "helm_release" "web" {\n  name  = "web"\n  chart = "nginx"\n  set = [\n'
    '    {\n      name  = "service.type"\n      value = "LoadBalancer"\n    },\n'
    '    {\n      name  = "securityContext.privileged"\n      value = "true"\n    }\n  ]\n}\n'
)


@pytest.mark.parametrize("rule", ["SEC-K8S-HELM-001", "SEC-K8S-HELM-002"])
def test_helm_v3_set_list_is_read(tmp_path, rule) -> None:
    assert _fires(tmp_path, rule, HELM_V3)


# ---- custom-rule YAML -----------------------------------------------------------------


def test_yaml_comments_are_stripped_from_list_items_but_not_quotes() -> None:
    data = load_yaml(
        "patterns:\n  - kind: grep  # note\n    regex: '(?m)^\\s*#'  # trailing\n"
        "url: http://x/#frag\n"
    )
    assert data["patterns"] == [{"kind": "grep", "regex": "(?m)^\\s*#"}]
    assert data["url"] == "http://x/#frag"


def test_custom_rule_with_a_trailing_comment_runs(tmp_path) -> None:
    rules = tmp_path / ".tf-analyze-rules"
    rules.mkdir()
    (tmp_path / ".tf-analyze.yaml").write_text("rules_dir: .tf-analyze-rules/\n")
    (rules / "CUSTOM-OWNER-001.yaml").write_text(
        "id: CUSTOM-OWNER-001\n"
        'title: "Instance needs an Owner tag"\n'
        "section: ops\ndefault_urgency: MEDIUM\nblast_radius: single-resource\nstatus: active\n"
        "patterns:\n"
        "  - kind: resource_missing_arg  # instances must carry an Owner tag\n"
        "    resource: aws_instance\n    arg: tags.Owner\n"
        "recommendation: |\n  Add it.\nverification: |\n  Check.\nfixtures: []\n"
    )
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "a" {\n  ami = "ami-1"\n}\n'
    )
    assert any(i == "CUSTOM-OWNER-001" for i, _, _ in _ids(tmp_path))


# ---- parser: multi-line conditional in parentheses ---------------------------------------


def test_multiline_conditional_does_not_push_the_file_to_the_fallback(tmp_path, monkeypatch) -> None:
    # Parse-tree behaviour: run with the parser even in the forced-fallback job.
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)
    text = (
        'resource "aws_security_group" "ssh" {\n  name = "ssh"\n  ingress = [{\n'
        '    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n  }]\n}\n'
        'locals {\n  env_size = (\n    var.prod\n    ? "large"\n    : "small"\n  )\n}\n'
        'resource "aws_s3_bucket" "after" {\n  bucket = "b"\n}\n'
    )
    tree, error = _parse_tf_cached(text)
    assert error is None
    after = next(
        r["aws_s3_bucket"]["after"] for r in tree["resource"] if "aws_s3_bucket" in r
    )
    assert (
        after["__start_line__"]
        == text[: text.index('resource "aws_s3_bucket"')].count("\n") + 1
    )
    assert _fires(tmp_path, "SEC-AWS-SG-001", text)
