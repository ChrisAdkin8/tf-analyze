"""Policy-as-code DSL (kind: policy) — unit + end-to-end tests.

Unit tests drive `_policy` through the full v1 ("hcl1") path: a resource
`body` string → regex attribute extraction → coercion → predicate, so they
exercise what real catalogue data hits, not a pre-typed model.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import _policy  # noqa: E402


def _idx(*entries: dict) -> dict:
    return {f"{e['type']}.{e['name']}": e for e in entries}


def _r(type_, name, body="", line=1):
    return {"type": type_, "name": name, "file": f"{name}.tf", "line": line, "body": body}


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
class TestParser:
    @pytest.mark.parametrize("expr", [
        'resource.type == "aws_s3_bucket"',
        'resource.tags.Env == "prod" and resource.attr.x != null',
        'exists(aws_kms_key where that.attr.rot == true)',
        'count(aws_instance) > 3',
        'not has(resource.tags.Owner) or resource.name matches "^tmp-"',
        '"0.0.0.0/0" in resource.attr.cidrs',
    ])
    def test_valid_expressions_compile(self, expr):
        assert _policy.compile_expr(expr) is not None

    @pytest.mark.parametrize("expr", [
        "resource.",            # dangling path
        "exists(",              # truncated quantifier
        "resource.a ==",        # missing right operand
        "( resource.a",         # unbalanced paren
        "and or",               # operators with no operands
        "resource.a in ]",      # malformed list
    ])
    def test_malformed_expressions_raise(self, expr):
        with pytest.raises(SyntaxError):
            _policy.compile_expr(expr)


# --------------------------------------------------------------------------- #
# Evaluation — through the regex/coercion resource view
# --------------------------------------------------------------------------- #
class TestEvaluate:
    def test_cross_resource_exists(self):
        # S3 bucket without an aws_s3_bucket_logging referencing it.
        idx = _idx(
            _r("aws_s3_bucket", "nolog", '  bucket = "x"'),
            _r("aws_s3_bucket", "haslog", '  bucket = "y"'),
            _r("aws_s3_bucket_logging", "l", "  bucket = aws_s3_bucket.haslog.id"),
        )
        pat = {"match": 'resource.type == "aws_s3_bucket"',
               "require": 'exists(aws_s3_bucket_logging where that.attr.bucket matches resource.name)',
               "description": "{resource.name} has no logging"}
        fired = [f["resource"] for f in _policy.evaluate_policy(pat, "ID", idx)]
        assert fired == ["aws_s3_bucket.nolog"]

    def test_conditional_with_tag_and_bool_coercion(self):
        idx = _idx(
            _r("aws_db_instance", "prod_bad",
               '  tags = { Environment = "prod" }\n  deletion_protection = false'),
            _r("aws_db_instance", "prod_ok",
               '  tags = { Environment = "prod" }\n  deletion_protection = true'),
            _r("aws_db_instance", "dev",
               '  tags = { Environment = "dev" }\n  deletion_protection = false'),
        )
        pat = {"match": 'resource.type == "aws_db_instance" and resource.tags.Environment == "prod"',
               "require": "resource.attr.deletion_protection == true",
               "description": "prod db unprotected"}
        fired = [f["resource"] for f in _policy.evaluate_policy(pat, "ID", idx)]
        assert fired == ["aws_db_instance.prod_bad"]

    def test_aggregate_nested_block_with_numeric_and_list_coercion(self):
        idx = _idx(
            _r("aws_security_group", "open",
               '  ingress {\n    from_port = 22\n    to_port = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }'),
            _r("aws_security_group", "closed",
               '  ingress {\n    from_port = 443\n    to_port = 443\n    cidr_blocks = ["10.0.0.0/8"]\n  }'),
        )
        pat = {"match": 'resource.type == "aws_security_group"',
               "forbid": '"0.0.0.0/0" in resource.attr.ingress.cidr_blocks '
                         'and resource.attr.ingress.from_port <= 22 and resource.attr.ingress.to_port >= 22',
               "description": "ssh open"}
        fired = [f["resource"] for f in _policy.evaluate_policy(pat, "ID", idx)]
        assert fired == ["aws_security_group.open"]

    def test_org_guardrail_has_and_match(self):
        idx = _idx(
            _r("aws_instance", "tagged", '  tags = { CostCenter = "eng" }'),
            _r("aws_instance", "untagged", '  ami = "ami-1"'),
            _r("google_compute_instance", "gcp", '  name = "g"'),  # ^aws_ match → skipped
        )
        pat = {"match": 'resource.type matches "^aws_"',
               "require": "has(resource.tags.CostCenter)",
               "description": "missing CostCenter"}
        fired = [f["resource"] for f in _policy.evaluate_policy(pat, "ID", idx)]
        assert fired == ["aws_instance.untagged"]

    def test_description_interpolation_and_finding_shape(self):
        idx = _idx(_r("aws_s3_bucket", "b", '  bucket = "x"', line=7))
        pat = {"match": 'resource.type == "aws_s3_bucket"', "forbid": "true",
               "description": "bucket {resource.name} at {resource.address}"}
        f = _policy.evaluate_policy(pat, "ORG-1", idx)[0]
        assert f == {"id": "ORG-1", "file": "b.tf", "line": 7,
                     "resource": "aws_s3_bucket.b",
                     "context": "bucket b at aws_s3_bucket.b"}

    def test_malformed_pattern_is_inert(self):
        idx = _idx(_r("aws_s3_bucket", "b", '  bucket = "x"'))
        # both require and forbid → invalid shape → no findings, no crash
        assert _policy.evaluate_policy(
            {"match": 'resource.type == "aws_s3_bucket"', "require": "true", "forbid": "true"},
            "ID", idx) == []
        # syntactically broken expression → inert (load-time validation reports it)
        assert _policy.evaluate_policy(
            {"match": "resource.", "require": "true"}, "ID", idx) == []


# --------------------------------------------------------------------------- #
# End-to-end through detect.py via a temporary --catalog
# --------------------------------------------------------------------------- #
_RULE = textwrap.dedent("""\
    id: ORG-S3-LOGGING-POLICY-001
    title: "S3 bucket without access logging (policy DSL)"
    section: security
    default_urgency: MEDIUM
    blast_radius: single-resource
    status: active
    recommendation: |
      Add an aws_s3_bucket_logging resource targeting the bucket.
    verification: |
      terraform state list | grep aws_s3_bucket_logging
    patterns:
      - kind: policy
        match: 'resource.type == "aws_s3_bucket"'
        require: 'exists(aws_s3_bucket_logging where that.attr.bucket matches resource.name)'
        description: "S3 bucket {resource.name} has no aws_s3_bucket_logging"
""")


def _scan(target: Path, catalog: Path) -> set[str]:
    res = subprocess.run(
        [sys.executable, str(DETECT_PY), "--target", str(target),
         "--catalog", str(catalog), "--format", "json", "--no-hcl2"],
        capture_output=True, text=True, timeout=60,
    )
    try:
        return {f["id"] for f in json.loads(res.stdout).get("findings", [])}
    except json.JSONDecodeError:
        return set()


def test_policy_rule_fires_end_to_end(tmp_path: Path) -> None:
    cat = tmp_path / "catalog"; cat.mkdir()
    (cat / "ORG-S3-LOGGING-POLICY-001.yaml").write_text(_RULE)
    target = tmp_path / "tf"; target.mkdir()

    # dirty — bucket with no logging resource → fires
    (target / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n')
    assert "ORG-S3-LOGGING-POLICY-001" in _scan(target, cat)

    # clean — add the logging resource → does not fire
    (target / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
        'resource "aws_s3_bucket_logging" "l" {\n  bucket = aws_s3_bucket.b.id\n}\n'
    )
    assert "ORG-S3-LOGGING-POLICY-001" not in _scan(target, cat)
