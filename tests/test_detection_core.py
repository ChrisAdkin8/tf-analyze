"""Unit tests for core detection primitives in detect.py."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import detect  # noqa: E402


# ---------------------------------------------------------------------------
# block_arg_value
# ---------------------------------------------------------------------------

class TestBlockArgValue:
    def test_bav_simple_string(self):
        body = '  name = "hello"\n'
        assert detect.block_arg_value(body, "name") == "hello"

    def test_bav_boolean_false(self):
        body = "  encrypted = false\n"
        assert detect.block_arg_value(body, "encrypted") == "false"

    def test_bav_boolean_true(self):
        body = "  enabled = true\n"
        assert detect.block_arg_value(body, "enabled") == "true"

    def test_bav_absent_returns_none(self):
        body = "  name = \"other\"\n"
        assert detect.block_arg_value(body, "encrypted") is None

    def test_bav_strips_inline_comment(self):
        body = '  value = "x"  # comment\n'
        assert detect.block_arg_value(body, "value") == "x"

    def test_bav_numeric(self):
        body = "  port = 3306\n"
        assert detect.block_arg_value(body, "port") == "3306"

    def test_bav_list_first_token(self):
        # Multi-line list: returns only the first line token
        body = '  types = [\n    "a",\n    "b",\n  ]\n'
        val = detect.block_arg_value(body, "types")
        assert val is not None
        assert "[" in val or val == "["

    def test_bav_single_line_list(self):
        body = '  types = ["a", "b"]\n'
        val = detect.block_arg_value(body, "types")
        assert val == '["a", "b"]'


# ---------------------------------------------------------------------------
# _resolve_var_ref
# ---------------------------------------------------------------------------

class TestResolveVarRef:
    def test_rvr_resolves_known_var(self):
        assert detect._resolve_var_ref("var.rotation", {"rotation": "false"}) == "false"

    def test_rvr_unknown_var_unchanged(self):
        assert detect._resolve_var_ref("var.unknown", {}) == "var.unknown"

    def test_rvr_literal_unchanged(self):
        assert detect._resolve_var_ref("false", {}) == "false"

    def test_rvr_compound_expression_unchanged(self):
        val = "var.x == true"
        assert detect._resolve_var_ref(val, {"x": "true"}) == val

    def test_rvr_local_ref(self):
        assert detect._resolve_var_ref("local.enc", {"__local__enc": "true"}) == "true"

    def test_rvr_ternary_true_branch(self):
        # `var.x ? "a" : "b"` with var.x = true → "a"
        assert detect._resolve_var_ref('var.x ? "a" : "b"', {"x": "true"}) == "a"

    def test_rvr_ternary_false_branch(self):
        assert detect._resolve_var_ref('var.x ? "a" : "b"', {"x": "false"}) == "b"

    def test_rvr_ternary_unknown_cond_unchanged(self):
        val = 'var.unknown ? "a" : "b"'
        assert detect._resolve_var_ref(val, {}) == val

    def test_rvr_ternary_bool_branches(self):
        assert detect._resolve_var_ref("var.x ? true : false", {"x": "true"}) == "true"
        assert detect._resolve_var_ref("var.x ? true : false", {"x": "false"}) == "false"


# ---------------------------------------------------------------------------
# _extract_var_defaults_by_dir
# ---------------------------------------------------------------------------

class TestExtractVarDefaults:
    def test_evd_basic(self):
        tf = 'variable "rotation" {\n  type    = bool\n  default = false\n}\n'
        result = detect._extract_var_defaults_by_dir({"/app/main.tf": tf})
        assert result.get("/app", {}).get("rotation") == "false"

    def test_evd_string_default(self):
        tf = 'variable "env" {\n  type    = string\n  default = "prod"\n}\n'
        result = detect._extract_var_defaults_by_dir({"/app/main.tf": tf})
        assert result.get("/app", {}).get("env") == "prod"

    def test_evd_no_default(self):
        tf = 'variable "required" {\n  type = string\n}\n'
        result = detect._extract_var_defaults_by_dir({"/app/main.tf": tf})
        assert result.get("/app", {}).get("required") is None

    def test_evd_multiple_files_same_dir(self):
        files = {
            "/app/vars.tf": 'variable "a" {\n  default = "1"\n}\n',
            "/app/main.tf": 'variable "b" {\n  default = "2"\n}\n',
        }
        result = detect._extract_var_defaults_by_dir(files)
        assert result["/app"]["a"] == "1"
        assert result["/app"]["b"] == "2"

    def test_evd_module_input_flow_through(self, tmp_path):
        # Parent at tmp_path/parent, child at tmp_path/child.
        parent = tmp_path / "parent"
        child = tmp_path / "child"
        parent.mkdir()
        child.mkdir()
        (child / "variables.tf").write_text(
            'variable "encrypted" {\n  default = false\n}\n'
        )
        (parent / "main.tf").write_text(
            'module "c" {\n  source    = "../child"\n  encrypted = true\n}\n'
        )
        files = {
            str(parent / "main.tf"): (parent / "main.tf").read_text(),
            str(child / "variables.tf"): (child / "variables.tf").read_text(),
        }
        result = detect._extract_var_defaults_by_dir(files)
        assert result[str(child.resolve())]["encrypted"] == "true"


# ---------------------------------------------------------------------------
# find_blocks
# ---------------------------------------------------------------------------

class TestFindBlocks:
    def test_fb_finds_resource(self):
        tf = 'resource "aws_s3_bucket" "example" {\n  bucket = "test"\n}\n'
        pat = re.compile(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*\{')
        blocks = detect.find_blocks(tf, pat)
        assert len(blocks) == 1
        assert "bucket" in blocks[0]["body"]

    def test_fb_no_match(self):
        tf = 'resource "aws_instance" "web" {\n  ami = "ami-abc"\n}\n'
        pat = re.compile(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*\{')
        blocks = detect.find_blocks(tf, pat)
        assert blocks == []

    def test_fb_nested_braces(self):
        tf = (
            'resource "aws_eks_cluster" "main" {\n'
            '  name = "cluster"\n'
            '  vpc_config {\n'
            '    subnet_ids = ["a"]\n'
            '  }\n'
            '}\n'
        )
        pat = re.compile(r'resource\s+"aws_eks_cluster"\s+"([^"]+)"\s*\{')
        blocks = detect.find_blocks(tf, pat)
        assert len(blocks) == 1
        assert "vpc_config" in blocks[0]["body"]


# ---------------------------------------------------------------------------
# _expand_dynamic_blocks
# ---------------------------------------------------------------------------

class TestExpandDynamicBlocks:
    def test_edb_expands_single(self):
        body = (
            'dynamic "ingress" {\n'
            '  for_each = var.ports\n'
            '  content {\n'
            '    from_port = ingress.value\n'
            '  }\n'
            '}\n'
        )
        expanded = detect._expand_dynamic_blocks(body)
        assert "ingress" in expanded
        assert "dynamic" not in expanded
        assert "from_port" in expanded

    def test_edb_no_dynamic_unchanged(self):
        body = '  name = "test"\n  value = true\n'
        assert detect._expand_dynamic_blocks(body) == body

    def test_edb_nested_content_preserved(self):
        body = (
            'dynamic "tag" {\n'
            '  for_each = var.tags\n'
            '  content {\n'
            '    key   = tag.key\n'
            '    value = tag.value\n'
            '  }\n'
            '}\n'
        )
        expanded = detect._expand_dynamic_blocks(body)
        assert "key" in expanded
        assert "value" in expanded
