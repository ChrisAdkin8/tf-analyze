"""Tests for the Session-B modularisation extract: `_hcl.py`.

The functional contracts for the HCL primitives are already covered
by `tests/test_hcl_primitives.py`, which reaches them via the
`detect` module's re-export shim. These tests cover the *seam
contract* — that `_hcl.py` exposes the names callers expect, and
that `detect.py` re-exports each name as a binding (not a copy) so
future renames stay in sync.

Same shape as the prior seam tests for `_mitre.py` (in
`tests/test_sarif_taxonomies_and_refactor.py::TestMitreModule`) and
`_versions.py`/`_scoring.py` (in `tests/test_session_a_extracts.py`).
"""
from __future__ import annotations

import sys

from helpers import REPO_ROOT


class TestHclModule:
    def test_module_imports_cleanly(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _hcl
        # Public surface every external caller depends on.
        assert hasattr(_hcl, "_LINE_COMMENT_RE")
        assert hasattr(_hcl, "_BLOCK_COMMENT_RE")
        assert hasattr(_hcl, "_DYNAMIC_BLOCK_START_RE")
        assert hasattr(_hcl, "_read_normalized")
        assert hasattr(_hcl, "_parse_scalar")
        assert hasattr(_hcl, "strip_hcl_context")
        assert hasattr(_hcl, "find_blocks")
        assert hasattr(_hcl, "find_simple_blocks")
        assert hasattr(_hcl, "block_has_arg")
        assert hasattr(_hcl, "_hcl_object_to_json")
        assert hasattr(_hcl, "block_has_nested_path")
        assert hasattr(_hcl, "_expand_dynamic_blocks")

    def test_detect_re_exports_bindings_not_copies(self) -> None:
        """Every legacy `detect.<name>` symbol must be the same object
        as the one in `_hcl.py`. tests/test_hcl_primitives.py and
        downstream callers reach these through the `detect` namespace —
        if the shim ever decays into a copy, this catches it."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        import _hcl
        # Regex constants — `is` because the compiled-regex object identity
        # matters (a separate compile would be a different object even if
        # the pattern string matched).
        assert detect._LINE_COMMENT_RE is _hcl._LINE_COMMENT_RE
        assert detect._BLOCK_COMMENT_RE is _hcl._BLOCK_COMMENT_RE
        assert detect._DYNAMIC_BLOCK_START_RE is _hcl._DYNAMIC_BLOCK_START_RE
        # Functions
        assert detect._read_normalized is _hcl._read_normalized
        assert detect._parse_scalar is _hcl._parse_scalar
        assert detect.strip_hcl_context is _hcl.strip_hcl_context
        assert detect.find_blocks is _hcl.find_blocks
        assert detect.find_simple_blocks is _hcl.find_simple_blocks
        assert detect.block_has_arg is _hcl.block_has_arg
        assert detect._hcl_object_to_json is _hcl._hcl_object_to_json
        assert detect.block_has_nested_path is _hcl.block_has_nested_path
        assert detect._expand_dynamic_blocks is _hcl._expand_dynamic_blocks

    def test_round_trip_through_shim(self) -> None:
        """End-to-end smoke: `detect.find_blocks` + `detect.RESOURCE_START`
        (the regex stayed in detect.py because it's used pervasively)
        must work together, proving the seam wires up cleanly. Without
        this, a regression in either module-level import order or in the
        regex export would only surface when a real workspace was
        scanned."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        hcl = (
            'resource "aws_s3_bucket" "x" {\n'
            '  bucket = "the-bucket"\n'
            '  versioning { enabled = true }\n'
            '}\n'
        )
        blocks = detect.find_blocks(hcl, detect.RESOURCE_START)
        assert len(blocks) == 1
        assert blocks[0]["groups"] == ("aws_s3_bucket", "x")
        body = blocks[0]["body"]
        assert detect.block_has_arg(body, "bucket")
        # nested-path lookup must traverse the inner block
        assert detect.block_has_nested_path(body, "versioning.enabled")

    def test_strip_hcl_context_preserves_total_length(self) -> None:
        """`strip_hcl_context` returns equal-length whitespace so that
        substring offsets (and line numbers up to the next block comment)
        stay aligned. Lock the length invariant at the seam — every
        grep-kind detector depends on it.

        Note: block comments collapse newlines into spaces, so
        line-number drift across `/* ... */` is a known limitation.
        Single-line comments DO preserve their trailing newline."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from _hcl import strip_hcl_context
        text = (
            'resource "aws_s3" "x" { # ignore_changes = all\n'
            '  bucket = "name"\n'
            '}\n'
        )
        out = strip_hcl_context(text)
        # Total length preserved → byte offsets stay valid.
        assert len(out) == len(text)
        # Single-line `#` comments don't eat the newline.
        assert out.count("\n") == text.count("\n")
        # The pragma-looking comment is gone, the surrounding code remains.
        assert "ignore_changes" not in out
        assert "bucket" in out

    def test_expand_dynamic_blocks_round_trip(self) -> None:
        """`dynamic "X" { content { ... } }` → `X { ... }` is the only
        reason `resource_arg` patterns can match attributes inside
        dynamic blocks. Lock the rewrite shape so future refactors
        don't silently regress to the no-op."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from _hcl import _expand_dynamic_blocks
        body = (
            'name = "sg"\n'
            'dynamic "ingress" {\n'
            '  for_each = var.rules\n'
            '  content {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            '  }\n'
            '}\n'
        )
        out = _expand_dynamic_blocks(body)
        assert "ingress {" in out
        assert "cidr_blocks" in out
        # The literal `dynamic "ingress"` header must be gone.
        assert 'dynamic "ingress"' not in out
