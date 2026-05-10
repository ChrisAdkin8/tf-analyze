"""Tests for the Session-F modularisation extract: `_cross_resource.py`.

The functional contracts for the `_graph_*` cross-resource detectors
are already covered by `tests/test_attack_graph.py` and a handful of
positive/clean fixtures in the self-test corpus. These tests cover
the *seam contract* — that `_cross_resource.py` exposes the names
callers expect, that `detect.py` re-exports each name as a binding,
and that `_GRAPH_CHECKS` dispatches via the shim.
"""
from __future__ import annotations

import sys

from helpers import REPO_ROOT


class TestCrossResourceModule:
    def test_module_imports_cleanly(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _cross_resource
        assert hasattr(_cross_resource, "_build_resource_index")
        for n in (
            "_graph_logging_target_public",
            "_graph_gke_nodepool_secure_boot",
            "_graph_kms_location_parity",
            "_graph_iam_member_breadth",
            "_graph_azure_uami_orphan",
            "_graph_dynamodb_pitr",
            "_graph_dynamodb_sse",
            "_GRAPH_CHECKS",
        ):
            assert hasattr(_cross_resource, n), n
        # The registry must wire each name to its function.
        assert _cross_resource._GRAPH_CHECKS["logging_target_public"] is _cross_resource._graph_logging_target_public

    def test_detect_re_exports_bindings_not_copies(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        import _cross_resource
        for n in (
            "_build_resource_index",
            "_graph_logging_target_public",
            "_graph_gke_nodepool_secure_boot",
            "_graph_kms_location_parity",
            "_graph_iam_member_breadth",
            "_graph_azure_uami_orphan",
            "_graph_dynamodb_pitr",
            "_graph_dynamodb_sse",
            "_GRAPH_CHECKS",
        ):
            assert getattr(detect, n) is getattr(_cross_resource, n), n

    def test_build_resource_index_round_trip(self) -> None:
        """`_build_resource_index` is the gateway: every graph check
        starts from the dict it returns. Lock the shape (`<type>.<name>` →
        `{file, line, body, type, name}`)."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        files = {
            "main.tf": (
                'resource "aws_dynamodb_table" "t" {\n'
                '  name         = "x"\n'
                '  billing_mode = "PAY_PER_REQUEST"\n'
                '}\n'
            ),
        }
        idx = detect._build_resource_index(files)
        assert "aws_dynamodb_table.t" in idx
        entry = idx["aws_dynamodb_table.t"]
        assert entry["type"] == "aws_dynamodb_table"
        assert entry["name"] == "t"
        assert entry["file"] == "main.tf"
        assert entry["line"] == 1
        assert "name" in entry["body"]

    def test_dynamodb_pitr_finds_missing(self) -> None:
        """One representative graph check end-to-end: a DynamoDB
        table without `point_in_time_recovery { enabled = true }`
        should produce a finding."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        files = {
            "main.tf": (
                'resource "aws_dynamodb_table" "t" {\n'
                '  name = "x"\n'
                '  hash_key = "id"\n'
                '}\n'
            ),
        }
        idx = detect._build_resource_index(files)
        findings = detect._graph_dynamodb_pitr(idx, files)
        assert len(findings) == 1
        assert findings[0]["resource"] == "aws_dynamodb_table.t"

    def test_block_arg_value_moved_to_hcl(self) -> None:
        """Session F also moved `block_arg_value` + the `_USE_HCL2`
        toggle from detect.py into `_hcl.py` so `_cross_resource.py`
        could import cleanly. Lock the new binding chain:
        `detect.block_arg_value` is `_hcl.block_arg_value`."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        import _hcl
        assert detect.block_arg_value is _hcl.block_arg_value
        assert detect._enable_hcl2_default is _hcl._enable_hcl2_default
        # _HAS_HCL2 is a bool — `is` is appropriate for True/False
        assert detect._HAS_HCL2 is _hcl._HAS_HCL2
