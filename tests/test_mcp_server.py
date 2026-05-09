"""Tests for the MCP server at ``integrations/mcp-server/``.

The MCP server is a thin RPC adapter over the engine — its job is
input validation + subprocess plumbing + Mermaid rendering for the
attack graph. These tests exercise the validation gates and the
underlying tool implementations directly (rather than spinning up a
full MCP transport, which adds protocol noise without catching bugs in
*our* code).

Auto-skip if the ``mcp`` SDK isn't installed, matching the badge-service
test pattern.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
MCP_DIR = REPO_ROOT / "integrations" / "mcp-server"

# The MCP SDK isn't a hard dep of the engine. Skip if absent.
pytest.importorskip("mcp")

# Load the MCP server module under a unique name. The badge-service
# tests also expose a module called `server`; relying on `sys.path`
# ordering causes the second import to alias the first when both
# tests are collected in the same session. importlib.util gives us
# an explicit, isolated load.
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "tfanalyze_mcp_server", str(MCP_DIR / "server.py"),
)
assert _spec is not None and _spec.loader is not None
server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(server)


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


class TestResolveTarget:
    def test_existing_directory_is_resolved(self, tmp_path: Path) -> None:
        result = server._resolve_target(str(tmp_path))
        assert result == tmp_path.resolve()

    def test_nonexistent_path_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            server._resolve_target(str(tmp_path / "does-not-exist"))

    def test_file_path_is_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "main.tf"
        f.write_text("")
        with pytest.raises(ValueError, match="not a directory"):
            server._resolve_target(str(f))

    def test_null_byte_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="null byte"):
            server._resolve_target("/tmp/foo\0bar")

    def test_empty_string_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            server._resolve_target("")

    def test_non_string_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            server._resolve_target(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Tool wiring — call the underlying functions directly (not through the
# MCP transport). Validates that the tool decorators don't break the
# call signatures and that the engine returns the expected shape.
# ---------------------------------------------------------------------------


def _underlying(tool):
    """Unwrap a FastMCP tool decorator to call the implementation
    function directly. Different SDK versions store the wrapped
    function under different attribute names; `fn` is the public
    accessor in current FastMCP, with `__wrapped__` as the fallback.
    """
    return getattr(tool, "fn", None) or getattr(tool, "__wrapped__", None) or tool


class TestScanWorkspaceTool:
    def test_clean_workspace_returns_summary(self, tmp_path: Path) -> None:
        (tmp_path / "main.tf").write_text(
            'output "ok" {\n'
            '  value       = "ok"\n'
            '  description = "smoke output"\n'
            '}\n'
        )
        result = _underlying(server.scan_workspace)(str(tmp_path))
        assert "summary" in result
        s = result["summary"]
        # Expected structural keys regardless of finding count.
        for key in ("score", "grade", "counts", "scoring_version"):
            assert key in s, f"summary missing {key!r}: {s}"

    def test_invalid_mode_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="mode must be"):
            _underlying(server.scan_workspace)(str(tmp_path), mode="banana")

    def test_findings_present_when_offending_resource_scanned(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        result = _underlying(server.scan_workspace)(str(tmp_path))
        findings = result.get("findings", [])
        assert any(
            f["id"].startswith("SEC-") for f in findings
        ), f"expected ≥1 SEC finding, got {[f['id'] for f in findings]}"


class TestExplainRuleTool:
    def test_real_rule_returns_text(self) -> None:
        out = _underlying(server.explain_rule)("SEC-AWS-IAM-001")
        assert "SEC-AWS-IAM-001" in out

    def test_invalid_rule_id_shape_is_rejected(self) -> None:
        # Lowercase, traversal, shell-injection — all must be rejected
        # at the tool boundary so the engine never sees them.
        for bad in ("sec-aws-001", "../etc/passwd", "SEC; rm -rf /",
                    "", "AB", "A"):
            with pytest.raises(ValueError, match="invalid rule ID"):
                _underlying(server.explain_rule)(bad)


class TestAttackGraphTool:
    def test_returns_summary_graph_and_mermaid(self, tmp_path: Path) -> None:
        # Build a fixture with at least one internet entry + one crown
        # jewel so the graph has structure.
        (tmp_path / "main.tf").write_text(
            'resource "aws_lb" "public" {\n'
            '  load_balancer_type = "application"\n'
            '  scheme             = "internet-facing"\n'
            '}\n'
            'resource "aws_s3_bucket" "appdata" {\n'
            '  bucket = "myapp-data"\n'
            '}\n'
        )
        result = _underlying(server.attack_graph)(str(tmp_path))
        for key in ("summary", "graph", "mermaid"):
            assert key in result, f"missing {key!r}: {result.keys()}"
        # Mermaid is best-effort: either a flowchart string or a
        # commented stub on rendering failure. Never empty.
        assert result["mermaid"], "mermaid output must not be empty"


class TestApplyFixesTool:
    def test_dry_run_returns_engine_output_without_writing(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        original = (tmp_path / "main.tf").read_text()
        out = _underlying(server.apply_fixes)(str(tmp_path), dry_run=True)
        # Dry-run output is the engine's diff/summary text — non-empty
        # and the underlying file must NOT have been modified.
        assert out, "dry-run output should be non-empty"
        assert (tmp_path / "main.tf").read_text() == original, (
            "dry-run must not mutate source files"
        )


# ---------------------------------------------------------------------------
# Server boot — `--health` returns 0 with a valid engine.
# ---------------------------------------------------------------------------


class TestHealthCheck:
    def test_health_subcommand_succeeds(self) -> None:
        import subprocess
        res = subprocess.run(
            [sys.executable, str(MCP_DIR / "server.py"), "--health"],
            capture_output=True, text=True, timeout=15,
        )
        assert res.returncode == 0, res.stderr
        assert "OK" in res.stderr  # `--health` prints to stderr
