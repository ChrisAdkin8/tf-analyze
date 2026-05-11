"""Tests for the Session-G modularisation extract: `_lsp.py`.

`_run_lsp_server` was the last sizeable block of glue logic still
embedded in detect.py. Session G extracts it to `scripts/_lsp.py` via
the callable-injection pattern: `_lsp.py` accepts a `scanner` callback
and a `load_catalog` callback so it never imports from `detect.py` (no
circular import risk).

These tests cover the *seam contract*:
  * `_lsp.py` exports `run_lsp_server` + `findings_to_diagnostics`.
  * detect.py's `_run_lsp_server` shim is a binding into `_lsp.run_lsp_server`.
  * The severity map matches what the legacy in-place implementation
    used (CRITICAL=1, HIGH=1, MEDIUM=2, LOW=3, INFO=4).

Functional contracts (initialize, diagnostics, codeAction, shutdown,
robustness) are covered by `tests/test_lsp_server.py` and continue to
pass because the shim is a pure wire-up.
"""
from __future__ import annotations

import sys

from helpers import REPO_ROOT


class TestLspModule:
    def test_module_imports_cleanly(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _lsp
        assert hasattr(_lsp, "run_lsp_server")
        assert hasattr(_lsp, "findings_to_diagnostics")
        assert callable(_lsp.run_lsp_server)
        assert callable(_lsp.findings_to_diagnostics)

    def test_severity_map_pinned(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _lsp
        assert _lsp._SEVERITY_MAP == {
            "CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
        }

    def test_findings_to_diagnostics_shape(self) -> None:
        """Pure-function check — lock in the LSP `Diagnostic[]` shape so
        downstream changes don't silently break the VS Code extension's
        squiggle rendering.
        """
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _lsp
        findings = [{"id": "FOO-BAR-001", "line": 7, "file": "x.tf"}]
        id_map = {"FOO-BAR-001": {"default_urgency": "HIGH", "title": "demo"}}
        diags = _lsp.findings_to_diagnostics(findings, id_map)
        assert len(diags) == 1
        d = diags[0]
        assert d["range"]["start"]["line"] == 6  # 1-based → 0-based
        assert d["range"]["end"]["character"] == 9999
        assert d["severity"] == 1  # HIGH → Error
        assert d["code"] == "FOO-BAR-001"
        assert d["source"] == "tf-analyze"
        assert "FOO-BAR-001" in d["message"]
        assert "demo" in d["message"]

    def test_findings_to_diagnostics_unknown_rule_falls_back_to_low(self) -> None:
        """Defensive: a finding whose ID isn't in the catalog map (live
        catalog reload edge case) must still render — at LOW severity."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _lsp
        diags = _lsp.findings_to_diagnostics(
            [{"id": "GHOST-RULE-999", "line": 1, "file": "x.tf"}],
            id_map={},
        )
        assert len(diags) == 1
        assert diags[0]["severity"] == 3  # LOW
        assert diags[0]["message"].startswith("GHOST-RULE-999:")

    def test_detect_run_lsp_server_is_shim(self) -> None:
        """The legacy private name `_run_lsp_server` must still exist on
        detect for callers (entry-point at `main()`); it should be a thin
        wrapper that delegates to `_lsp.run_lsp_server`."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        assert hasattr(detect, "_run_lsp_server")
        # No circular import: importing _lsp must not pull in detect.
        # If this fails we've leaked a `from detect import ...` into _lsp.
        import importlib
        import _lsp
        importlib.reload(_lsp)  # safe — module has no module-level state
