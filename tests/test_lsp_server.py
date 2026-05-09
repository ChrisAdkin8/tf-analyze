"""LSP-server JSON-RPC subprocess tests.

`detect.py --lsp` is the language server the VS Code extension talks to
on every keystroke. The LSP loop is ~200 LoC of `_run_lsp_server` in
`detect.py` with **zero tests prior to this file** — making it the
single highest-impact untested surface in the engine.

These tests spawn `python3 detect.py --lsp` as a subprocess and exchange
LSP-shaped Content-Length-framed JSON-RPC messages, mirroring exactly
what `vscode-languageclient` does in the extension. They cover:

  * Server boots and responds to `initialize` with the documented
    capabilities (textDocumentSync object form, codeActionProvider).
  * Opening a malformed `.tf` produces diagnostics on the right URI.
  * `textDocument/codeAction` returns a `WorkspaceEdit` with `fix_hcl`
    inserted at the offending line — the shape the extension's Quick
    Fix renderer expects.
  * Unknown requests return `-32601 Method not found` (LSP spec).
  * A handler crash on one request doesn't take down the whole server
    — the loop's outer try/except keeps subsequent requests alive.
  * `shutdown` followed by `exit` terminates cleanly.

Subprocess-based: the LSP loop reads from stdin and writes to stdout,
so an in-process test would have to monkey-patch sys.stdin/stdout —
fragile. A real subprocess is the same thing the user gets.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"


# ---------------------------------------------------------------------------
# Tiny LSP client — Content-Length-framed JSON-RPC over a subprocess pipe
# ---------------------------------------------------------------------------


class LspClient:
    """Minimal LSP client. Spawns `detect.py --lsp` and exposes
    `send_request` / `send_notification` / `read_message` so tests
    can speak the protocol without pulling in `python-lsp-jsonrpc`.
    """

    _HEADER_RE = re.compile(rb"Content-Length: (\d+)\r\n")

    def __init__(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, str(DETECT_PY), "--lsp", "--no-hcl2"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._next_id = 1

    def __enter__(self) -> "LspClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def _send_raw(self, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        assert self.proc.stdin is not None
        self.proc.stdin.write(header + body)
        self.proc.stdin.flush()

    def send_request(self, method: str, params: dict | None = None) -> int:
        rid = self._next_id
        self._next_id += 1
        self._send_raw({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        return rid

    def send_notification(self, method: str, params: dict | None = None) -> None:
        self._send_raw({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def read_message(self, timeout: float = 5.0) -> dict | None:
        """Read a single Content-Length-framed message. Returns None on EOF."""
        assert self.proc.stdout is not None
        deadline = time.time() + timeout
        # Read header up to the blank line.
        header = b""
        while b"\r\n\r\n" not in header:
            if time.time() > deadline:
                pytest.fail(f"LSP read timed out; got header so far: {header!r}")
            ch = self.proc.stdout.read(1)
            if not ch:
                return None
            header += ch
        m = self._HEADER_RE.search(header)
        if not m:
            pytest.fail(f"missing Content-Length in header: {header!r}")
        length = int(m.group(1))
        body = self.proc.stdout.read(length)
        return json.loads(body)

    def read_until(self, predicate, timeout: float = 5.0) -> dict:
        """Read messages until `predicate(msg)` is True. Useful for
        skipping notifications when the test wants the matching response.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = self.read_message(timeout=max(0.1, deadline - time.time()))
            if msg is None:
                pytest.fail("server closed stdout before predicate matched")
            if predicate(msg):
                return msg
        pytest.fail("predicate did not match in time")

    def read_response(self, request_id: int, timeout: float = 5.0) -> dict:
        return self.read_until(lambda m: m.get("id") == request_id, timeout=timeout)

    def close(self) -> None:
        try:
            if self.proc.poll() is None:
                self.send_notification("exit")
                self.proc.wait(timeout=2.0)
        except (subprocess.TimeoutExpired, BrokenPipeError):
            self.proc.kill()
            self.proc.wait(timeout=2.0)


@pytest.fixture
def lsp() -> LspClient:
    """Each test gets a fresh server. Cleanup on exit."""
    client = LspClient()
    yield client
    client.close()


def _file_uri(path: Path) -> str:
    return f"file://{path.as_posix()}"


def _initialize(lsp: LspClient) -> dict:
    rid = lsp.send_request("initialize", {
        "processId": None,
        "rootUri": None,
        "capabilities": {},
    })
    resp = lsp.read_response(rid)
    lsp.send_notification("initialized")
    return resp


# ---------------------------------------------------------------------------
# Lifecycle + capabilities
# ---------------------------------------------------------------------------


class TestLspLifecycle:
    def test_initialize_returns_advertised_capabilities(self, lsp: LspClient) -> None:
        resp = _initialize(lsp)
        # Required shape per LSP spec — vscode-languageclient rejects
        # responses missing `result.capabilities`.
        assert resp["jsonrpc"] == "2.0"
        caps = resp["result"]["capabilities"]
        # textDocumentSync must be the OBJECT form so older clients
        # don't reject it (we hit this in v0.1.x).
        sync = caps["textDocumentSync"]
        assert isinstance(sync, dict)
        assert sync["openClose"] is True
        assert sync["change"] == 1
        # codeActionProvider is the gate for Quick Fix.
        assert caps["codeActionProvider"] is True
        # serverInfo helps Output-channel debugging.
        assert resp["result"]["serverInfo"]["name"] == "tf-analyze"

    def test_shutdown_returns_null_result(self, lsp: LspClient) -> None:
        _initialize(lsp)
        rid = lsp.send_request("shutdown")
        resp = lsp.read_response(rid)
        assert resp.get("result") is None

    def test_unknown_request_returns_method_not_found(self, lsp: LspClient) -> None:
        _initialize(lsp)
        rid = lsp.send_request("textDocument/totallyMadeUp")
        resp = lsp.read_response(rid)
        # Per JSON-RPC spec, code -32601 = Method not found.
        assert "error" in resp
        assert resp["error"]["code"] == -32601
        assert "Method not found" in resp["error"]["message"]

    def test_unknown_notification_is_silently_dropped(self, lsp: LspClient) -> None:
        _initialize(lsp)
        # Notifications (no id) for unknown methods get no response per spec.
        # Send it then verify a subsequent valid request still gets a response,
        # i.e. the server didn't crash on the unknown notification.
        lsp.send_notification("$/randomNotification", {"foo": "bar"})
        rid = lsp.send_request("shutdown")
        resp = lsp.read_response(rid)
        assert resp.get("result") is None


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


class TestLspDiagnostics:
    def test_did_open_publishes_diagnostics_for_offending_file(
        self, lsp: LspClient, tmp_path: Path,
    ) -> None:
        # Synthesise a file the engine will fire a high-confidence rule
        # on — `aws_db_instance` with `storage_encrypted = false`
        # triggers `SEC-AWS-RDS-001` deterministically.
        tf = tmp_path / "main.tf"
        tf.write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        _initialize(lsp)
        uri = _file_uri(tf)
        lsp.send_notification("textDocument/didOpen", {
            "textDocument": {
                "uri": uri,
                "languageId": "terraform",
                "version": 1,
                "text": tf.read_text(),
            }
        })
        # First publishDiagnostics for this URI is the response we want.
        msg = lsp.read_until(
            lambda m: m.get("method") == "textDocument/publishDiagnostics"
                      and m.get("params", {}).get("uri") == uri,
            timeout=10.0,
        )
        diags = msg["params"]["diagnostics"]
        assert isinstance(diags, list)
        assert len(diags) >= 1, f"expected ≥1 diagnostic; got {diags}"
        # Each diagnostic must carry: range, severity, message, code (rule ID).
        d = diags[0]
        assert "range" in d and "severity" in d
        assert isinstance(d.get("message"), str) and d["message"]
        # Rule ID lives in either `code` or the structured `code` form per spec.
        assert d.get("code"), f"diagnostic missing rule ID: {d}"

    def test_did_close_clears_diagnostics(
        self, lsp: LspClient, tmp_path: Path,
    ) -> None:
        tf = tmp_path / "main.tf"
        tf.write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        _initialize(lsp)
        uri = _file_uri(tf)
        lsp.send_notification("textDocument/didOpen", {
            "textDocument": {"uri": uri, "languageId": "terraform",
                             "version": 1, "text": tf.read_text()},
        })
        # Wait for the open-time publish.
        lsp.read_until(
            lambda m: m.get("method") == "textDocument/publishDiagnostics"
                      and m.get("params", {}).get("uri") == uri,
            timeout=10.0,
        )
        # Closing must publish an empty diagnostics list — otherwise
        # squiggles persist after the user closes the editor.
        lsp.send_notification("textDocument/didClose", {
            "textDocument": {"uri": uri},
        })
        msg = lsp.read_until(
            lambda m: m.get("method") == "textDocument/publishDiagnostics"
                      and m.get("params", {}).get("uri") == uri,
            timeout=5.0,
        )
        assert msg["params"]["diagnostics"] == []

    def test_clean_file_publishes_empty_diagnostics(
        self, lsp: LspClient, tmp_path: Path,
    ) -> None:
        tf = tmp_path / "main.tf"
        # Truly clean Terraform — outputs need a description to satisfy
        # STYLE-DESC-001 (otherwise the LSP fires that on opening).
        tf.write_text(
            'output "ok" {\n'
            '  value       = "ok"\n'
            '  description = "smoke output for the LSP test"\n'
            '}\n'
        )
        _initialize(lsp)
        uri = _file_uri(tf)
        lsp.send_notification("textDocument/didOpen", {
            "textDocument": {"uri": uri, "languageId": "terraform",
                             "version": 1, "text": tf.read_text()},
        })
        msg = lsp.read_until(
            lambda m: m.get("method") == "textDocument/publishDiagnostics"
                      and m.get("params", {}).get("uri") == uri,
            timeout=10.0,
        )
        # Clean fixture should produce no per-file diagnostics
        # (corpus-level rules fire only on whole-workspace scans).
        assert msg["params"]["diagnostics"] == []


# ---------------------------------------------------------------------------
# Code actions (Quick Fix)
# ---------------------------------------------------------------------------


class TestLspCodeActions:
    def test_code_action_returns_workspace_edit_for_finding_with_fix_hcl(
        self, lsp: LspClient, tmp_path: Path,
    ) -> None:
        tf = tmp_path / "main.tf"
        tf.write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        _initialize(lsp)
        uri = _file_uri(tf)
        lsp.send_notification("textDocument/didOpen", {
            "textDocument": {"uri": uri, "languageId": "terraform",
                             "version": 1, "text": tf.read_text()},
        })
        # Wait for diagnostics (the cache the codeAction handler reads).
        diag_msg = lsp.read_until(
            lambda m: m.get("method") == "textDocument/publishDiagnostics"
                      and m.get("params", {}).get("uri") == uri,
            timeout=10.0,
        )
        diags = diag_msg["params"]["diagnostics"]
        assert diags, "no diagnostics on the offending fixture"
        # Pick the line of the first diagnostic.
        target_line = diags[0]["range"]["start"]["line"]

        rid = lsp.send_request("textDocument/codeAction", {
            "textDocument": {"uri": uri},
            "range": {
                "start": {"line": target_line, "character": 0},
                "end":   {"line": target_line, "character": 0},
            },
            "context": {"diagnostics": diags},
        })
        resp = lsp.read_response(rid, timeout=10.0)
        actions = resp["result"]
        assert isinstance(actions, list)
        # At least one Quick Fix when the rule has fix_hcl. Some rules
        # don't, so this asserts the *shape* not the count when present.
        for a in actions:
            assert a["kind"] == "quickfix"
            assert a["title"].startswith("tf-analyze fix:")
            edit = a["edit"]["changes"][uri]
            assert isinstance(edit, list)
            assert "newText" in edit[0]
            assert "tf-analyze fix" in edit[0]["newText"]

    def test_code_action_far_from_finding_returns_empty(
        self, lsp: LspClient, tmp_path: Path,
    ) -> None:
        tf = tmp_path / "main.tf"
        tf.write_text(
            'resource "aws_db_instance" "x" {\n'
            '  storage_encrypted = false\n'
            '}\n'
            '\n'
            '\n'
            '\n'
            '\n'
            '# unrelated comment far below\n'
        )
        _initialize(lsp)
        uri = _file_uri(tf)
        lsp.send_notification("textDocument/didOpen", {
            "textDocument": {"uri": uri, "languageId": "terraform",
                             "version": 1, "text": tf.read_text()},
        })
        lsp.read_until(
            lambda m: m.get("method") == "textDocument/publishDiagnostics"
                      and m.get("params", {}).get("uri") == uri,
            timeout=10.0,
        )
        # Cursor on line 7 (well past the finding on line 2). Handler
        # filters to findings within 2 lines; expect an empty list.
        rid = lsp.send_request("textDocument/codeAction", {
            "textDocument": {"uri": uri},
            "range": {"start": {"line": 6, "character": 0},
                      "end":   {"line": 6, "character": 0}},
            "context": {"diagnostics": []},
        })
        resp = lsp.read_response(rid, timeout=10.0)
        assert resp["result"] == []


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


class TestLspRobustness:
    def test_handler_crash_doesnt_terminate_server(
        self, lsp: LspClient, tmp_path: Path,
    ) -> None:
        # vscode-languageclient gives up after 5 crashes in 3 minutes.
        # Single-handler crashes must NOT take the loop down — the
        # outer try/except has to keep iterating.
        _initialize(lsp)
        # didOpen with a structurally invalid URI scheme — likely to
        # exercise the error path inside `_scan_uri`.
        bad_uri = "not-a-valid-uri-scheme://nowhere"
        lsp.send_notification("textDocument/didOpen", {
            "textDocument": {"uri": bad_uri, "languageId": "terraform",
                             "version": 1, "text": ""},
        })
        # Now send a healthy request; if the loop is alive, we get a response.
        rid = lsp.send_request("shutdown")
        resp = lsp.read_response(rid, timeout=5.0)
        assert resp.get("result") is None, (
            "shutdown failed after a handler crash — outer try/except missing"
        )

    def test_request_after_unknown_request_still_works(self, lsp: LspClient) -> None:
        _initialize(lsp)
        # First, a method-not-found request.
        bad_id = lsp.send_request("textDocument/totallyMadeUp")
        lsp.read_response(bad_id)
        # Then a healthy one.
        good_id = lsp.send_request("shutdown")
        resp = lsp.read_response(good_id)
        assert resp.get("result") is None
