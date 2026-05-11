"""JSON-RPC 2.0 LSP server for the VS Code extension.

Extracted from `detect.py` as the ninth seam in the modularisation
(after `_mitre.py`, `_versions.py`, `_scoring.py`, `_hcl.py`,
`_catalog.py`, `_attack_graph.py`, `_output.py`, `_cross_resource.py`).

`run_lsp_server` is invoked by `detect.py --lsp`. It exchanges
Content-Length-framed JSON-RPC messages on stdin/stdout, mirroring
exactly what `vscode-languageclient` expects: `initialize` →
`textDocument/didOpen|didChange|didSave` → diagnostics →
`textDocument/codeAction` → workspace edits.

Public surface:
  * `run_lsp_server(catalog_dir, project_config, *, scanner)` —
    enters the main loop; never returns under normal operation
    (`exit` notification calls `sys.exit(0)`).
  * `findings_to_diagnostics(findings, id_map)` — pure mapper used by
    `run_lsp_server` and exposed for unit testing.

Dependency injection: `scanner(path: Path, entries: list[dict]) -> list[dict]`
is provided by `detect.py` so this module does not import the heavy
HCL detection stack. The callable-injection seam keeps `_lsp.py`
under 200 LoC and free of circular imports.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Callable


# Severity mapping: LSP DiagnosticSeverity is 1..4 (Error/Warning/Info/Hint).
# CRITICAL and HIGH both surface as Error squiggles — anything less is a
# soft warning the user can ignore without missing a real problem.
_SEVERITY_MAP: dict[str, int] = {
    "CRITICAL": 1,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


# R30.18 — Blast-radius drives an editor-time urgency uplift. A HIGH
# finding on a leaf-resource S3 bucket is less load-bearing than a
# MEDIUM finding on a 12-downstream VPC. The LSP severity is what the
# editor renders as squiggle colour; uplifting it surfaces the
# load-bearing finding *visually* without the user needing to read
# the attack-graph view.
#
# Thresholds tuned for the SRE persona: small blasts (1–4) are below
# noise; mid (5–9) bumps one tier; large (10+) bumps two tiers (cap at
# severity 1 = Error). Easy to dial; thresholds are constants so a
# future telemetry pass can A/B them.
_BLAST_UPLIFT_SMALL = 5
_BLAST_UPLIFT_LARGE = 10


def _uplift_severity(base_severity: int, blast: int) -> int:
    """Compute the LSP severity after blast-radius uplift.

    Args:
        base_severity: severity from the rule's default urgency (1..4,
            with 1 = Error and 4 = Hint per the LSP spec).
        blast: downstream blast radius for the resource this finding
            cites; 0 when --attack-graph wasn't requested or the
            resource is a leaf.

    Returns:
        Effective severity, capped at 1 (Error).
    """
    if blast >= _BLAST_UPLIFT_LARGE:
        return max(1, base_severity - 2)
    if blast >= _BLAST_UPLIFT_SMALL:
        return max(1, base_severity - 1)
    return base_severity


def findings_to_diagnostics(
    findings: list[dict],
    id_map: dict[str, dict],
) -> list[dict]:
    """Convert engine findings to LSP `Diagnostic[]`.

    Each diagnostic gets `range`, `severity` (1..4), `code` (rule ID),
    `source` ("tf-analyze"), and `message`. The range character span is
    a sentinel 0..9999 because the engine returns line-granular hits
    only; the LSP client trims to the visible line.

    When a finding carries a ``blast_radius`` field (populated when the
    scan ran with ``--attack-graph``), two enrichments fire:

    * **Severity uplift** — large blasts bump severity up one or two
      tiers (mid → high, etc.), so the editor's squiggle colour
      reflects operational impact, not just rule urgency.
    * **Message annotation** — appends ``🌊 blast: N`` to the hover
      tooltip so the user sees the downstream count without opening
      the attack-graph view.

    Both enrichments are no-ops when ``blast_radius`` is absent or
    zero, so the LSP works identically whether the engine was invoked
    with ``--attack-graph`` or not.
    """
    diags: list[dict] = []
    for f in findings:
        line = max(0, f["line"] - 1)
        urgency = id_map.get(f["id"], {}).get("default_urgency", "LOW")
        base_severity = _SEVERITY_MAP.get(urgency, 3)
        blast = int(f.get("blast_radius") or 0)
        severity = _uplift_severity(base_severity, blast)
        title = id_map.get(f["id"], {}).get("title", "")
        message = f"{f['id']}: {title}"
        if blast >= 1:
            message += f"  🌊 blast: {blast}"
        diags.append({
            "range": {"start": {"line": line, "character": 0},
                      "end":   {"line": line, "character": 9999}},
            "severity": severity,
            "code": f["id"],
            "source": "tf-analyze",
            "message": message,
        })
    return diags


def _uri_to_path(uri: str) -> Path:
    return Path(uri.removeprefix("file://"))


def run_lsp_server(
    catalog_dir: Path,
    project_config: dict,
    *,
    scanner: Callable[[Path, list[dict]], list[dict]],
    load_catalog: Callable[[Path], list[dict]],
) -> None:
    """JSON-RPC 2.0 LSP server on stdin/stdout.

    `scanner(path, entries)` returns findings for a single .tf file.
    `load_catalog(catalog_dir)` returns the parsed catalogue entries.
    Both are injected so this module does not import from `detect.py`.
    """
    entries = load_catalog(catalog_dir)
    id_map = {e["id"]: e for e in entries}
    _diagnostics: dict[str, list] = {}

    def _scan_uri(uri: str) -> list[dict]:
        path = _uri_to_path(uri)
        if not path.exists() or path.suffix != ".tf":
            return []
        return scanner(path, entries)

    def _read_message() -> dict | None:
        header = b""
        while not header.endswith(b"\r\n\r\n"):
            ch = sys.stdin.buffer.read(1)
            if not ch:
                return None
            header += ch
        m = re.search(rb"Content-Length: (\d+)", header)
        if not m:
            return None
        length = int(m.group(1))
        body = sys.stdin.buffer.read(length)
        return json.loads(body)

    def _send(obj: dict) -> None:
        body = json.dumps(obj).encode()
        sys.stdout.buffer.write(
            f"Content-Length: {len(body)}\r\n\r\n".encode() + body
        )
        sys.stdout.buffer.flush()

    def _notify(method: str, params: dict) -> None:
        _send({"jsonrpc": "2.0", "method": method, "params": params})

    while True:
        msg = _read_message()
        if msg is None:
            break
        method = msg.get("method", "")
        mid = msg.get("id")

        # Wrap every message handler in a try/except so a single bad
        # file or malformed payload can't take the whole server down.
        # vscode-languageclient gives up after five crashes in three
        # minutes ("The server will not be restarted"), so any handler
        # that throws on real-world input loses the LSP entirely until
        # the user reloads. Log the traceback to stderr (visible in
        # the extension's Output channel) and keep the loop alive.
        try:
            if method == "initialize":
                _send({
                    "jsonrpc": "2.0", "id": mid,
                    "result": {
                        "capabilities": {
                            # Spec-compliant shape: openClose + change=Full
                            # (we re-scan the whole file on every update,
                            # so incremental sync would be wasted) + save
                            # as an object so older clients don't reject it.
                            "textDocumentSync": {
                                "openClose": True,
                                "change": 1,
                                "save": {"includeText": False},
                            },
                            "codeActionProvider": True,
                        },
                        "serverInfo": {"name": "tf-analyze", "version": "0.1.0"},
                    }
                })

            elif method == "initialized":
                pass

            elif method in ("textDocument/didOpen", "textDocument/didSave", "textDocument/didChange"):
                uri = msg["params"]["textDocument"]["uri"]
                findings = _scan_uri(uri)
                _diagnostics[uri] = findings
                _notify("textDocument/publishDiagnostics", {
                    "uri": uri,
                    "diagnostics": findings_to_diagnostics(findings, id_map),
                })

            elif method == "textDocument/didClose":
                uri = msg["params"]["textDocument"]["uri"]
                _diagnostics.pop(uri, None)
                _notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": []})

            elif method == "textDocument/codeAction":
                uri = msg["params"]["textDocument"]["uri"]
                req_line = msg["params"]["range"]["start"]["line"] + 1
                findings = _diagnostics.get(uri, [])
                actions = []
                for f in findings:
                    if abs(f["line"] - req_line) > 2:
                        continue
                    entry = id_map.get(f["id"], {})
                    fix_hcl = entry.get("fix_hcl")
                    if not fix_hcl:
                        continue
                    actions.append({
                        "title": f"tf-analyze fix: {f['id']}",
                        "kind": "quickfix",
                        "edit": {
                            "changes": {
                                uri: [{
                                    "range": {
                                        "start": {"line": f["line"] - 1, "character": 0},
                                        "end":   {"line": f["line"] - 1, "character": 0},
                                    },
                                    "newText": f"\n# tf-analyze fix for {f['id']}:\n{fix_hcl}\n",
                                }]
                            }
                        }
                    })
                _send({"jsonrpc": "2.0", "id": mid, "result": actions})

            elif method == "shutdown":
                _send({"jsonrpc": "2.0", "id": mid, "result": None})

            elif method == "exit":
                sys.exit(0)

            elif mid is not None:
                # Unknown request — return MethodNotFound. Notifications
                # (mid is None) for unhandled methods are silently dropped
                # per LSP spec.
                _send({"jsonrpc": "2.0", "id": mid,
                       "error": {"code": -32601, "message": f"Method not found: {method}"}})
        except SystemExit:
            # `exit` notification calls sys.exit(0) — let that propagate.
            raise
        except Exception as _exc:
            import traceback as _tb
            _tb.print_exc(file=sys.stderr)
            print(f"[tf-analyze LSP] handler for {method!r} crashed; continuing. {_exc!r}", file=sys.stderr)
            # If this was a request (has an id), return an error so the
            # client doesn't hang waiting for a response that'll never
            # arrive. Notifications get no response either way.
            if mid is not None:
                try:
                    _send({"jsonrpc": "2.0", "id": mid,
                           "error": {"code": -32603, "message": f"Internal error in {method}: {_exc}"}})
                except Exception:
                    pass
