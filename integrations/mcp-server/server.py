"""tf-analyze MCP server.

Exposes the engine to any [Model Context Protocol]-aware client (Claude
Desktop, Cursor, Continue.dev, GitHub Copilot Chat with MCP support,
etc.) through four tools:

  * ``scan_workspace(path, mode='static', show_info=False, attack_graph=False)``
    Run a tf-analyze scan and return summary + findings.
  * ``explain_rule(rule_id)``
    Print the catalogue entry for a single rule (same shape as ``--explain``).
  * ``apply_fixes(path, dry_run=True)``
    Run ``--apply-fixes`` on the workspace; default is dry-run so the
    agent must explicitly opt in to writes.
  * ``attack_graph(path)``
    Build the internet → crown-jewels graph and return the JSON shape
    + a Mermaid rendering of the graph.

Why MCP: the Claude-specific skill (`/tf-analyze`) hits Claude Code
only. MCP standardises the tool-shape so the engine becomes addressable
from every other AI agent surface — Cursor, Continue, JetBrains AI
Assistant, the wave of MCP-aware shells. The engine itself is
unchanged; this server is a thin RPC adapter.

Run as a stdio server (the canonical MCP transport):

    python3 server.py

Wire into Claude Desktop's `claude_desktop_config.json`:

    {
      "mcpServers": {
        "tf-analyze": {
          "command": "python3",
          "args": ["/path/to/tf-analyze/integrations/mcp-server/server.py"]
        }
      }
    }

Or run as a self-contained Docker image (`integrations/mcp-server/Dockerfile`)
behind a streamable-HTTP transport for remote clients.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

# The MCP SDK is the only runtime dep.
from mcp.server.fastmcp import FastMCP


REPO_ROOT = Path(os.environ.get(
    "TFA_REPO_ROOT",
    str(Path(__file__).resolve().parent.parent.parent),
))
DETECT_PY = Path(os.environ.get(
    "TFA_DETECT_PY",
    str(REPO_ROOT / "scripts" / "detect.py"),
))


_VALID_MODES = {"static", "diff", "plan", "fleet", "trend", "pr-review", "verify-fixed"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_target(raw: str) -> Path:
    """Validate + canonicalise a path argument.

    MCP tools receive untrusted strings from the caller. Reject path-
    traversal and non-existent paths early so the engine doesn't see a
    half-validated argument.
    """
    if not raw or not isinstance(raw, str):
        raise ValueError("path must be a non-empty string")
    if "\0" in raw:
        raise ValueError("path contains a null byte")
    p = Path(raw).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"target path does not exist: {p}")
    if not p.is_dir():
        raise ValueError(f"target path is not a directory: {p}")
    return p


def _run_engine(args: list[str], *, timeout: int = 120) -> str:
    """Execute `detect.py` with the given args and return stdout.

    Raises `RuntimeError` on engine error so the MCP error surface
    matches the underlying failure rather than masking it.
    """
    if not DETECT_PY.exists():
        raise RuntimeError(
            f"detect.py not found at {DETECT_PY}. Set TFA_DETECT_PY or "
            f"TFA_REPO_ROOT to point at the engine."
        )
    res = subprocess.run(
        [sys.executable, str(DETECT_PY), *args],
        capture_output=True, text=True, timeout=timeout,
    )
    # exit 0 = clean, exit 1 = findings-found, both are "scan succeeded".
    # exit 2+ = configuration error → surface to the caller.
    if res.returncode > 1:
        raise RuntimeError(
            f"detect.py exited {res.returncode}. stderr: {res.stderr.strip()}"
        )
    return res.stdout


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


mcp = FastMCP(
    name="tf-analyze",
    instructions=(
        "Terraform static analysis exposed over MCP. Tools cover "
        "scanning a workspace (`scan_workspace`), explaining a single "
        "rule (`explain_rule`), previewing or applying fixes "
        "(`apply_fixes`), and building an attack graph (`attack_graph`). "
        "All paths are validated against the local filesystem; "
        "tool errors surface the underlying engine failure rather than "
        "swallowing it."
    ),
)


@mcp.tool(
    description=(
        "Run a tf-analyze scan over a Terraform workspace. Returns the "
        "engine's `summary` block (score 0-100, letter grade A/B/B-/C/D/F, "
        "per-tier finding counts) plus the full `findings` list. "
        "Findings include rule ID, urgency, file:line, resource, "
        "recommendation, and (when present) `fix_hcl` plus an "
        "adversarial `narrative` for HIGH/CRITICAL findings."
    ),
)
def scan_workspace(
    path: str,
    mode: str = "static",
    show_info: bool = False,
    attack_graph: bool = False,
) -> dict[str, Any]:
    """Scan a Terraform workspace.

    Args:
        path: Absolute path to the workspace directory.
        mode: One of static / diff / plan / fleet / trend / pr-review /
              verify-fixed. Default `static`.
        show_info: Include INFO-tier advisories (Module Reuse, etc.) in
                   the output. Default `False` — they're advisory only.
        attack_graph: Build the internet → crown-jewels graph and
                      promote critical-path findings.
    """
    target = _resolve_target(path)
    if mode not in _VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(_VALID_MODES)}, got {mode!r}")
    args = ["--target", str(target), "--mode", mode, "--format", "json"]
    if show_info:
        args.append("--show-info")
    if attack_graph:
        args.append("--attack-graph")
    out = _run_engine(args)
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"engine returned non-JSON output: {e}")


@mcp.tool(
    description=(
        "Print the full catalogue entry for a single rule. Mirrors "
        "`detect.py --explain <RULE-ID>`: title, urgency, blast radius, "
        "patterns, recommendation, fix_hcl, fix_disruption, CIS/PCI/SOC2 "
        "/MITRE references, and adversarial narrative when present."
    ),
)
def explain_rule(rule_id: str) -> str:
    """Return the full catalogue entry for a rule ID.

    Args:
        rule_id: Catalogue rule identifier (e.g. `SEC-AWS-IAM-001`).
                 Validated against the canonical regex before being
                 passed to the engine.
    """
    import re as _re
    if not _re.match(r"^[A-Z][A-Z0-9-]{2,63}$", rule_id):
        raise ValueError(f"invalid rule ID shape: {rule_id!r}")
    return _run_engine(["--explain", rule_id])


@mcp.tool(
    description=(
        "Run `--apply-fixes` over a workspace. Default is `dry-run` so "
        "the agent must explicitly set `dry_run=False` to write files. "
        "The dry-run output shows the unified diff the engine would "
        "apply; an `apply` run writes files in place and saves originals "
        "as `<file>.bak`."
    ),
)
def apply_fixes(path: str, dry_run: bool = True) -> str:
    """Preview or apply fixes for the entire workspace.

    Args:
        path: Absolute path to the workspace directory.
        dry_run: If True (default), preview only. If False, apply
                 changes in place.
    """
    target = _resolve_target(path)
    mode = "dry-run" if dry_run else "apply"
    return _run_engine([
        "--target", str(target),
        "--apply-fixes", mode,
    ], timeout=300)


@mcp.tool(
    description=(
        "Build the attack-path graph for a workspace. Returns the graph "
        "as JSON (nodes, edges, internet_node_id, critical_path) plus a "
        "Mermaid string suitable for embedding in chat responses or "
        "Markdown documents. Crown-jewel resources (databases, KMS keys, "
        "secrets) are flagged; reachable nodes are walked from internet "
        "entry points."
    ),
)
def attack_graph(path: str) -> dict[str, Any]:
    """Build the attack graph and return both JSON + Mermaid rendering.

    Args:
        path: Absolute path to the workspace directory.
    """
    target = _resolve_target(path)
    out = _run_engine([
        "--target", str(target), "--format", "json", "--attack-graph",
    ])
    payload = json.loads(out)
    graph = payload.get("graph", {})
    # Render Mermaid by importing the engine's renderer directly. This
    # avoids a second engine subprocess and keeps the canonical Mermaid
    # output consistent with what `--format text --attack-graph` shows.
    sys.path.insert(0, str(DETECT_PY.parent))
    try:
        import detect as _detect  # noqa: WPS433 — by-design dynamic import
        mermaid = _detect.graph_to_mermaid(graph) if graph else ""
    except Exception as e:
        # If the engine module can't be imported (older bundle path,
        # etc.), still return the JSON graph so the caller has data.
        mermaid = f"# (Mermaid rendering unavailable: {e})"
    return {
        "summary": payload.get("summary", {}),
        "graph": graph,
        "mermaid": mermaid,
    }


@mcp.resource("tfanalyze://catalogue")
def catalogue_index() -> str:
    """Catalogue index — every active rule ID, urgency, and section.

    Exposed as an MCP resource so agents can browse the full ruleset
    before deciding which to call `explain_rule` on.
    """
    return _run_engine(["--list-rules"])


def _resolve_engine_dir() -> Path:
    """Return the engine directory the MCP server is talking to.

    Used by ``--health`` and CLI debug output to confirm wiring.
    """
    return DETECT_PY.parent


def main() -> int:
    if "--health" in sys.argv:
        # Quick wiring check — does the engine respond? Useful when
        # debugging Claude Desktop config drift.
        try:
            _run_engine(["--list-rules"], timeout=10)
        except Exception as e:
            print(f"engine check failed: {e}", file=sys.stderr)
            return 1
        print(f"OK — engine at {DETECT_PY}", file=sys.stderr)
        return 0
    # Default: run as a stdio MCP server.
    if not shutil.which(sys.executable):
        print(
            f"Python interpreter {sys.executable!r} not found on PATH. "
            f"Set TFA_DETECT_PY or run with the absolute interpreter path.",
            file=sys.stderr,
        )
        return 1
    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
