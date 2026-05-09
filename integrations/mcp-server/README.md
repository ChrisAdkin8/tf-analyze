# tf-analyze MCP server

Exposes the tf-analyze engine over the [Model Context
Protocol](https://modelcontextprotocol.io) so any MCP-aware agent —
Claude Desktop, Cursor, Continue.dev, GitHub Copilot Chat with MCP, the
JetBrains AI Assistant, and the wave of MCP-compatible shells — can
scan, explain, fix, and graph Terraform code through the same surface.

## Tools

| Tool | Description |
|------|-------------|
| `scan_workspace(path, mode='static', show_info=False, attack_graph=False)` | Run a tf-analyze scan; returns `summary` + `findings`. |
| `explain_rule(rule_id)` | Print the catalogue entry for one rule. |
| `apply_fixes(path, dry_run=True)` | Preview or apply `--apply-fixes`. Default dry-run. |
| `attack_graph(path)` | Build the internet → crown-jewels graph; returns JSON graph + Mermaid string. |

The catalogue index is also exposed as an MCP resource at
`tfanalyze://catalogue`.

## Install

```sh
pip install -r requirements.txt    # MCP SDK only
pip install python-hcl2            # Optional fast-path; engine works without it
```

## Wire into Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or the equivalent on your platform:

```json
{
  "mcpServers": {
    "tf-analyze": {
      "command": "python3",
      "args": ["/path/to/tf-analyze/integrations/mcp-server/server.py"]
    }
  }
}
```

Restart Claude Desktop. The four tools appear in the tool picker; the
agent can call them on any folder you give it.

## Wire into Cursor

Cursor reads MCP config from `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "tf-analyze": {
      "command": "python3",
      "args": ["/absolute/path/to/integrations/mcp-server/server.py"]
    }
  }
}
```

## Wire into other MCP-aware clients

Continue.dev, the Cline extension, the JetBrains AI Assistant, and most
other MCP shells share the same config shape: a `command` + `args` pair
that spawns the server over stdio. Point them at `server.py`.

## Health check

```sh
python3 server.py --health
```

Confirms the wired-up engine responds. Useful when debugging
config-file path drift in Claude Desktop / Cursor.

## Docker

```sh
docker build -f integrations/mcp-server/Dockerfile -t tf-analyze-mcp .
```

The image bundles the engine + catalogue alongside the server.
Stdio is the default transport — for remote clients, override `CMD` to
a streamable-HTTP transport in your deployment.

## Why MCP

The `/tf-analyze` Claude Code skill is Claude-specific. MCP standardises
the tool-shape so the engine becomes addressable from every other AI
agent surface — without per-host adapters. The engine itself doesn't
change; this server is a thin RPC layer.
