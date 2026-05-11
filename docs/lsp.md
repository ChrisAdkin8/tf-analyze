# tf-analyze LSP server

`detect.py --lsp` starts a JSON-RPC 2.0 Language Server Protocol server on
`stdin/stdout`. Any LSP-capable editor gets inline diagnostics and Quick Fix
actions for `.tf` files without a plugin-specific integration.

## Capabilities

| Feature | Details |
|---------|---------|
| Diagnostics | Published on `didOpen` and `didSave`; cleared on `didClose` |
| Urgency → LSP severity | CRITICAL/HIGH → Error (1) · MEDIUM → Warning (2) · LOW → Info (3) |
| Code actions | `textDocument/codeAction` returns a `WorkspaceEdit` inserting `fix_hcl` for findings near the cursor |
| Latency | Catalogue loaded once at startup; per-file scan ~50–200 ms |

## Neovim (nvim-lspconfig)

```lua
-- ~/.config/nvim/lua/plugins/tf-analyze.lua
local lspconfig = require("lspconfig")
local configs   = require("lspconfig.configs")

if not configs.tf_analyze then
  configs.tf_analyze = {
    default_config = {
      cmd = { "python3", vim.fn.expand("~/Projects/tf-analyze/scripts/detect.py"), "--lsp" },
      filetypes = { "terraform", "tf" },
      root_dir = lspconfig.util.root_pattern(".terraform", ".git", ".tf-analyze.yaml"),
      settings = {},
    },
  }
end

lspconfig.tf_analyze.setup({
  on_attach = function(client, bufnr)
    -- Standard keymaps
    vim.keymap.set("n", "K",  vim.lsp.buf.hover,          { buffer = bufnr })
    vim.keymap.set("n", "<leader>ca", vim.lsp.buf.code_action, { buffer = bufnr })
  end,
})
```

## coc.nvim

Add to `~/.config/nvim/coc-settings.json`:

```json
{
  "languageserver": {
    "tf-analyze": {
      "command": "python3",
      "args": ["/path/to/tf-analyze/scripts/detect.py", "--lsp"],
      "filetypes": ["terraform"],
      "rootPatterns": [".terraform", ".git"]
    }
  }
}
```

## VS Code (without extension)

Add to `settings.json`:

```json
{
  "terraform.languageServer": {
    "external": true,
    "pathToBinary": "python3",
    "args": ["/path/to/tf-analyze/scripts/detect.py", "--lsp"]
  }
}
```

Or use the bundled `tf-analyze` VS Code extension which wires this automatically
when `tf-analyze.useLsp` is `true`.

## Emacs (eglot)

```elisp
(with-eval-after-load 'eglot
  (add-to-list 'eglot-server-programs
    '(terraform-mode . ("python3" "/path/to/detect.py" "--lsp"))))
```

## Zed

In `~/.config/zed/settings.json`:

```json
{
  "lsp": {
    "tf-analyze": {
      "binary": {
        "path": "python3",
        "arguments": ["/path/to/tf-analyze/scripts/detect.py", "--lsp"]
      }
    }
  }
}
```

## Custom rules in LSP mode

If a `.tf-analyze.yaml` with `rules_dir:` is present in the workspace root,
the LSP server picks it up automatically — custom `CUSTOM-*` rules appear as
diagnostics alongside built-in catalogue rules.

## Smoke test

```bash
MSG='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}'
LEN=${#MSG}
printf "Content-Length: %d\r\n\r\n%s" "$LEN" "$MSG" \
  | python3 scripts/detect.py --lsp \
  | python3 -c "import sys,json; print(json.load(open('/dev/stdin')))" 2>/dev/null
```

Expected: JSON with `capabilities.textDocumentSync` and `serverInfo.name = "tf-analyze"`.

## Embedding the LSP server in another tool (R30.10)

`scripts/_lsp.py:run_lsp_server(catalog_dir, project_config, *, scanner,
load_catalog)` accepts two **injected callables** so the module stays
import-free of `detect.py` state. The callable signatures are now
asserted at module entry via `inspect.signature` — a wrapper with the
wrong arity raises `TypeError` immediately rather than failing on the
first JSON-RPC request.

The contract:

| Param | Expected signature | Notes |
|---|---|---|
| `scanner` | `(path: Path, entries: list[dict]) -> list[dict]` | Exactly 2 positional args. `*args`-bearing callables are rejected: the interface is fixed at 2 args, and `*args` would mask future arity drift. |
| `load_catalog` | `(catalog_dir: Path, …) -> list[dict]` | At least 1 required positional arg; extra optional kwargs (`include_stubs`, `strict`, `extra_rules_dir`) are allowed and ignored unless callers pass them. |

If you wrap `run_lsp_server` from outside `detect.py` (e.g. embedding
tf-analyze in another LSP host), make sure your wrapper's positional
arity matches. The assertion error includes the offending signature
verbatim so the failure mode is self-explanatory.
