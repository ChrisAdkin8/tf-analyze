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
