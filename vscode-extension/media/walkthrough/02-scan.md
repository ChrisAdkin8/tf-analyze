## Run your first scan

1. Open any **`.tf`** file in your workspace.
2. Save it (`⌘S` / `Ctrl+S`) — the extension scans automatically.

Or trigger a scan manually:

- **Command Palette** → `tf-analyze: Run Scan`
- **Click the 🛡 status-bar item** (bottom-left)
- **Click the title-bar shield button** in the editor

The status bar will update to something like `🛡 tf-analyze: 6 (C:1 H:4 M:1)` when the scan completes — `C` is critical, `H` is high, `M` is medium.

> **Tip:** If you want to scope to a single concern (e.g. only security findings), set `tf-analyze.section` to `security` in your settings.
