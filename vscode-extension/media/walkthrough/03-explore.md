## Explore findings & fix issues

### 🔴 Inline diagnostics

Findings appear as **squiggles** on the offending line. Hover for severity, the catalogue rule ID, the CIS mapping, and a remediation hint.

### ⚡ Quick Fix

If a rule supports auto-remediation, hit `⌘.` / `Ctrl+.` on the squiggled line to apply the fix without leaving the editor.

### 🌳 Findings tree

Click the 🛡 **shield icon on the Activity Bar** (left rail) to open the **Findings** view. Items are grouped by file → severity, with one click to jump to the source line.

### 🕸️ Attack-graph view

Run `tf-analyze: Show Attack Graph` from the Command Palette to open an interactive webview that visualises IAM, networking, and KMS reachability between your resources — useful for spotting lateral-movement paths.

---

You're done. Welcome to a quieter Terraform workflow. 🎉
