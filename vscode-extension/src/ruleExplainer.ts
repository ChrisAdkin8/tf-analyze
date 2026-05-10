import * as vscode from 'vscode';
import * as cp from 'child_process';
import { resolveScriptPath } from './scriptResolver';
import { ruleDocsUrl } from './urls';

/**
 * Rule explainer webview. Opened by:
 *   1. The URI handler when a `vscode://tfanalyze.tf-analyze/rule/<RULE-ID>`
 *      link is clicked (typically on the docs site).
 *   2. The `tf-analyze.explainRule` command from the palette.
 *
 * Runs `detect.py --explain <RULE-ID>` against the bundled engine and
 * renders the plain-text output in a styled <pre> with rule-id
 * cross-links and a one-click button back to the docs page.
 */
export class RuleExplainerPanel {
  private static panels = new Map<string, RuleExplainerPanel>();
  private readonly _panel: vscode.WebviewPanel;
  private readonly _ruleId: string;

  static createOrShow(context: vscode.ExtensionContext, ruleId: string): void {
    const col = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
    const existing = RuleExplainerPanel.panels.get(ruleId);
    if (existing) {
      existing._panel.reveal(col);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      `tfAnalyzeExplain:${ruleId}`,
      `tf-analyze: ${ruleId}`,
      col,
      { enableScripts: false, retainContextWhenHidden: true }
    );
    RuleExplainerPanel.panels.set(ruleId, new RuleExplainerPanel(panel, context, ruleId));
  }

  private constructor(panel: vscode.WebviewPanel, _context: vscode.ExtensionContext, ruleId: string) {
    this._panel = panel;
    this._ruleId = ruleId;
    this._panel.onDidDispose(() => {
      RuleExplainerPanel.panels.delete(ruleId);
    });
    this._panel.webview.html = this._loading();
    this._refresh();
  }

  private _refresh(): void {
    if (!/^[A-Z][A-Z0-9-]{2,63}$/.test(this._ruleId)) {
      // Reject anything that doesn't look like a catalogue ID before
      // shelling out — defense against URI-handler injection from
      // untrusted browser-side links.
      this._panel.webview.html = this._error(
        'Invalid rule ID',
        `<p>The rule ID <code>${this._escape(this._ruleId)}</code> doesn't match the expected pattern. ` +
        'Catalogue IDs are uppercase letters, digits, and hyphens (e.g. <code>SEC-AWS-IAM-001</code>).</p>'
      );
      return;
    }
    const cfg = vscode.workspace.getConfiguration('tf-analyze');
    const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
    const absScript = resolveScriptPath(cfg, wsFolder);
    if (!absScript) {
      this._panel.webview.html = this._error(
        'detect.py not found',
        'Set <code>tf-analyze.scriptPath</code> or open the tf-analyze project as part of your workspace.'
      );
      return;
    }
    const argv = [absScript, '--explain', this._ruleId];
    cp.execFile('python3', argv, { maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      const errCode = (err as cp.ExecException & { code?: number } | null)?.code;
      if (typeof errCode === 'number' && errCode > 1) {
        this._panel.webview.html = this._error(
          `Couldn't load ${this._ruleId}`,
          `<p><strong>Exit code:</strong> ${errCode}</p>` +
          `<pre>${this._escape(stderr || (err && err.message) || '(empty)')}</pre>`
        );
        return;
      }
      this._panel.webview.html = this._render(stdout || '');
    });
  }

  private _render(text: string): string {
    const docsUrl = ruleDocsUrl(this._ruleId);
    const escaped = this._escape(text)
      // Taxonomy header lines emitted by `detect.py --explain`:
      //   # CIS: 1.16
      //   # MITRE ATT&CK: T1078.004
      //   # CWE: CWE-269, CWE-732
      //   # MITRE D3FEND: D3-PA, D3-MFA
      // Promote each to a styled chip-row before the H1 promotion below
      // catches them as part of an h1 block.
      .replace(/^# CIS: (.+)$/gm, (_m, items: string) =>
        `<div class="taxon"><span class="taxon-label">CIS</span>${items.split(',').map(s => `<span class="chip chip-cis">${s.trim()}</span>`).join('')}</div>`)
      .replace(/^# MITRE ATT&amp;CK: (.+)$/gm, (_m, items: string) =>
        `<div class="taxon"><span class="taxon-label">MITRE ATT&amp;CK</span>${items.split(',').map(s => `<a class="chip chip-mitre" href="https://attack.mitre.org/techniques/${s.trim().replace('.', '/')}/" target="_blank" rel="noopener">${s.trim()}</a>`).join('')}</div>`)
      .replace(/^# CWE: (.+)$/gm, (_m, items: string) =>
        `<div class="taxon"><span class="taxon-label">CWE</span>${items.split(',').map(s => {
          const id = s.trim();
          const num = id.replace(/^CWE-/, '');
          return `<a class="chip chip-cwe" href="https://cwe.mitre.org/data/definitions/${num}.html" target="_blank" rel="noopener">${id}</a>`;
        }).join('')}</div>`)
      .replace(/^# MITRE D3FEND: (.+)$/gm, (_m, items: string) =>
        `<div class="taxon"><span class="taxon-label">D3FEND</span>${items.split(',').map(s => `<a class="chip chip-d3fend" href="https://d3fend.mitre.org/technique/${s.trim()}/" target="_blank" rel="noopener">${s.trim()}</a>`).join('')}</div>`)
      // Promote `## Section` headings to <h2>
      .replace(/^## (.+)$/gm, '<h2>$1</h2>')
      // First line `# RULE-ID — title` to <h1>
      .replace(/^# (.+)$/gm, '<h1>$1</h1>')
      // Cross-link any other rule IDs in the body to their docs pages.
      .replace(/\b((?:SEC|ROB|STK|OPS|MOD|COST|INT|CI|STYLE|CUSTOM|DRY)-[A-Z0-9-]+)\b/g,
        (_m, id: string) =>
          id === this._ruleId ? id : `<a href="${ruleDocsUrl(id)}">${id}</a>`);
    return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
  body { margin: 0; background: #1e1e1e; color: #ccc; font-family: ui-monospace, Menlo, monospace; font-size: 12px; padding: 24px; line-height: 1.55; }
  h1 { font-size: 17px; color: #e1e1e1; margin: 0 0 12px; padding-bottom: 6px; border-bottom: 1px solid #3c3c3c; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
  h2 { font-size: 13px; color: #ddd; margin: 18px 0 4px; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
  a { color: #4daafc; text-decoration: none; }
  a:hover { text-decoration: underline; }
  pre { white-space: pre-wrap; margin: 0; font-family: inherit; }
  .toolbar { margin-bottom: 16px; }
  .toolbar a { display: inline-block; background: #157878; color: #fff !important; padding: 6px 12px; border-radius: 4px; font-family: -apple-system, BlinkMacSystemFont, sans-serif; font-weight: 600; font-size: 12px; }
  .toolbar a:hover { text-decoration: none; opacity: 0.9; }
  /* Taxonomy chip rows — CIS / MITRE / CWE / D3FEND.
     One row per framework, label on the left, chip-style links across.  */
  .taxon { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: 4px 0; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
  .taxon-label { color: #888; font-size: 11px; font-weight: 600; min-width: 100px; text-transform: uppercase; letter-spacing: 0.5px; }
  .chip { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-family: ui-monospace, Menlo, monospace; text-decoration: none; }
  .chip:hover { opacity: 0.9; text-decoration: none; }
  .chip-cis    { background: #2a4a6a; color: #cce0f5 !important; }
  .chip-mitre  { background: #4A2A6A; color: #e0c8f5 !important; }
  .chip-cwe    { background: #6a4a2a; color: #f5e0c8 !important; }
  .chip-d3fend { background: #2a6a4a; color: #c8f5e0 !important; }
</style></head><body>
<div class="toolbar"><a href="${docsUrl}" target="_blank" rel="noopener">📖 Open full rule docs in browser →</a></div>
<pre>${escaped}</pre>
</body></html>`;
  }

  private _escape(s: string): string {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  private _loading(): string {
    return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif"><p>Loading ${this._escape(this._ruleId)}…</p></body></html>`;
  }

  private _error(title: string, body: string): string {
    return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;padding:24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:13px;line-height:1.5">
<h2 style="color:#e53e3e;margin-top:0">${this._escape(title)}</h2>
<div>${body}</div>
</body></html>`;
  }
}
