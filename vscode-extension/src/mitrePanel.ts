import * as vscode from 'vscode';
import * as cp from 'child_process';
import { resolveScriptPath, defaultSearchPaths } from './scriptResolver';

/** MITRE ATT&CK view. Runs `detect.py --format mitre`, which emits a
 * markdown-flavoured plain-text grouping of findings by ATT&CK
 * technique (e.g. "T1078.004 — Valid Accounts: Cloud Accounts").
 *
 * Pure text output drops into a styled `<pre>` block. This is a
 * niche-but-loved view for red-team users; available via the command
 * palette and the Findings tree-view title bar (no status-bar slot —
 * the bar already has five entries).
 */
export class MitrePanel {
  static currentPanel: MitrePanel | undefined;
  private readonly _panel: vscode.WebviewPanel;

  static createOrShow(context: vscode.ExtensionContext): void {
    const col = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
    if (MitrePanel.currentPanel) {
      MitrePanel.currentPanel._panel.reveal(col);
      MitrePanel.currentPanel._refresh();
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      'tfAnalyzeMitre',
      'tf-analyze: MITRE ATT&CK',
      col,
      { enableScripts: false, retainContextWhenHidden: true }
    );
    MitrePanel.currentPanel = new MitrePanel(panel, context);
  }

  private constructor(panel: vscode.WebviewPanel, _context: vscode.ExtensionContext) {
    this._panel = panel;
    this._panel.onDidDispose(() => {
      MitrePanel.currentPanel = undefined;
    });
    this._panel.webview.html = this._loading();
    this._refresh();
  }

  private _refresh(): void {
    const cfg = vscode.workspace.getConfiguration('tf-analyze');
    const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
    const absScript = resolveScriptPath(cfg, wsFolder);
    if (!absScript) {
      this._panel.webview.html = this._error(
        'detect.py not found',
        'Set <code>tf-analyze.scriptPath</code> or open the tf-analyze project as part of your workspace.<br><br>Looked in:<ul>' +
        defaultSearchPaths(wsFolder).map(p => `<li><code>${this._escape(p)}</code></li>`).join('') + '</ul>'
      );
      return;
    }

    const argv = [absScript, '--target', wsFolder, '--format', 'mitre'];
    cp.execFile('python3', argv, { maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
      const errCode = (err as cp.ExecException & { code?: number } | null)?.code;
      const exitGtOne = typeof errCode === 'number' && errCode > 1;
      const stdoutEmpty = !stdout || !stdout.trim();
      const cmdLine = `python3 ${argv.slice(1).map(a => /\s/.test(a) ? `"${a}"` : a).join(' ')}`;

      if (exitGtOne || stdoutEmpty) {
        this._panel.webview.html = this._error(
          'detect.py failed',
          `<p><strong>Exit code:</strong> ${errCode ?? '(none)'}</p>` +
          `<p><strong>stderr:</strong></p><pre>${this._escape(stderr || (err && err.message) || '(empty)')}</pre>` +
          `<p><strong>Command:</strong> <code>${this._escape(cmdLine)}</code></p>`
        );
        return;
      }

      this._panel.webview.html = this._renderMitre(stdout);
    });
  }

  /** The engine emits markdown-style headings (`## ...`, `### Txxxx`)
   * and indented finding bullets. We don't need a markdown renderer —
   * a styled `<pre>` keeps the engine's column alignment intact and
   * highlights the technique IDs and urgency tags inline. */
  private _renderMitre(text: string): string {
    const escaped = this._escape(text)
      // Section header: ### Txxxx.yyy or ### (unmapped)
      .replace(/^### (T\d+(?:\.\d+)?|.+?)(\s+\(\d+ findings?\))?$/gm,
        (_m, tid: string, count: string) => {
          const tagged = tid.startsWith('T')
            ? `<span class="tech">${tid}</span>`
            : `<span class="tech-unmapped">${tid}</span>`;
          return `<h3>${tagged}${count ? `<span class="count">${count.trim()}</span>` : ''}</h3>`;
        })
      .replace(/^## (.+)$/gm, '<h2>$1</h2>')
      // Urgency tag inside finding bullets
      .replace(/\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/g, (_m, u: string) => `<span class="u u-${u}">${u}</span>`);

    return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
  body { margin: 0; background: #1e1e1e; color: #ccc; font-family: ui-monospace, Menlo, monospace; font-size: 12px; padding: 24px; line-height: 1.5; }
  h2 { font-size: 16px; color: #e1e1e1; margin: 20px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #3c3c3c; }
  h3 { font-size: 13px; color: #ddd; margin: 16px 0 4px; display: flex; align-items: baseline; gap: 8px; }
  .tech { background: #4A90D9; color: #fff; padding: 1px 6px; border-radius: 3px; font-family: ui-monospace, Menlo, monospace; font-size: 11px; }
  .tech-unmapped { color: #888; font-style: italic; }
  .count { color: #888; font-size: 11px; font-weight: normal; }
  .u { display: inline-block; padding: 0 5px; border-radius: 2px; font-size: 10px; font-weight: 600; margin-right: 4px; }
  .u-CRITICAL { background: #c0392b; color: #fff; }
  .u-HIGH { background: #e67e22; color: #fff; }
  .u-MEDIUM { background: #d4a017; color: #2a1a00; }
  .u-LOW { background: #6BBF84; color: #1a2a1a; }
  .u-INFO { background: #4A90D9; color: #fff; }
  pre { white-space: pre-wrap; margin: 0; }
</style></head><body>
<pre>${escaped}</pre>
</body></html>`;
  }

  private _escape(s: string): string {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  private _loading(): string {
    return '<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif"><p>Building MITRE ATT&CK view…</p></body></html>';
  }

  private _error(title: string, body: string): string {
    return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;padding:24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:13px;line-height:1.5">
<h2 style="color:#e53e3e;margin-top:0">${this._escape(title)}</h2>
<div>${body}</div>
</body></html>`;
  }
}
