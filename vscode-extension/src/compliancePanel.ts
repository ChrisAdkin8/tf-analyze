import * as vscode from 'vscode';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { resolveScriptPath, defaultSearchPaths } from './scriptResolver';
import { injectLinkInterceptor, injectReportCsp, LINK_BRIDGE_PARENT_JS } from './iframeBridge';
import { runEngine } from './engineRunner';

const FRAMEWORKS = ['cis', 'pci_dss', 'soc2', 'owasp_iac', 'all'] as const;
type Framework = (typeof FRAMEWORKS)[number];

/** Compliance gap report panel. Wraps `detect.py --format html
 * --compliance --compliance-framework <fw>` in a webview with a
 * framework picker so the user can flip between CIS / PCI / SOC 2 / all
 * without leaving the panel.
 *
 * The engine's compliance HTML lists every framework control, marks
 * each PASS/FAIL with the rule(s) that map to it, and highlights gaps
 * (controls with no rule coverage at all). Same self-contained HTML
 * convention as the regular report, so it drops cleanly into an
 * iframe srcdoc.
 */
export class CompliancePanel {
  static currentPanel: CompliancePanel | undefined;
  private readonly _panel: vscode.WebviewPanel;
  private _framework: Framework = 'cis';
  private _lastHtml = '';

  static createOrShow(context: vscode.ExtensionContext): void {
    const col = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
    if (CompliancePanel.currentPanel) {
      CompliancePanel.currentPanel._panel.reveal(col);
      CompliancePanel.currentPanel._refresh();
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      'tfAnalyzeCompliance',
      'tf-analyze: Compliance',
      col,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    CompliancePanel.currentPanel = new CompliancePanel(panel, context);
  }

  private constructor(panel: vscode.WebviewPanel, _context: vscode.ExtensionContext) {
    this._panel = panel;
    this._panel.onDidDispose(() => {
      CompliancePanel.currentPanel = undefined;
    });
    // Audit follow-up #1 — capture + dispose the message handler so a
    // closed-and-reopened panel doesn't leak the prior subscription.
    const msgSub = this._panel.webview.onDidReceiveMessage((msg: { command?: string; framework?: string; url?: string }) => {
      if (msg?.command === 'setFramework' && msg.framework && FRAMEWORKS.includes(msg.framework as Framework)) {
        this._framework = msg.framework as Framework;
        this._refresh();
      } else if (msg?.command === 'openExternal') {
        void this._openInBrowser();
      } else if (msg?.command === 'openLink' && typeof msg.url === 'string') {
        // Click on a rule-ID anchor (or any external link) inside the
        // embedded iframe. The webview's iframe sandbox blocks regular
        // navigation, so the iframe forwards link clicks here and we
        // open them in the user's default browser.
        const url = msg.url;
        if (/^https?:\/\//i.test(url)) {
          void vscode.env.openExternal(vscode.Uri.parse(url));
        }
      }
    });
    this._panel.onDidDispose(() => msgSub.dispose());
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

    const argv = ['--target', wsFolder, '--format', 'html', '--compliance', '--compliance-framework', this._framework];
    runEngine(absScript, argv, ({ err, stdout, stderr, cmdLine, timedOut }) => {
      const errCode = err?.code;
      const exitGtOne = typeof errCode === 'number' && errCode > 1;
      const stdoutEmpty = !stdout || !stdout.trim();

      if (exitGtOne || stdoutEmpty || timedOut) {
        this._panel.webview.html = this._error(
          timedOut ? 'detect.py timed out' : 'detect.py failed',
          `<p><strong>Exit code:</strong> ${errCode ?? '(none)'}</p>` +
          `<p><strong>stderr:</strong></p><pre>${this._escape(stderr || (err && err.message) || '(empty)')}</pre>` +
          `<p><strong>Command:</strong> <code>${this._escape(cmdLine)}</code></p>`
        );
        return;
      }

      // Keep _lastHtml as the engine's pristine HTML so "Open in
      // browser" gets the unmodified report (browsers handle <a>
      // links natively; the bridge is only needed inside the iframe).
      this._lastHtml = stdout;
      this._panel.webview.html = this._wrap(injectLinkInterceptor(stdout));
    });
  }

  private _wrap(reportHtml: string): string {
    // Audit follow-up #14 — srcdoc escape must cover the same character
    // set as the inline `_escape` helper below; previously this path
    // only escaped `&` and `"`, so a `</script>` sequence inside an
    // engine-rendered attribute could break the wrapping HTML.
    const srcdoc = injectReportCsp(reportHtml)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    const opts = FRAMEWORKS.map(fw => {
      const label =
        fw === 'cis' ? 'CIS' :
        fw === 'pci_dss' ? 'PCI DSS' :
        fw === 'soc2' ? 'SOC 2' :
        fw === 'owasp_iac' ? 'OWASP IaC' :
        'All';
      const sel = fw === this._framework ? ' selected' : '';
      return `<option value="${fw}"${sel}>${label}</option>`;
    }).join('');

    return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
  body { margin: 0; background: #1e1e1e; color: #ccc; font-family: -apple-system, BlinkMacSystemFont, sans-serif; height: 100vh; display: flex; flex-direction: column; }
  #toolbar { padding: 6px 12px; background: #252526; border-bottom: 1px solid #3c3c3c; display: flex; align-items: center; gap: 8px; font-size: 12px; }
  #toolbar .label { color: #888; }
  #toolbar select { background: #3a3d41; border: 1px solid #555; color: #ccc; padding: 3px 8px; border-radius: 3px; font-size: 11px; }
  #toolbar button { background: #3a3d41; border: 1px solid #555; color: #ccc; padding: 4px 10px; border-radius: 3px; cursor: pointer; font-size: 11px; }
  #toolbar button:hover { background: #4a4d51; }
  iframe { flex: 1; border: 0; background: #fff; }
</style></head><body>
<div id="toolbar">
  <span class="label">Framework</span>
  <select id="fw">${opts}</select>
  <span style="flex:1"></span>
  <button onclick="reload()">Refresh</button>
  <button onclick="openExternal()">Open in browser</button>
</div>
<iframe id="report" sandbox="allow-scripts" srcdoc="${srcdoc}"></iframe>
<script>
  const vscode = acquireVsCodeApi();
  document.getElementById('fw').addEventListener('change', e => {
    vscode.postMessage({ command: 'setFramework', framework: e.target.value });
  });
  function reload() { vscode.postMessage({ command: 'setFramework', framework: document.getElementById('fw').value }); }
  function openExternal() { vscode.postMessage({ command: 'openExternal' }); }
  ${LINK_BRIDGE_PARENT_JS}
</script>
</body></html>`;
  }

  private async _openInBrowser(): Promise<void> {
    if (!this._lastHtml) return;
    const wsName = vscode.workspace.workspaceFolders?.[0]?.name ?? 'workspace';
    const safe = wsName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const file = path.join(os.tmpdir(), `tf-analyze-${safe}-compliance-${this._framework}-${Date.now()}.html`);
    try {
      fs.writeFileSync(file, this._lastHtml, 'utf8');
      await vscode.env.openExternal(vscode.Uri.file(file));
    } catch (e) {
      void vscode.window.showErrorMessage(`tf-analyze: failed to open report — ${(e as Error).message}`);
    }
  }

  private _escape(s: string): string {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  private _loading(): string {
    return '<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif"><p>Building compliance report…</p></body></html>';
  }

  private _error(title: string, body: string): string {
    return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;padding:24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:13px;line-height:1.5">
<h2 style="color:#e53e3e;margin-top:0">${this._escape(title)}</h2>
<div>${body}</div>
</body></html>`;
  }
}
