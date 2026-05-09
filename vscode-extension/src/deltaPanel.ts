import * as vscode from 'vscode';
import * as cp from 'child_process';
import { resolveScriptPath, defaultSearchPaths } from './scriptResolver';
import { ruleDocsUrl } from './urls';

interface Finding {
  id: string;
  title?: string;
  urgency: string;
  file: string;
  line: number;
  resource?: string;
}

interface DeltaPayload {
  delta?: {
    new?: Finding[];
    resolved?: Finding[];
    unchanged?: Finding[];
  };
  summary?: { counts?: Record<string, number> };
}

/** "Since last scan" panel. Runs `detect.py --format json --auto-compare`
 * which auto-discovers the most recent prior JSON report in the
 * configured reports-dir and emits a `delta = {new, resolved, unchanged}`
 * block.
 *
 * The panel surfaces *new* findings front and centre (most actionable),
 * *resolved* findings as a celebratory roll-up (motivational), and an
 * *unchanged* counter (the long-tail to keep working through). Clicking
 * a finding row opens the file at the offending line.
 */
export class DeltaPanel {
  static currentPanel: DeltaPanel | undefined;
  private readonly _panel: vscode.WebviewPanel;

  static createOrShow(context: vscode.ExtensionContext): void {
    const col = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
    if (DeltaPanel.currentPanel) {
      DeltaPanel.currentPanel._panel.reveal(col);
      DeltaPanel.currentPanel._refresh();
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      'tfAnalyzeDelta',
      'tf-analyze: Since Last Scan',
      col,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    DeltaPanel.currentPanel = new DeltaPanel(panel, context);
  }

  private constructor(panel: vscode.WebviewPanel, _context: vscode.ExtensionContext) {
    this._panel = panel;
    this._panel.onDidDispose(() => {
      DeltaPanel.currentPanel = undefined;
    });
    this._panel.webview.onDidReceiveMessage(async (msg: { command?: string; file?: string; line?: number }) => {
      if (msg?.command === 'open' && msg.file && typeof msg.line === 'number') {
        try {
          const doc = await vscode.workspace.openTextDocument(msg.file);
          const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
          const pos = new vscode.Position(Math.max(0, msg.line - 1), 0);
          editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
          editor.selection = new vscode.Selection(pos, pos);
        } catch (e) {
          void vscode.window.showWarningMessage(`tf-analyze: could not open ${msg.file} — ${(e as Error).message}`);
        }
      }
    });
    this._panel.webview.html = '<html><body style="background:#1e1e1e;color:#ccc;font-family:sans-serif;padding:24px"><p>Comparing against last scan…</p></body></html>';
    this._refresh();
  }

  private _refresh(): void {
    const cfg = vscode.workspace.getConfiguration('tf-analyze');
    const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
    const absScript = resolveScriptPath(cfg, wsFolder);
    if (!absScript) {
      this._panel.webview.html = this._errorHtml(
        'detect.py not found',
        'Set <code>tf-analyze.scriptPath</code> in settings or open the tf-analyze project as part of your workspace.<br><br>Looked in:<ul>' +
        defaultSearchPaths(wsFolder).map(p => `<li><code>${this._escape(p)}</code></li>`).join('') + '</ul>'
      );
      return;
    }

    const argv = [absScript, '--target', wsFolder, '--format', 'json', '--auto-compare'];
    cp.execFile('python3', argv, { maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
      const errCode = (err as cp.ExecException & { code?: number } | null)?.code;
      const exitGtOne = typeof errCode === 'number' && errCode > 1;
      const stdoutEmpty = !stdout || !stdout.trim();
      const cmdLine = `python3 ${argv.slice(1).map(a => /\s/.test(a) ? `"${a}"` : a).join(' ')}`;

      if (exitGtOne || stdoutEmpty) {
        this._panel.webview.html = this._errorHtml(
          'detect.py failed',
          `<p><strong>Exit code:</strong> ${errCode ?? '(none)'}</p>` +
          `<p><strong>stderr:</strong></p><pre>${this._escape(stderr || (err && err.message) || '(empty)')}</pre>` +
          `<p><strong>Command:</strong> <code>${this._escape(cmdLine)}</code></p>`
        );
        return;
      }

      let data: DeltaPayload;
      try {
        data = JSON.parse(stdout) as DeltaPayload;
      } catch (e) {
        this._panel.webview.html = this._errorHtml(
          'Could not parse detect.py output',
          `<pre>${this._escape((e as Error).message)}</pre>` +
          `<p>First 500 chars of stdout:</p><pre>${this._escape(stdout.slice(0, 500))}</pre>`
        );
        return;
      }

      this._panel.webview.html = this._renderDelta(data);
    });
  }

  private _renderDelta(data: DeltaPayload): string {
    const delta = data.delta ?? {};
    const newFindings = delta.new ?? [];
    const resolved = delta.resolved ?? [];
    const unchanged = delta.unchanged ?? [];

    const noPrior = newFindings.length === 0 && resolved.length === 0 && unchanged.length === 0;
    if (noPrior) {
      return this._errorHtml(
        'No prior report to compare against',
        '<p>Delta requires at least one prior JSON scan to diff against. The engine auto-discovers reports from <code>--reports-dir</code> (default <code>~/.tf-analyze/reports/</code>).</p>' +
        '<ol>' +
        '<li>Run <code>tf-analyze: Run Scan</code> at least once to seed a baseline report.</li>' +
        '<li>Make a change, save, then re-open this panel — it will show what moved.</li>' +
        '</ol>'
      );
    }

    return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
  body { margin: 0; background: #1e1e1e; color: #ccc; font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 24px; line-height: 1.5; }
  h2 { color: #e1e1e1; margin: 0 0 4px; }
  .lede { color: #888; margin: 0 0 24px; font-size: 12px; }
  .group { margin: 0 0 28px; }
  .group h3 { display: flex; align-items: baseline; gap: 8px; margin: 0 0 8px; font-size: 14px; }
  .count { background: #3a3d41; color: #eee; padding: 1px 7px; border-radius: 10px; font-size: 11px; font-weight: normal; }
  .group.new h3 { color: #e53e3e; } .group.new .count { background: #c0392b; color: #fff; }
  .group.resolved h3 { color: #6BBF84; } .group.resolved .count { background: #27ae60; color: #fff; }
  .group.unchanged h3 { color: #888; }
  ul { list-style: none; padding: 0; margin: 0; }
  li { padding: 6px 8px; border-left: 2px solid #3a3d41; margin: 2px 0; cursor: pointer; font-size: 12px; }
  li:hover { background: #2a2d2e; }
  .urgency { font-weight: 600; padding: 1px 5px; border-radius: 2px; font-size: 10px; margin-right: 6px; }
  .u-CRITICAL { background: #c0392b; color: #fff; }
  .u-HIGH { background: #e67e22; color: #fff; }
  .u-MEDIUM { background: #d4a017; color: #2a1a00; }
  .u-LOW { background: #6BBF84; color: #1a2a1a; }
  .u-INFO { background: #4A90D9; color: #fff; }
  .id { font-family: ui-monospace, Menlo, monospace; color: #aaa; font-size: 11px; margin-right: 6px;
        text-decoration: none; }
  a.id:hover { color: var(--vscode-textLink-activeForeground, #4daafc); text-decoration: underline; }
  .loc { color: #888; font-size: 11px; }
</style></head><body>
<h2>Since last scan</h2>
<p class="lede">Compared against the most recent prior JSON report in the engine's reports directory.</p>

<div class="group new">
  <h3>New <span class="count">${newFindings.length}</span></h3>
  ${newFindings.length === 0 ? '<p style="color:#888;font-size:12px">No new findings since last scan. 🎉</p>' : '<ul>' + newFindings.map(f => this._renderRow(f)).join('') + '</ul>'}
</div>

<div class="group resolved">
  <h3>Resolved <span class="count">${resolved.length}</span></h3>
  ${resolved.length === 0 ? '<p style="color:#888;font-size:12px">No findings resolved since last scan.</p>' : '<ul>' + resolved.map(f => this._renderRow(f)).join('') + '</ul>'}
</div>

<div class="group unchanged">
  <h3>Unchanged <span class="count">${unchanged.length}</span></h3>
  <p style="color:#888;font-size:12px">${unchanged.length} finding${unchanged.length === 1 ? '' : 's'} carried forward from the prior report.</p>
</div>

<script>
const vscode = acquireVsCodeApi();
document.querySelectorAll('li[data-file]').forEach(el => {
  el.addEventListener('click', () => {
    vscode.postMessage({ command: 'open', file: el.dataset.file, line: parseInt(el.dataset.line || '1', 10) });
  });
});
</script>
</body></html>`;
  }

  private _renderRow(f: Finding): string {
    const urg = (f.urgency || 'INFO').toUpperCase();
    const where = f.resource ? `${f.resource} — ${f.file}:${f.line}` : `${f.file}:${f.line}`;
    return `<li data-file="${this._escape(f.file)}" data-line="${f.line}">
      <span class="urgency u-${this._escape(urg)}">${this._escape(urg)}</span>
      <a class="id" href="${ruleDocsUrl(f.id)}" target="_blank" rel="noopener" title="Open rule documentation">${this._escape(f.id)}</a>
      ${this._escape(f.title ?? '')}
      <div class="loc">${this._escape(where)}</div>
    </li>`;
  }

  private _escape(s: string): string {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  private _errorHtml(title: string, body: string): string {
    return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;padding:24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:13px;line-height:1.5">
<h2 style="color:#e53e3e;margin-top:0">${this._escape(title)}</h2>
<div>${body}</div>
</body></html>`;
  }
}
