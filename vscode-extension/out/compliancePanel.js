"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.CompliancePanel = void 0;
const vscode = __importStar(require("vscode"));
const cp = __importStar(require("child_process"));
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const scriptResolver_1 = require("./scriptResolver");
const FRAMEWORKS = ['cis', 'pci_dss', 'soc2', 'all'];
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
class CompliancePanel {
    static createOrShow(context) {
        const col = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
        if (CompliancePanel.currentPanel) {
            CompliancePanel.currentPanel._panel.reveal(col);
            CompliancePanel.currentPanel._refresh();
            return;
        }
        const panel = vscode.window.createWebviewPanel('tfAnalyzeCompliance', 'tf-analyze: Compliance', col, { enableScripts: true, retainContextWhenHidden: true });
        CompliancePanel.currentPanel = new CompliancePanel(panel, context);
    }
    constructor(panel, _context) {
        this._framework = 'cis';
        this._lastHtml = '';
        this._panel = panel;
        this._panel.onDidDispose(() => {
            CompliancePanel.currentPanel = undefined;
        });
        this._panel.webview.onDidReceiveMessage((msg) => {
            if (msg?.command === 'setFramework' && msg.framework && FRAMEWORKS.includes(msg.framework)) {
                this._framework = msg.framework;
                this._refresh();
            }
            else if (msg?.command === 'openExternal') {
                void this._openInBrowser();
            }
        });
        this._panel.webview.html = this._loading();
        this._refresh();
    }
    _refresh() {
        const cfg = vscode.workspace.getConfiguration('tf-analyze');
        const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
        const absScript = (0, scriptResolver_1.resolveScriptPath)(cfg, wsFolder);
        if (!absScript) {
            this._panel.webview.html = this._error('detect.py not found', 'Set <code>tf-analyze.scriptPath</code> or open the tf-analyze project as part of your workspace.<br><br>Looked in:<ul>' +
                (0, scriptResolver_1.defaultSearchPaths)(wsFolder).map(p => `<li><code>${this._escape(p)}</code></li>`).join('') + '</ul>');
            return;
        }
        const argv = [absScript, '--target', wsFolder, '--format', 'html', '--compliance', '--compliance-framework', this._framework];
        cp.execFile('python3', argv, { maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
            const errCode = err?.code;
            const exitGtOne = typeof errCode === 'number' && errCode > 1;
            const stdoutEmpty = !stdout || !stdout.trim();
            const cmdLine = `python3 ${argv.slice(1).map(a => /\s/.test(a) ? `"${a}"` : a).join(' ')}`;
            if (exitGtOne || stdoutEmpty) {
                this._panel.webview.html = this._error('detect.py failed', `<p><strong>Exit code:</strong> ${errCode ?? '(none)'}</p>` +
                    `<p><strong>stderr:</strong></p><pre>${this._escape(stderr || (err && err.message) || '(empty)')}</pre>` +
                    `<p><strong>Command:</strong> <code>${this._escape(cmdLine)}</code></p>`);
                return;
            }
            this._lastHtml = stdout;
            this._panel.webview.html = this._wrap(stdout);
        });
    }
    _wrap(reportHtml) {
        const srcdoc = reportHtml.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
        const opts = FRAMEWORKS.map(fw => {
            const label = fw === 'cis' ? 'CIS' : fw === 'pci_dss' ? 'PCI DSS' : fw === 'soc2' ? 'SOC 2' : 'All';
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
<iframe id="report" srcdoc="${srcdoc}"></iframe>
<script>
  const vscode = acquireVsCodeApi();
  document.getElementById('fw').addEventListener('change', e => {
    vscode.postMessage({ command: 'setFramework', framework: e.target.value });
  });
  function reload() { vscode.postMessage({ command: 'setFramework', framework: document.getElementById('fw').value }); }
  function openExternal() { vscode.postMessage({ command: 'openExternal' }); }
</script>
</body></html>`;
    }
    async _openInBrowser() {
        if (!this._lastHtml)
            return;
        const wsName = vscode.workspace.workspaceFolders?.[0]?.name ?? 'workspace';
        const safe = wsName.replace(/[^a-zA-Z0-9._-]/g, '_');
        const file = path.join(os.tmpdir(), `tf-analyze-${safe}-compliance-${this._framework}-${Date.now()}.html`);
        try {
            fs.writeFileSync(file, this._lastHtml, 'utf8');
            await vscode.env.openExternal(vscode.Uri.file(file));
        }
        catch (e) {
            void vscode.window.showErrorMessage(`tf-analyze: failed to open report — ${e.message}`);
        }
    }
    _escape(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    _loading() {
        return '<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif"><p>Building compliance report…</p></body></html>';
    }
    _error(title, body) {
        return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;padding:24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:13px;line-height:1.5">
<h2 style="color:#e53e3e;margin-top:0">${this._escape(title)}</h2>
<div>${body}</div>
</body></html>`;
    }
}
exports.CompliancePanel = CompliancePanel;
//# sourceMappingURL=compliancePanel.js.map