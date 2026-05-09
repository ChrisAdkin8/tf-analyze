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
exports.MitrePanel = void 0;
const vscode = __importStar(require("vscode"));
const cp = __importStar(require("child_process"));
const scriptResolver_1 = require("./scriptResolver");
const urls_1 = require("./urls");
/** MITRE ATT&CK view. Runs `detect.py --format mitre`, which emits a
 * markdown-flavoured plain-text grouping of findings by ATT&CK
 * technique (e.g. "T1078.004 — Valid Accounts: Cloud Accounts").
 *
 * Pure text output drops into a styled `<pre>` block. This is a
 * niche-but-loved view for red-team users; available via the command
 * palette and the Findings tree-view title bar (no status-bar slot —
 * the bar already has five entries).
 */
class MitrePanel {
    static createOrShow(context) {
        const col = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
        if (MitrePanel.currentPanel) {
            MitrePanel.currentPanel._panel.reveal(col);
            MitrePanel.currentPanel._refresh();
            return;
        }
        const panel = vscode.window.createWebviewPanel('tfAnalyzeMitre', 'tf-analyze: MITRE ATT&CK', col, { enableScripts: false, retainContextWhenHidden: true });
        MitrePanel.currentPanel = new MitrePanel(panel, context);
    }
    constructor(panel, _context) {
        this._panel = panel;
        this._panel.onDidDispose(() => {
            MitrePanel.currentPanel = undefined;
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
        const argv = [absScript, '--target', wsFolder, '--format', 'mitre'];
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
            this._panel.webview.html = this._renderMitre(stdout);
        });
    }
    /** The engine emits markdown-style headings (`## ...`, `### Txxxx`)
     * and indented finding bullets. We don't need a markdown renderer —
     * a styled `<pre>` keeps the engine's column alignment intact and
     * highlights the technique IDs and urgency tags inline. */
    _renderMitre(text) {
        const escaped = this._escape(text)
            // Section header: ### Txxxx.yyy or ### (unmapped)
            .replace(/^### (T\d+(?:\.\d+)?|.+?)(\s+\(\d+ findings?\))?$/gm, (_m, tid, count) => {
            const tagged = tid.startsWith('T')
                ? `<span class="tech">${tid}</span>`
                : `<span class="tech-unmapped">${tid}</span>`;
            return `<h3>${tagged}${count ? `<span class="count">${count.trim()}</span>` : ''}</h3>`;
        })
            .replace(/^## (.+)$/gm, '<h2>$1</h2>')
            // Urgency tag inside finding bullets
            .replace(/\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/g, (_m, u) => `<span class="u u-${u}">${u}</span>`)
            // Rule IDs in finding bullets: SEC-AWS-IAM-001, ROB-AWS-RDS-002, …
            // The plain-text output emits them as bare tokens after the
            // urgency tag; turn each into an anchor that links to the
            // per-rule docs page.
            .replace(/\b((?:SEC|ROB|STK|OPS|MOD|COST|INT|CI|STYLE|CUSTOM)-[A-Z0-9-]+)\b/g, (_m, ruleId) => `<a class="rule-id" href="${(0, urls_1.ruleDocsUrl)(ruleId)}" target="_blank" rel="noopener" title="Open rule documentation">${ruleId}</a>`);
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
  .rule-id { color: #ccc; text-decoration: none; border-bottom: 1px dotted #555; }
  .rule-id:hover { color: #4daafc; border-bottom-color: #4daafc; }
  pre { white-space: pre-wrap; margin: 0; }
</style></head><body>
<pre>${escaped}</pre>
</body></html>`;
    }
    _escape(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    _loading() {
        return '<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif"><p>Building MITRE ATT&CK view…</p></body></html>';
    }
    _error(title, body) {
        return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;padding:24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:13px;line-height:1.5">
<h2 style="color:#e53e3e;margin-top:0">${this._escape(title)}</h2>
<div>${body}</div>
</body></html>`;
    }
}
exports.MitrePanel = MitrePanel;
//# sourceMappingURL=mitrePanel.js.map