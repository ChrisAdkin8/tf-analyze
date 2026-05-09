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
exports.HtmlReportPanel = void 0;
const vscode = __importStar(require("vscode"));
const cp = __importStar(require("child_process"));
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const scriptResolver_1 = require("./scriptResolver");
const iframeBridge_1 = require("./iframeBridge");
/** Webview panel that renders `detect.py --format html` output inline.
 *
 * The engine emits a self-contained HTML document with all CSS inlined
 * and zero external script/CDN references — so it drops cleanly into a
 * webview with no CSP rewriting needed. We expose an "Open in browser"
 * affordance for users who want full-fidelity printing or sharing; the
 * webview writes the same HTML to a temp file and asks VS Code to open
 * the file:// URI externally.
 */
class HtmlReportPanel {
    static createOrShow(context) {
        const col = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
        if (HtmlReportPanel.currentPanel) {
            HtmlReportPanel.currentPanel._panel.reveal(col);
            HtmlReportPanel.currentPanel._refresh();
            return;
        }
        const panel = vscode.window.createWebviewPanel('tfAnalyzeHtmlReport', 'tf-analyze: Report', col, { enableScripts: true, retainContextWhenHidden: true });
        HtmlReportPanel.currentPanel = new HtmlReportPanel(panel, context);
    }
    constructor(panel, _context) {
        this._lastHtml = '';
        this._panel = panel;
        this._panel.onDidDispose(() => {
            HtmlReportPanel.currentPanel = undefined;
        });
        // Webview → extension messaging: the toolbar's "Open in browser"
        // button posts { command: 'openExternal' }. We persist the most
        // recently rendered report HTML on `this` so the handler doesn't
        // have to re-scan to satisfy the click.
        this._panel.webview.onDidReceiveMessage((msg) => {
            if (msg?.command === 'openExternal') {
                void this._openInBrowser();
            }
            else if (msg?.command === 'openLink' && typeof msg.url === 'string') {
                // Anchor inside the embedded iframe — webview iframes can't
                // navigate externally on their own. Forward to the user's
                // browser via openExternal.
                if (/^https?:\/\//i.test(msg.url)) {
                    void vscode.env.openExternal(vscode.Uri.parse(msg.url));
                }
            }
        });
        this._panel.webview.html = this._getLoadingHtml();
        this._refresh();
    }
    _refresh() {
        const cfg = vscode.workspace.getConfiguration('tf-analyze');
        const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
        const absScript = (0, scriptResolver_1.resolveScriptPath)(cfg, wsFolder);
        if (!absScript) {
            this._panel.webview.html = this._getErrorHtml('detect.py not found', 'Set <code>tf-analyze.scriptPath</code> in settings to the absolute path of ' +
                '<code>scripts/detect.py</code>, or open the tf-analyze project as part of your ' +
                'workspace.<br><br>Looked in:<ul>' +
                (0, scriptResolver_1.defaultSearchPaths)(wsFolder).map(p => `<li><code>${this._escape(p)}</code></li>`).join('') +
                '</ul>');
            return;
        }
        // Honour the same per-section / extra-args settings the main scan
        // path respects, so the HTML report reflects whatever filter the
        // user has dialed in for the rest of the extension.
        const section = (cfg.get('section') ?? '').trim();
        const extraArgs = (cfg.get('extraArgs') ?? []).filter(a => typeof a === 'string' && a.length > 0);
        const argv = [absScript, '--target', wsFolder, '--format', 'html'];
        if (section)
            argv.push('--section', section);
        argv.push(...extraArgs);
        cp.execFile('python3', argv, { maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
            // Same diagnostic shape as the attack-graph panel: exit 1 with
            // empty stdout means Python crashed before emitting; exit > 1
            // is a hard failure. Either way, surface stderr verbatim.
            const errCode = err?.code;
            const exitGtOne = typeof errCode === 'number' && errCode > 1;
            const stdoutEmpty = !stdout || !stdout.trim();
            const cmdLine = `python3 ${argv.slice(1).map(a => /\s/.test(a) ? `"${a}"` : a).join(' ')}`;
            if (exitGtOne || stdoutEmpty) {
                const reason = stdoutEmpty && !exitGtOne
                    ? 'detect.py exited without printing HTML. Most often this is an unhandled Python exception — see stderr below.'
                    : 'detect.py exited with an error.';
                this._panel.webview.html = this._getErrorHtml('detect.py failed', `<p>${this._escape(reason)}</p>` +
                    `<p><strong>Exit code:</strong> ${errCode ?? '(none)'}</p>` +
                    `<p><strong>stderr:</strong></p><pre>${this._escape(stderr || (err && err.message) || '(empty)')}</pre>` +
                    `<p><strong>Command:</strong> <code>${this._escape(cmdLine)}</code></p>` +
                    '<p>Re-run the command in a terminal to see the full traceback.</p>');
                return;
            }
            // Quick sanity check: the engine output should look like an HTML
            // document. If we got JSON or text by accident (someone edited
            // the format string upstream), say so loudly rather than render
            // raw text inside an <iframe> srcdoc.
            const lookHtml = /^\s*<(?:!doctype|html)/i.test(stdout);
            if (!lookHtml) {
                this._panel.webview.html = this._getErrorHtml('Unexpected detect.py output', '<p>Expected an HTML document but got something else. First 500 chars of stdout:</p>' +
                    `<pre>${this._escape(stdout.slice(0, 500))}</pre>` +
                    `<p><strong>Command:</strong> <code>${this._escape(cmdLine)}</code></p>`);
                return;
            }
            // Keep _lastHtml as pristine engine HTML for "Open in browser"
            // (browsers handle <a> natively); only the iframe-embedded
            // copy needs the click-bridge injected.
            this._lastHtml = stdout;
            this._panel.webview.html = this._wrapReport((0, iframeBridge_1.injectLinkInterceptor)(stdout));
        });
    }
    /** Wrap the engine's HTML in an outer document that adds a small
     * toolbar and embeds the report itself in an `<iframe srcdoc>`. The
     * srcdoc isolates the report's CSS so it can't bleed into the toolbar
     * styling, and keeps the engine output as a verbatim, copy-paste-able
     * artefact (the same bytes that would land on disk).
     */
    _wrapReport(reportHtml) {
        const srcdoc = reportHtml
            .replace(/&/g, '&amp;')
            .replace(/"/g, '&quot;');
        return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body { margin: 0; background: #1e1e1e; color: #ccc; font-family: -apple-system, BlinkMacSystemFont, sans-serif; height: 100vh; display: flex; flex-direction: column; }
  #toolbar { padding: 6px 12px; background: #252526; border-bottom: 1px solid #3c3c3c; display: flex; align-items: center; gap: 8px; font-size: 12px; }
  #toolbar .label { color: #888; }
  #toolbar button { background: #3a3d41; border: 1px solid #555; color: #ccc; padding: 4px 10px; border-radius: 3px; cursor: pointer; font-size: 11px; }
  #toolbar button:hover { background: #4a4d51; }
  iframe { flex: 1; border: 0; background: #fff; }
</style>
</head>
<body>
<div id="toolbar">
  <span class="label">tf-analyze report</span>
  <span style="flex:1"></span>
  <button onclick="reload()">Refresh</button>
  <button onclick="openExternal()">Open in browser</button>
</div>
<iframe id="report" srcdoc="${srcdoc}"></iframe>
<script>
  const vscode = acquireVsCodeApi();
  function reload() { location.reload(); }
  function openExternal() { vscode.postMessage({ command: 'openExternal' }); }
  ${iframeBridge_1.LINK_BRIDGE_PARENT_JS}
</script>
</body>
</html>`;
    }
    /** Write the most recently rendered report to a temp file and ask
     * VS Code to open it externally. Tempfile name embeds the workspace
     * basename so the browser tab is identifiable when several are open.
     */
    async _openInBrowser() {
        if (!this._lastHtml) {
            void vscode.window.showWarningMessage('tf-analyze: no report to open yet.');
            return;
        }
        const wsName = vscode.workspace.workspaceFolders?.[0]?.name ?? 'workspace';
        const safe = wsName.replace(/[^a-zA-Z0-9._-]/g, '_');
        const file = path.join(os.tmpdir(), `tf-analyze-${safe}-${Date.now()}.html`);
        try {
            fs.writeFileSync(file, this._lastHtml, 'utf8');
            await vscode.env.openExternal(vscode.Uri.file(file));
        }
        catch (e) {
            void vscode.window.showErrorMessage(`tf-analyze: failed to open report — ${e.message}`);
        }
    }
    _escape(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    _getLoadingHtml() {
        return '<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif"><p>Building report…</p></body></html>';
    }
    _getErrorHtml(title, body) {
        return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;padding:24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:13px;line-height:1.5">
<h2 style="color:#e53e3e;margin-top:0">${this._escape(title)}</h2>
<div>${body}</div>
<p style="margin-top:24px;color:#888">Re-run with <code>tf-analyze: Show Report</code> after fixing the issue.</p>
</body></html>`;
    }
}
exports.HtmlReportPanel = HtmlReportPanel;
//# sourceMappingURL=htmlReport.js.map