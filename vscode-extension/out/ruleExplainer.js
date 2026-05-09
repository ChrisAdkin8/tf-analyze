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
exports.RuleExplainerPanel = void 0;
const vscode = __importStar(require("vscode"));
const cp = __importStar(require("child_process"));
const scriptResolver_1 = require("./scriptResolver");
const urls_1 = require("./urls");
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
class RuleExplainerPanel {
    static createOrShow(context, ruleId) {
        const col = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
        const existing = RuleExplainerPanel.panels.get(ruleId);
        if (existing) {
            existing._panel.reveal(col);
            return;
        }
        const panel = vscode.window.createWebviewPanel(`tfAnalyzeExplain:${ruleId}`, `tf-analyze: ${ruleId}`, col, { enableScripts: false, retainContextWhenHidden: true });
        RuleExplainerPanel.panels.set(ruleId, new RuleExplainerPanel(panel, context, ruleId));
    }
    constructor(panel, _context, ruleId) {
        this._panel = panel;
        this._ruleId = ruleId;
        this._panel.onDidDispose(() => {
            RuleExplainerPanel.panels.delete(ruleId);
        });
        this._panel.webview.html = this._loading();
        this._refresh();
    }
    _refresh() {
        if (!/^[A-Z][A-Z0-9-]{2,63}$/.test(this._ruleId)) {
            // Reject anything that doesn't look like a catalogue ID before
            // shelling out — defense against URI-handler injection from
            // untrusted browser-side links.
            this._panel.webview.html = this._error('Invalid rule ID', `<p>The rule ID <code>${this._escape(this._ruleId)}</code> doesn't match the expected pattern. ` +
                'Catalogue IDs are uppercase letters, digits, and hyphens (e.g. <code>SEC-AWS-IAM-001</code>).</p>');
            return;
        }
        const cfg = vscode.workspace.getConfiguration('tf-analyze');
        const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
        const absScript = (0, scriptResolver_1.resolveScriptPath)(cfg, wsFolder);
        if (!absScript) {
            this._panel.webview.html = this._error('detect.py not found', 'Set <code>tf-analyze.scriptPath</code> or open the tf-analyze project as part of your workspace.');
            return;
        }
        const argv = [absScript, '--explain', this._ruleId];
        cp.execFile('python3', argv, { maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
            const errCode = err?.code;
            if (typeof errCode === 'number' && errCode > 1) {
                this._panel.webview.html = this._error(`Couldn't load ${this._ruleId}`, `<p><strong>Exit code:</strong> ${errCode}</p>` +
                    `<pre>${this._escape(stderr || (err && err.message) || '(empty)')}</pre>`);
                return;
            }
            this._panel.webview.html = this._render(stdout || '');
        });
    }
    _render(text) {
        const docsUrl = (0, urls_1.ruleDocsUrl)(this._ruleId);
        const escaped = this._escape(text)
            // Promote `## Section` headings to <h2>
            .replace(/^## (.+)$/gm, '<h2>$1</h2>')
            // First line `# RULE-ID — title` to <h1>
            .replace(/^# (.+)$/gm, '<h1>$1</h1>')
            // Cross-link any other rule IDs in the body to their docs pages.
            .replace(/\b((?:SEC|ROB|STK|OPS|MOD|COST|INT|CI|STYLE|CUSTOM)-[A-Z0-9-]+)\b/g, (_m, id) => id === this._ruleId ? id : `<a href="${(0, urls_1.ruleDocsUrl)(id)}">${id}</a>`);
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
</style></head><body>
<div class="toolbar"><a href="${docsUrl}" target="_blank" rel="noopener">📖 Open full rule docs in browser →</a></div>
<pre>${escaped}</pre>
</body></html>`;
    }
    _escape(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    _loading() {
        return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif"><p>Loading ${this._escape(this._ruleId)}…</p></body></html>`;
    }
    _error(title, body) {
        return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;padding:24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:13px;line-height:1.5">
<h2 style="color:#e53e3e;margin-top:0">${this._escape(title)}</h2>
<div>${body}</div>
</body></html>`;
    }
}
exports.RuleExplainerPanel = RuleExplainerPanel;
RuleExplainerPanel.panels = new Map();
//# sourceMappingURL=ruleExplainer.js.map