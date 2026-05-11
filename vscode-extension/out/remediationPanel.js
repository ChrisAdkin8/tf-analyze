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
exports.RemediationPanel = void 0;
const vscode = __importStar(require("vscode"));
const scriptResolver_1 = require("./scriptResolver");
const engineRunner_1 = require("./engineRunner");
/** Remediation panel: bulk apply-fixes UX.
 *
 * The panel runs `detect.py --apply-fixes dry-run` to produce a unified
 * diff of every fix the engine would make, renders it inline with
 * basic syntax highlighting, and offers an **Apply Fixes** button that
 * re-runs with `--apply-fixes apply` (which writes the patched files
 * to disk and creates `.bak` backups alongside them).
 *
 * Two-stage UX is deliberate — *apply* mutates source files, so the
 * user must see the diff first. Same diagnostic shape as every other
 * panel: empty stdout / exit > 1 surfaces stderr + the reproduction
 * command rather than rendering blank.
 */
class RemediationPanel {
    static createOrShow(context) {
        const col = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
        if (RemediationPanel.currentPanel) {
            RemediationPanel.currentPanel._panel.reveal(col);
            RemediationPanel.currentPanel._refresh();
            return;
        }
        const panel = vscode.window.createWebviewPanel('tfAnalyzeRemediation', 'tf-analyze: Remediate', col, { enableScripts: true, retainContextWhenHidden: true });
        RemediationPanel.currentPanel = new RemediationPanel(panel, context);
    }
    constructor(panel, _context) {
        this._panel = panel;
        this._panel.onDidDispose(() => {
            RemediationPanel.currentPanel = undefined;
        });
        // Audit follow-up #1 — capture the disposable returned by
        // `onDidReceiveMessage` and dispose it when the panel closes.
        // Previously the handler stayed in memory after the panel was
        // closed; opening + closing the same panel many times in a
        // session leaked subscriptions.
        const msgSub = this._panel.webview.onDidReceiveMessage((msg) => {
            if (msg?.command === 'apply') {
                void this._apply();
            }
            else if (msg?.command === 'refresh') {
                this._refresh();
            }
        });
        this._panel.onDidDispose(() => msgSub.dispose());
        this._panel.webview.html = this._loading('Computing the diff…');
        this._refresh();
    }
    _runEngine(mode, cb) {
        const cfg = vscode.workspace.getConfiguration('tf-analyze');
        const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
        const absScript = (0, scriptResolver_1.resolveScriptPath)(cfg, wsFolder);
        if (!absScript) {
            this._panel.webview.html = this._error('detect.py not found', 'Set <code>tf-analyze.scriptPath</code> or open the tf-analyze project as part of your workspace.<br><br>Looked in:<ul>' +
                (0, scriptResolver_1.defaultSearchPaths)(wsFolder).map(p => `<li><code>${this._escape(p)}</code></li>`).join('') + '</ul>');
            return;
        }
        (0, engineRunner_1.runEngine)(absScript, ['--target', wsFolder, '--apply-fixes', mode], cb);
    }
    _refresh() {
        this._runEngine('dry-run', ({ err, stdout, stderr, cmdLine, timedOut }) => {
            const errCode = err?.code;
            const exitGtOne = typeof errCode === 'number' && errCode > 1;
            const stdoutEmpty = !stdout || !stdout.trim();
            if (exitGtOne || timedOut) {
                this._panel.webview.html = this._error(timedOut ? 'detect.py timed out' : 'detect.py failed', `<p><strong>Exit code:</strong> ${errCode ?? '(none)'}</p>` +
                    `<p><strong>stderr:</strong></p><pre>${this._escape(stderr || (err && err.message) || '(empty)')}</pre>` +
                    `<p><strong>Command:</strong> <code>${this._escape(cmdLine)}</code></p>`);
                return;
            }
            const { diffOnly, hasFix } = this._splitDiffFromSummary(stdout);
            if (!hasFix || stdoutEmpty) {
                this._panel.webview.html = this._renderEmpty(stdout, cmdLine);
                return;
            }
            this._panel.webview.html = this._renderDiff(diffOnly, cmdLine);
        });
    }
    /** The engine prints unified-diff blocks, then a one-line summary
     * (`# tf-analyze: 24 (F) · ...`), then a flat list of finding refs.
     * For the panel we only render the diff itself; the summary rows
     * carry no remediation value once the diff is in front of the user.
     * Returns `hasFix=true` iff at least one `--- file` block was found. */
    _splitDiffFromSummary(out) {
        const lines = out.split('\n');
        const cut = [];
        let hasFix = false;
        for (const line of lines) {
            if (line.startsWith('# tf-analyze:'))
                break;
            if (line.startsWith('--- '))
                hasFix = true;
            cut.push(line);
        }
        return { diffOnly: cut.join('\n').trimEnd(), hasFix };
    }
    async _apply() {
        const choice = await vscode.window.showWarningMessage('Apply tf-analyze fixes? This rewrites .tf files on disk. Originals will be saved as <file>.bak alongside each patched file.', { modal: true }, 'Apply');
        if (choice !== 'Apply')
            return;
        this._panel.webview.html = this._loading('Applying fixes…');
        this._runEngine('apply', ({ err, stdout, stderr, cmdLine, timedOut }) => {
            const errCode = err?.code;
            const exitGtOne = typeof errCode === 'number' && errCode > 1;
            if (exitGtOne || timedOut) {
                this._panel.webview.html = this._error(timedOut ? 'Apply timed out' : 'Apply failed', `<p><strong>Exit code:</strong> ${errCode ?? '(none)'}</p>` +
                    `<p><strong>stderr:</strong></p><pre>${this._escape(stderr || (err && err.message) || '(empty)')}</pre>` +
                    `<p><strong>Command:</strong> <code>${this._escape(cmdLine)}</code></p>`);
                return;
            }
            // Engine emits the same unified-diff format on apply, plus a
            // summary line. We re-show the diff as an "applied" report and
            // tell the user where backups landed.
            const { diffOnly } = this._splitDiffFromSummary(stdout);
            this._panel.webview.html = this._renderApplied(diffOnly);
            void vscode.window.showInformationMessage('tf-analyze: fixes applied. Originals saved as <file>.bak alongside each patched file.');
        });
    }
    _renderDiff(diff, cmdLine) {
        return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
  ${this._sharedCss()}
  #diff { font-family: ui-monospace, Menlo, monospace; font-size: 12px; line-height: 1.5; padding: 16px 24px; white-space: pre; overflow: auto; }
  .file-hdr { color: #d4a017; font-weight: 600; padding-top: 14px; }
  .hunk-hdr { color: #888; }
  .add { color: #6BBF84; background: rgba(107, 191, 132, 0.07); }
  .del { color: #e57373; background: rgba(229, 115, 115, 0.07); }
  .ctx { color: #aaa; }
</style></head><body>
<div id="toolbar">
  <span class="label">Preview (dry run) — no files modified yet</span>
  <span style="flex:1"></span>
  <button onclick="refresh()">Refresh</button>
  <button class="primary" onclick="apply()">Apply Fixes</button>
</div>
<div id="diff">${this._highlightDiff(diff)}</div>
<div id="footer">
  <span class="label">Command:</span> <code>${this._escape(cmdLine)}</code>
</div>
<script>
  const vscode = acquireVsCodeApi();
  function apply() { vscode.postMessage({ command: 'apply' }); }
  function refresh() { vscode.postMessage({ command: 'refresh' }); }
</script>
</body></html>`;
    }
    _renderApplied(diff) {
        return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
  ${this._sharedCss()}
  #diff { font-family: ui-monospace, Menlo, monospace; font-size: 12px; line-height: 1.5; padding: 16px 24px; white-space: pre; overflow: auto; }
  .file-hdr { color: #d4a017; font-weight: 600; padding-top: 14px; }
  .hunk-hdr { color: #888; }
  .add { color: #6BBF84; background: rgba(107, 191, 132, 0.07); }
  .del { color: #e57373; background: rgba(229, 115, 115, 0.07); }
  .ctx { color: #aaa; }
  .banner { background: #1f3d2a; border-left: 3px solid #6BBF84; padding: 10px 16px; color: #cfe9d7; }
</style></head><body>
<div id="toolbar">
  <span class="label" style="color:#6BBF84">✓ Fixes applied. Originals saved as &lt;file&gt;.bak.</span>
  <span style="flex:1"></span>
  <button onclick="refresh()">Re-scan</button>
</div>
<div class="banner">Review the patched files in your editor and run <code>tf-analyze: Run Scan</code> (or just save) to confirm findings cleared. If anything looks wrong, restore from the <code>.bak</code> sibling.</div>
<div id="diff">${this._highlightDiff(diff)}</div>
<script>
  const vscode = acquireVsCodeApi();
  function refresh() { vscode.postMessage({ command: 'refresh' }); }
</script>
</body></html>`;
    }
    _renderEmpty(rawOutput, cmdLine) {
        return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>${this._sharedCss()}
  .empty { padding: 32px 24px; color: #ccc; font-size: 13px; line-height: 1.6; }
  .empty h2 { color: #6BBF84; margin: 0 0 8px; }
  pre { background: #252526; padding: 10px; border-radius: 4px; font-size: 11px; }
</style></head><body>
<div id="toolbar">
  <span class="label">No fixable findings</span>
  <span style="flex:1"></span>
  <button onclick="refresh()">Refresh</button>
</div>
<div class="empty">
  <h2>Nothing to remediate</h2>
  <p>The engine has no auto-fixable findings to patch in this workspace. Common reasons:</p>
  <ul>
    <li>The findings present don't carry <code>fix_hcl</code> snippets in the catalogue (mostly absent-resource and provider-config rules).</li>
    <li>The workspace already has zero findings (well done).</li>
    <li>The <code>--apply-fixes</code> path only patches <code>resource_missing_arg</code> and <code>resource_arg / hcl_attr</code> patterns — other patterns are left for the in-editor Quick Fix flow.</li>
  </ul>
  <details style="margin-top:14px"><summary style="cursor:pointer;color:#888">Engine output</summary>
    <pre>${this._escape(rawOutput.slice(0, 2000))}</pre>
  </details>
  <p style="color:#888;font-size:11px;margin-top:18px">Command: <code>${this._escape(cmdLine)}</code></p>
</div>
<script>
  const vscode = acquireVsCodeApi();
  function refresh() { vscode.postMessage({ command: 'refresh' }); }
</script>
</body></html>`;
    }
    /** Tokenise unified-diff lines into spans the CSS classes light up.
     * Operates on the already-escaped string so tag injection isn't a
     * concern — `<` / `>` are already entities by the time we're here. */
    _highlightDiff(diff) {
        const escaped = this._escape(diff);
        return escaped
            .split('\n')
            .map(line => {
            if (line.startsWith('--- ') || line.startsWith('+++ '))
                return `<span class="file-hdr">${line}</span>`;
            if (line.startsWith('@@'))
                return `<span class="hunk-hdr">${line}</span>`;
            if (line.startsWith('+'))
                return `<span class="add">${line}</span>`;
            if (line.startsWith('-'))
                return `<span class="del">${line}</span>`;
            return `<span class="ctx">${line}</span>`;
        })
            .join('\n');
    }
    _sharedCss() {
        return `
  body { margin: 0; background: #1e1e1e; color: #ccc; font-family: -apple-system, BlinkMacSystemFont, sans-serif; height: 100vh; display: flex; flex-direction: column; }
  #toolbar { padding: 6px 12px; background: #252526; border-bottom: 1px solid #3c3c3c; display: flex; align-items: center; gap: 8px; font-size: 12px; }
  #toolbar .label { color: #888; }
  #toolbar button { background: #3a3d41; border: 1px solid #555; color: #ccc; padding: 4px 10px; border-radius: 3px; cursor: pointer; font-size: 11px; }
  #toolbar button:hover { background: #4a4d51; }
  #toolbar button.primary { background: #5c6bc0; border-color: #5c6bc0; color: #fff; }
  #toolbar button.primary:hover { background: #6e7bd1; }
  #footer { padding: 8px 24px; background: #252526; border-top: 1px solid #3c3c3c; color: #888; font-size: 11px; }
  #footer .label { color: #666; }
    `;
    }
    _escape(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    _loading(msg) {
        return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif"><p>${this._escape(msg)}</p></body></html>`;
    }
    _error(title, body) {
        return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;padding:24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:13px;line-height:1.5">
<h2 style="color:#e53e3e;margin-top:0">${this._escape(title)}</h2>
<div>${body}</div>
</body></html>`;
    }
}
exports.RemediationPanel = RemediationPanel;
//# sourceMappingURL=remediationPanel.js.map