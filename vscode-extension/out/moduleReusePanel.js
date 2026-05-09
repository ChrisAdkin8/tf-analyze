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
exports.ModuleReusePanel = void 0;
const vscode = __importStar(require("vscode"));
const cp = __importStar(require("child_process"));
const scriptResolver_1 = require("./scriptResolver");
const urls_1 = require("./urls");
/**
 * Module-reuse advisory view. Runs `detect.py --show-info --format json`,
 * filters findings to the `module-reuse` section, and groups them by
 * registry module so reviewers see at a glance which directories are
 * candidates for replacement by community modules.
 *
 * Findings are INFO-tier — advisory only, no CI gate. They never move
 * the risk score (weight 0).
 */
class ModuleReusePanel {
    static createOrShow(context) {
        const col = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
        if (ModuleReusePanel.currentPanel) {
            ModuleReusePanel.currentPanel._panel.reveal(col);
            ModuleReusePanel.currentPanel._refresh();
            return;
        }
        const panel = vscode.window.createWebviewPanel('tfAnalyzeModuleReuse', 'tf-analyze: Module Reuse', col, { enableScripts: false, retainContextWhenHidden: true });
        ModuleReusePanel.currentPanel = new ModuleReusePanel(panel, context);
    }
    constructor(panel, _context) {
        this._panel = panel;
        this._panel.onDidDispose(() => {
            ModuleReusePanel.currentPanel = undefined;
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
        const argv = [absScript, '--target', wsFolder, '--format', 'json', '--show-info'];
        cp.execFile('python3', argv, { maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
            const errCode = err?.code;
            const exitGtOne = typeof errCode === 'number' && errCode > 1;
            const cmdLine = `python3 ${argv.slice(1).map(a => /\s/.test(a) ? `"${a}"` : a).join(' ')}`;
            if (exitGtOne || !stdout) {
                this._panel.webview.html = this._error('detect.py failed', `<p><strong>Exit code:</strong> ${errCode ?? '(none)'}</p>` +
                    `<p><strong>stderr:</strong></p><pre>${this._escape(stderr || (err && err.message) || '(empty)')}</pre>` +
                    `<p><strong>Command:</strong> <code>${this._escape(cmdLine)}</code></p>`);
                return;
            }
            let parsed;
            try {
                parsed = JSON.parse(stdout);
            }
            catch (parseErr) {
                this._panel.webview.html = this._error('Output was not valid JSON', `<pre>${this._escape(String(parseErr))}</pre>`);
                return;
            }
            const findings = (parsed.findings ?? []).filter(f => f.section === 'module-reuse' || f.id.startsWith('MOD-REUSE-'));
            this._panel.webview.html = this._render(findings);
        });
    }
    _render(findings) {
        if (findings.length === 0) {
            return this._empty();
        }
        // Group by rule id (= one community module per rule).
        const grouped = new Map();
        for (const f of findings) {
            if (!grouped.has(f.id))
                grouped.set(f.id, []);
            grouped.get(f.id).push(f);
        }
        const sections = [];
        for (const [ruleId, hits] of [...grouped.entries()].sort(([a], [b]) => a.localeCompare(b))) {
            const title = hits[0].title;
            const registryUrl = hits[0].registry_url;
            const docsUrl = (0, urls_1.ruleDocsUrl)(ruleId);
            const rows = hits.map(h => {
                const conf = (h.confidence ?? 'medium').toLowerCase();
                const fileShort = h.file.split('/').slice(-2).join('/');
                const roiCell = h.roi && h.roi.lines_saved > 0
                    ? `<span class="roi" title="${h.roi.bespoke_lines} bespoke lines vs. ~${h.roi.replacement_lines} for a module call">~${h.roi.lines_saved} lines (${h.roi.pct_saved}%)</span>`
                    : '<span class="roi-none">—</span>';
                return `<tr>
          <td><span class="conf conf-${conf}">${conf}</span></td>
          <td><code>${this._escape(fileShort)}:${h.line}</code></td>
          <td><code>${this._escape(h.resource ?? '')}</code></td>
          <td class="roi-cell">${roiCell}</td>
          <td class="ctx">${this._escape(h.context ?? '')}</td>
        </tr>`;
            }).join('');
            // Aggregate ROI summary across all hits for this module.
            const totalSaved = hits.reduce((s, h) => s + (h.roi?.lines_saved ?? 0), 0);
            const matchSummary = totalSaved > 0
                ? `<p class="match-summary">~${totalSaved} lines saved across ${hits.length} match${hits.length !== 1 ? 'es' : ''} by adopting this module.</p>`
                : '';
            sections.push(`<section>
        <h2>
          <a class="rule-id" href="${docsUrl}" target="_blank" rel="noopener" title="Open rule docs">${ruleId}</a>
          <span class="title">${this._escape(title)}</span>
          <span class="badge u-info">INFO</span>
        </h2>
        ${registryUrl ? `<p class="registry">📦 <a href="${registryUrl}" target="_blank" rel="noopener"><code>${this._escape(this._extractModuleName(registryUrl))}</code></a></p>` : ''}
        ${matchSummary}
        <table>
          <thead><tr><th>Confidence</th><th>Location</th><th>Anchor</th><th>Lines saved</th><th>Match details</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </section>`);
        }
        return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
  body { margin: 0; background: #1e1e1e; color: #ccc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 13px; padding: 24px; line-height: 1.5; }
  h1 { font-size: 17px; color: #e1e1e1; margin: 0 0 4px; }
  .lede { color: #999; font-size: 12px; margin-bottom: 24px; }
  section { margin: 28px 0; padding-top: 12px; border-top: 1px solid #3c3c3c; }
  section:first-of-type { border-top: none; }
  h2 { font-size: 14px; color: #ddd; margin: 0 0 6px; display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
  h2 .title { color: #bbb; font-weight: normal; font-size: 13px; }
  .badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; }
  .u-info { background: #4A90D9; color: #fff; }
  .registry { margin: 4px 0 12px; font-size: 12px; }
  .registry code { font-size: 12px; }
  a { color: #4daafc; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .rule-id { color: #ccc; border-bottom: 1px dotted #555; }
  .rule-id:hover { color: #4daafc; border-bottom-color: #4daafc; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { text-align: left; padding: 6px 8px; color: #999; font-weight: 600; border-bottom: 1px solid #3c3c3c; }
  td { padding: 6px 8px; border-bottom: 1px solid #2a2a2a; vertical-align: top; }
  td.ctx { color: #888; font-size: 11px; }
  code { font-family: ui-monospace, Menlo, monospace; font-size: 12px; background: #2a2a2a; padding: 1px 4px; border-radius: 2px; }
  .conf { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; text-transform: uppercase; }
  .conf-high { background: #2d6a3a; color: #d4f4d8; }
  .conf-medium { background: #c27a00; color: #ffe6b3; }
  .conf-low { background: #555; color: #ccc; }
  .match-summary { margin: 6px 0 12px; padding: 8px 12px; background: #2a3340; border-left: 3px solid #4daafc; border-radius: 0 3px 3px 0; color: #cfe6ff; font-size: 12px; }
  td.roi-cell { white-space: nowrap; }
  .roi { color: #7fd99c; font-weight: 600; }
  .roi-none { color: #555; }
</style></head><body>
<h1>Module Reuse Advisor</h1>
<p class="lede">Directories whose resource cluster matches the shape of a popular community module on the Terraform Registry. Findings are advisory (INFO tier) — bespoke implementations are sometimes deliberate.</p>
${sections.join('\n')}
</body></html>`;
    }
    _extractModuleName(url) {
        // .../modules/<ns>/<mod>/<provider>/latest -> <ns>/<mod>/<provider>
        const m = /modules\/([^/]+)\/([^/]+)\/([^/]+)/.exec(url);
        return m ? `${m[1]}/${m[2]}/${m[3]}` : url;
    }
    _escape(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    _loading() {
        return '<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif"><p>Scanning for module-reuse opportunities…</p></body></html>';
    }
    _empty() {
        return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;padding:32px;font-family:-apple-system,sans-serif;font-size:13px;line-height:1.5">
<h1 style="font-size:17px;color:#e1e1e1;margin:0 0 8px">Module Reuse Advisor</h1>
<p style="color:#999;margin:0 0 24px">No module-reuse opportunities detected in this workspace.</p>
<div style="background:#2a2a2a;border-left:3px solid #4A90D9;padding:12px 16px;border-radius:0 4px 4px 0">
  <p style="margin:0 0 8px"><strong>What this looks for</strong></p>
  <p style="margin:0;color:#bbb;font-size:12px">Directories whose resource clusters match the shape of well-known community modules (AWS VPC, GCP network, Azure AKS, …). Pure greenfield projects often have no matches.</p>
</div>
</body></html>`;
    }
    _error(title, body) {
        return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;padding:24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:13px;line-height:1.5">
<h2 style="color:#e53e3e;margin-top:0">${this._escape(title)}</h2>
<div>${body}</div>
</body></html>`;
    }
}
exports.ModuleReusePanel = ModuleReusePanel;
//# sourceMappingURL=moduleReusePanel.js.map