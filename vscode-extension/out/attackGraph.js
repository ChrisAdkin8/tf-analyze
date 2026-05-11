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
exports.AttackGraphPanel = void 0;
const vscode = __importStar(require("vscode"));
const cp = __importStar(require("child_process"));
const scriptResolver_1 = require("./scriptResolver");
class AttackGraphPanel {
    static createOrShow(context) {
        const col = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
        if (AttackGraphPanel.currentPanel) {
            AttackGraphPanel.currentPanel._panel.reveal(col);
            AttackGraphPanel.currentPanel._refresh();
            return;
        }
        const panel = vscode.window.createWebviewPanel('tfAnalyzeAttackGraph', 'tf-analyze: Attack Graph', col, { enableScripts: true, retainContextWhenHidden: true });
        AttackGraphPanel.currentPanel = new AttackGraphPanel(panel, context);
    }
    constructor(panel, context) {
        this._panel = panel;
        this._context = context;
        this._panel.onDidDispose(() => {
            AttackGraphPanel.currentPanel = undefined;
        });
        this._panel.webview.html = this._getLoadingHtml();
        this._refresh();
    }
    _refresh() {
        const cfg = vscode.workspace.getConfiguration('tf-analyze');
        const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
        const absScript = (0, scriptResolver_1.resolveScriptPath)(cfg, wsFolder);
        if (!absScript) {
            this._panel.webview.html = this._getErrorHtml("detect.py not found", "Set <code>tf-analyze.scriptPath</code> in settings to the absolute path of " +
                "<code>scripts/detect.py</code>, or open the tf-analyze project as part of your " +
                "workspace.\n\nLooked in: " + (0, scriptResolver_1.defaultSearchPaths)(wsFolder).map(p => `<li><code>${p}</code></li>`).join(""));
            return;
        }
        // Audit item 30 — `cp.exec` with a template-literal command lets a
        // workspace path containing backticks or double-quotes inject
        // arbitrary shell. `execFile` passes argv directly to the kernel:
        // no shell, no interpolation, no escape gymnastics.
        cp.execFile('python3', [absScript, '--target', wsFolder, '--format', 'json', '--attack-graph'], { maxBuffer: 20 * 1024 * 1024 }, (err, stdout, stderr) => {
            // exit 1 = findings exist (expected); exit > 1 = real error.
            // BUT: Python emits exit 1 for any unhandled exception, with a
            // traceback on stderr and empty stdout. Don't conflate the two —
            // an empty/non-JSON stdout means detect.py crashed before emitting,
            // regardless of the exit code, and stderr is the only useful clue.
            const errCode = err?.code;
            const exitGtOne = typeof errCode === "number" && errCode > 1;
            const stdoutEmpty = !stdout || !stdout.trim();
            const cmdLine = `python3 ${absScript} --target ${wsFolder} --format json --attack-graph`;
            if (exitGtOne || stdoutEmpty) {
                const reason = stdoutEmpty && !exitGtOne
                    ? "detect.py exited without printing JSON. Most often this is an unhandled Python exception — see stderr below."
                    : "detect.py exited with an error.";
                this._panel.webview.html = this._getErrorHtml("detect.py failed", `<p>${this._escape(reason)}</p>` +
                    `<p><strong>Exit code:</strong> ${errCode ?? "(none)"}</p>` +
                    `<p><strong>stderr:</strong></p><pre>${this._escape(stderr || (err && err.message) || "(empty)")}</pre>` +
                    `<p><strong>Command:</strong> <code>${this._escape(cmdLine)}</code></p>` +
                    `<p>Re-run the command in a terminal to see the full traceback.</p>`);
                return;
            }
            let data = {};
            try {
                data = JSON.parse(stdout);
            }
            catch (parseErr) {
                this._panel.webview.html = this._getErrorHtml("Could not parse detect.py output", `<pre>${this._escape(parseErr.message)}</pre>` +
                    `<p><strong>stderr:</strong></p><pre>${this._escape(stderr || "(empty)")}</pre>` +
                    `<p><strong>First 500 chars of stdout:</strong></p><pre>${this._escape(stdout.slice(0, 500))}</pre>` +
                    `<p><strong>Command:</strong> <code>${this._escape(cmdLine)}</code></p>`);
                return;
            }
            // The engine emits the graph under the top-level `graph` key
            // (since Round 25). Older builds used `attack_graph`; check both
            // for backwards-compat with users running pinned older detect.py.
            const graph = data.graph ?? data.attack_graph ?? { nodes: [], edges: [] };
            // Treat "only the synthetic INTERNET entry node and no edges" as
            // empty — otherwise the webview renders a lone red dot which users
            // (rightly) call empty. Common cause: the workspace root contains
            // no .tf resources (e.g. a parent folder, the extension subfolder,
            // or a project-of-modules where resources live in submodules).
            const realNodes = (graph.nodes ?? []).filter(n => n.id !== 'INTERNET');
            if (realNodes.length === 0 || (graph.edges ?? []).length === 0) {
                this._panel.webview.html = this._getErrorHtml("Empty attack graph", `<p><strong>Scanned:</strong> <code>${this._escape(wsFolder)}</code></p>` +
                    `<p>The scan completed but produced no attack paths. Most common causes:</p>` +
                    "<ol>" +
                    "<li><b>The workspace root has no <code>.tf</code> files with resources.</b> If your Terraform code lives in a subfolder, open that subfolder as the workspace root, or add it to a multi-root workspace.</li>" +
                    "<li><b>No resource is internet-reachable.</b> The graph starts from internet entry points (public LBs, public S3, security groups with <code>0.0.0.0/0</code>) and walks toward crown jewels (RDS, KMS, Secrets, etc.). With no entry point, there's no path to draw.</li>" +
                    "<li><b>The files only declare modules, providers, or data sources.</b> The engine builds nodes from <code>resource</code> blocks, not <code>module</code> calls — open the module's own folder.</li>" +
                    "</ol>" +
                    `<p>Quick sanity check: <code>python3 detect.py --target ${this._escape(wsFolder)} --format json --attack-graph</code> in a terminal should print the same node count.</p>` +
                    `<p>Try the bundled demo: open <code>fixtures/attack_graph_demo/</code> from the tf-analyze repo as your workspace and re-run — that produces 8 nodes / 5 edges.</p>`);
                return;
            }
            // Derive critical-path edges by walking consecutive node pairs in
            // the graph.critical_path array. The engine exports the path as
            // node IDs; the webview wants per-edge `is_critical: true` for
            // styling.
            const critPairs = new Set();
            const cp_ = graph.critical_path ?? [];
            for (let i = 0; i < cp_.length - 1; i++) {
                critPairs.add(`${cp_[i]}->${cp_[i + 1]}`);
            }
            for (const e of graph.edges) {
                e.is_critical = critPairs.has(`${e.from}->${e.to}`);
            }
            this._panel.webview.html = this._getHtml(graph);
        });
    }
    _escape(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    _getErrorHtml(title, body) {
        return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;padding:24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:13px;line-height:1.5">
<h2 style="color:#e53e3e;margin-top:0">${this._escape(title)}</h2>
<div>${body}</div>
<p style="margin-top:24px;color:#888">Re-run with <code>tf-analyze: Show Attack Graph</code> after fixing the issue.</p>
</body></html>`;
    }
    _getLoadingHtml() {
        return `<!DOCTYPE html><html><body style="background:#1e1e1e;color:#ccc;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif"><p>Building attack graph…</p></body></html>`;
    }
    _getHtml(graph) {
        // Audit item 1 — also defend against a `</script>` sequence inside
        // a JSON string field (label, finding ID, etc.) breaking out of
        // the inline script tag. JSON.stringify does not escape `/`; we
        // replace `</` with `<\/` so the bytes are still valid JSON-as-JS
        // but cannot terminate the surrounding <script>…</script>.
        const safeJson = (v) => JSON.stringify(v).replace(/<\/(script)/gi, '<\\/$1');
        const nodesJson = safeJson(graph.nodes);
        const edgesJson = safeJson(graph.edges);
        return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<!-- Audit item 1 (defence-in-depth): CSP narrows what the webview can
     execute even if the field-escape regression returns. d3 lives on
     d3js.org over HTTPS so we allow that origin explicitly; everything
     else falls back to the webview's own origin. -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; script-src 'unsafe-inline' https://d3js.org; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none';">
<style>
  body { margin: 0; background: #1e1e1e; color: #ccc; font-family: -apple-system, BlinkMacSystemFont, sans-serif; overflow: hidden; }
  #container { display: flex; height: 100vh; }
  #graph-area { flex: 1; position: relative; }
  svg { width: 100%; height: 100%; }
  #sidebar { width: 260px; background: #252526; padding: 12px; overflow-y: auto; border-left: 1px solid #3c3c3c; font-size: 12px; }
  #sidebar h3 { margin: 0 0 8px; font-size: 13px; color: #e1e1e1; }
  .finding-chip { background: #3a3d41; border-radius: 3px; padding: 2px 6px; margin: 2px 2px 2px 0; display: inline-block; font-size: 11px; }
  .badge { font-size: 10px; padding: 1px 5px; border-radius: 2px; margin-left: 4px; }
  .badge-cj { background: #b8860b; color: #fff; }
  .badge-inet { background: #c0392b; color: #fff; }
  #toolbar { position: absolute; top: 8px; right: 8px; display: flex; gap: 6px; }
  button { background: #3a3d41; border: 1px solid #555; color: #ccc; padding: 4px 10px; border-radius: 3px; cursor: pointer; font-size: 11px; }
  button:hover { background: #4a4d51; }
  .node circle { cursor: pointer; transition: stroke-width 0.15s; }
  .node circle:hover { stroke-width: 3; }
  .node text { font-size: 9px; fill: #ddd; pointer-events: none; }
  .link { fill: none; marker-end: url(#arrow); }
  .link.critical { stroke: #e53e3e; stroke-width: 2.5; }
  .link.normal { stroke: #555; stroke-width: 1.2; }
  @keyframes pulse { 0%,100%{stroke-opacity:1} 50%{stroke-opacity:0.3} }
  .inet-pulse { animation: pulse 2s ease-in-out infinite; }
</style>
</head>
<body>
<div id="container">
  <div id="graph-area">
    <div id="toolbar">
      <button onclick="exportSvg()">Export SVG</button>
      <button onclick="resetZoom()">Reset</button>
    </div>
    <svg id="svg">
      <defs>
        <marker id="arrow" markerWidth="8" markerHeight="8" refX="16" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#555"/>
        </marker>
        <marker id="arrow-critical" markerWidth="8" markerHeight="8" refX="16" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#e53e3e"/>
        </marker>
      </defs>
      <g id="root"></g>
    </svg>
  </div>
  <div id="sidebar">
    <h3>Attack Graph</h3>
    <div id="node-detail"><p style="color:#888">Click a node to inspect</p></div>
  </div>
</div>
<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
const nodes = ${nodesJson};
// The engine emits edges as { from, to, label } but d3.forceLink reads
// { source, target } and resolves them via .id(d => d.id). Without this
// aliasing d3 sees source=undefined / target=undefined on every link
// and throws "node not found: undefined" inside d3.v7.min.js.
const edges = ${edgesJson}.map(e => ({ ...e, source: e.from, target: e.to }));

const COLOR = {
  compute: '#4A90D9', storage: '#E8A838', iam: '#D4A017',
  network: '#7B9EA6', key: '#6BBF84', secret: '#6BBF84',
  internet: '#E53E3E', unknown: '#888'
};

const svg = d3.select('#svg');
const root = d3.select('#root');
const width = () => document.getElementById('graph-area').clientWidth;
const height = () => window.innerHeight;

const zoom = d3.zoom().scaleExtent([0.1, 4]).on('zoom', e => root.attr('transform', e.transform));
svg.call(zoom);

function resetZoom() { svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity); }

const sim = d3.forceSimulation(nodes)
  .force('link', d3.forceLink(edges).id(d => d.id).distance(120))
  .force('charge', d3.forceManyBody().strength(-300))
  .force('center', d3.forceCenter(width() / 2, height() / 2))
  .force('collide', d3.forceCollide(30));

const link = root.append('g').selectAll('line')
  .data(edges).join('line')
  .attr('class', d => 'link ' + (d.is_critical ? 'critical' : 'normal'))
  .attr('marker-end', d => d.is_critical ? 'url(#arrow-critical)' : 'url(#arrow)');

const node = root.append('g').selectAll('g')
  .data(nodes).join('g')
  .attr('class', 'node')
  .call(d3.drag()
    .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
    .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
    .on('end', (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }))
  .on('click', (e, d) => showDetail(d));

node.each(function(d) {
  const g = d3.select(this);
  const r = d.is_crown_jewel ? 16 : 10;
  const color = COLOR[d.type] ?? COLOR.unknown;
  // Outer glow ring for internet-reachable
  if (d.internet_reachable) {
    g.append('circle').attr('r', r + 5)
      .attr('fill', 'none').attr('stroke', color).attr('stroke-width', 2)
      .attr('stroke-dasharray', '5,3').attr('class', 'inet-pulse');
  }
  // Crown jewel double ring
  if (d.is_crown_jewel) {
    g.append('circle').attr('r', r + 3)
      .attr('fill', 'none').attr('stroke', '#b8860b').attr('stroke-width', 1.5);
  }
  g.append('circle').attr('r', r)
    .attr('fill', color).attr('stroke', d.on_critical_path ? '#e53e3e' : '#333').attr('stroke-width', d.on_critical_path ? 2.5 : 1);
  g.append('text').text(d.label.split('.').pop()).attr('dy', r + 12).attr('text-anchor', 'middle');
});

sim.on('tick', () => {
  link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
  node.attr('transform', d => \`translate(\${d.x},\${d.y})\`);
});

// Audit item 1 — every engine-supplied field flowing into innerHTML
// must round-trip through HTML-escape, otherwise a Terraform resource
// named  <img src=x onerror=alert(1)> (or any unescaped label, type,
// finding ID, etc.) executes JS in the webview (enableScripts: true).
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showDetail(d) {
  const badges = [
    d.is_crown_jewel ? '<span class="badge badge-cj">Crown Jewel</span>' : '',
    d.internet_reachable ? '<span class="badge badge-inet">Internet-reachable</span>' : '',
  ].join('');
  const findings = d.findings?.length
    ? d.findings.map(f => \`<span class="finding-chip">\${esc(f)}</span>\`).join('')
    : '<span style="color:#888">No findings</span>';
  document.getElementById('node-detail').innerHTML = \`
    <h3>\${esc(d.label)}\${badges}</h3>
    <p><strong>Type:</strong> \${esc(d.type)}</p>
    <p><strong>Findings:</strong><br>\${findings}</p>
  \`;
}

function exportSvg() {
  const svgEl = document.getElementById('svg');
  const blob = new Blob([svgEl.outerHTML], {type: 'image/svg+xml'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = 'attack-graph.svg'; a.click();
}
</script>
</body>
</html>`;
    }
}
exports.AttackGraphPanel = AttackGraphPanel;
//# sourceMappingURL=attackGraph.js.map