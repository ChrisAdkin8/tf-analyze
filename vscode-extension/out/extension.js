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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const cp = __importStar(require("child_process"));
const path = __importStar(require("path"));
const attackGraph_1 = require("./attackGraph");
const htmlReport_1 = require("./htmlReport");
const deltaPanel_1 = require("./deltaPanel");
const compliancePanel_1 = require("./compliancePanel");
const mitrePanel_1 = require("./mitrePanel");
const remediationPanel_1 = require("./remediationPanel");
const scriptResolver_1 = require("./scriptResolver");
const lspClient_1 = require("./lspClient");
const baseline_1 = require("./baseline");
// ─── Tree view ────────────────────────────────────────────────────────────────
class FindingItem extends vscode.TreeItem {
    constructor(finding, collapsibleState) {
        super(`[${finding.urgency}] ${finding.id}`, collapsibleState);
        this.finding = finding;
        this.collapsibleState = collapsibleState;
        this.description = finding.title;
        this.tooltip = finding.recommendation ?? finding.title;
        this.iconPath = urgencyIcon(finding.urgency);
        this.command = {
            command: "tf-analyze.openFinding",
            title: "Open Finding",
            arguments: [finding],
        };
        this.contextValue = "finding";
    }
}
class SectionItem extends vscode.TreeItem {
    constructor(label, findings) {
        super(label, vscode.TreeItemCollapsibleState.Expanded);
        this.label = label;
        this.findings = findings;
        this.description = `${findings.length} finding${findings.length !== 1 ? "s" : ""}`;
        this.iconPath = new vscode.ThemeIcon("folder");
    }
}
function urgencyIcon(urgency) {
    switch (urgency.toUpperCase()) {
        case "CRITICAL": return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
        case "HIGH": return new vscode.ThemeIcon("warning", new vscode.ThemeColor("problemsWarningIcon.foreground"));
        case "MEDIUM": return new vscode.ThemeIcon("info", new vscode.ThemeColor("problemsInfoIcon.foreground"));
        default: return new vscode.ThemeIcon("circle-outline");
    }
}
class FindingsProvider {
    constructor() {
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.findings = [];
        this.scanRunning = false;
    }
    setFindings(findings) {
        this.findings = findings;
        this._onDidChangeTreeData.fire();
    }
    setScanRunning(running) {
        this.scanRunning = running;
        this._onDidChangeTreeData.fire();
    }
    clear() {
        this.findings = [];
        this._onDidChangeTreeData.fire();
    }
    getTreeItem(element) {
        return element;
    }
    getChildren(element) {
        if (this.scanRunning && !element) {
            const item = new vscode.TreeItem("Scanning…");
            item.iconPath = new vscode.ThemeIcon("sync~spin");
            return [item];
        }
        if (!element) {
            if (this.findings.length === 0) {
                const item = new vscode.TreeItem("No findings");
                item.iconPath = new vscode.ThemeIcon("check");
                return [item];
            }
            const sections = [...new Set(this.findings.map((f) => f.section))].sort();
            return sections.map((s) => new SectionItem(s, this.findings.filter((f) => f.section === s)));
        }
        if (element instanceof SectionItem) {
            return element.findings.map((f) => new FindingItem(f, vscode.TreeItemCollapsibleState.None));
        }
        return [];
    }
}
// ─── Diagnostics ──────────────────────────────────────────────────────────────
function urgencyToDiagnosticSeverity(urgency) {
    const cfg = vscode.workspace.getConfiguration("tf-analyze");
    const failOn = cfg.get("failOn") ?? "HIGH";
    const order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const failIdx = order.indexOf(failOn.toUpperCase());
    const findingIdx = order.indexOf(urgency.toUpperCase());
    if (findingIdx >= failIdx)
        return vscode.DiagnosticSeverity.Error;
    if (findingIdx >= order.indexOf("MEDIUM"))
        return vscode.DiagnosticSeverity.Warning;
    return vscode.DiagnosticSeverity.Information;
}
function applyDiagnostics(diagnosticCollection, findings) {
    diagnosticCollection.clear();
    const byFile = new Map();
    for (const f of findings) {
        const absPath = f.file.startsWith("/") ? f.file : path.join(workspacePath(), f.file);
        const uri = vscode.Uri.file(absPath);
        const lineIdx = Math.max(0, f.line - 1);
        const colIdx = Math.max(0, (f.column ?? 1) - 1);
        const range = new vscode.Range(lineIdx, colIdx, lineIdx, colIdx + 1);
        const diag = new vscode.Diagnostic(range, `[${f.id}] ${f.title}`, urgencyToDiagnosticSeverity(f.urgency));
        diag.source = "tf-analyze";
        diag.code = { value: f.id, target: vscode.Uri.parse(`https://github.com/example/tf-analyze`) };
        const key = uri.fsPath;
        if (!byFile.has(key))
            byFile.set(key, []);
        byFile.get(key).push(diag);
    }
    for (const [fsPath, diags] of byFile) {
        diagnosticCollection.set(vscode.Uri.file(fsPath), diags);
    }
}
// ─── Code actions (Quick Fix) ─────────────────────────────────────────────────
class TfAnalyzeCodeActionProvider {
    constructor(findingsMap) {
        this.findingsMap = findingsMap;
    }
    provideCodeActions(document, range, context) {
        const actions = [];
        const filePath = document.uri.fsPath;
        const findings = this.findingsMap.get(filePath) ?? [];
        for (const diag of context.diagnostics) {
            if (diag.source !== "tf-analyze")
                continue;
            const idMatch = /^\[([A-Z0-9-]+)\]/.exec(diag.message);
            if (!idMatch)
                continue;
            const id = idMatch[1];
            const finding = findings.find((f) => f.id === id && f.line === diag.range.start.line + 1);
            if (!finding?.fix_hcl)
                continue;
            const action = new vscode.CodeAction(`tf-analyze: Apply fix for ${id}`, vscode.CodeActionKind.QuickFix);
            action.diagnostics = [diag];
            action.isPreferred = true;
            action.command = {
                command: "tf-analyze.applyFix",
                title: `Apply fix for ${id}`,
                arguments: [document, diag.range, finding],
            };
            actions.push(action);
            const docAction = new vscode.CodeAction(`tf-analyze: View recommendation for ${id}`, vscode.CodeActionKind.Empty);
            docAction.diagnostics = [diag];
            docAction.command = {
                command: "tf-analyze.openFinding",
                title: "View recommendation",
                arguments: [finding],
            };
            actions.push(docAction);
        }
        return actions;
    }
}
// ─── Runner ───────────────────────────────────────────────────────────────────
function workspacePath() {
    return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();
}
function resolveScriptPath() {
    const cfg = vscode.workspace.getConfiguration("tf-analyze");
    return (0, scriptResolver_1.resolveScriptPath)(cfg, workspacePath());
}
function buildArgs(target) {
    const cfg = vscode.workspace.getConfiguration("tf-analyze");
    const args = ["--target", target, "--format", "json"];
    const section = cfg.get("section") ?? "";
    if (section)
        args.push("--section", section);
    // Auto-pin a baseline file if one exists at the workspace root.
    // The engine will then suppress matching findings — this is the
    // sole consumer surface for the baseline UI's writes.
    if ((0, baseline_1.baselineExists)(target)) {
        args.push("--baseline", (0, baseline_1.baselinePath)(target));
    }
    const extra = cfg.get("extraArgs") ?? [];
    args.push(...extra);
    return args;
}
async function runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel) {
    const scriptPath = resolveScriptPath();
    if (!scriptPath) {
        vscode.window.showErrorMessage("tf-analyze: detect.py not found. Set tf-analyze.scriptPath in settings.");
        return;
    }
    const target = workspacePath();
    const args = buildArgs(target);
    provider.setScanRunning(true);
    statusBar.text = "$(sync~spin) tf-analyze scanning…";
    statusBar.show();
    outputChannel.appendLine(`[tf-analyze] Running: python3 ${scriptPath} ${args.join(" ")}`);
    try {
        const result = await new Promise((resolve, reject) => {
            let stdout = "";
            let stderr = "";
            const proc = cp.spawn("python3", [scriptPath, ...args], { cwd: target });
            proc.stdout.on("data", (d) => (stdout += d));
            proc.stderr.on("data", (d) => (stderr += d));
            proc.on("close", (code) => {
                if (stderr)
                    outputChannel.appendLine(`[tf-analyze] stderr: ${stderr}`);
                // exit 1 = findings found, exit 0 = clean — both are valid
                if (code !== null && code > 1) {
                    reject(new Error(`detect.py exited with code ${code}: ${stderr}`));
                }
                else {
                    resolve(stdout);
                }
            });
            proc.on("error", reject);
        });
        let parsed;
        try {
            parsed = JSON.parse(result);
        }
        catch {
            outputChannel.appendLine("[tf-analyze] Failed to parse JSON output. Raw output:");
            outputChannel.appendLine(result.substring(0, 2000));
            throw new Error("tf-analyze output is not valid JSON. Check the Output panel.");
        }
        const findings = parsed.findings ?? [];
        findingsMap.clear();
        for (const f of findings) {
            const key = f.file.startsWith("/") ? f.file : path.join(target, f.file);
            if (!findingsMap.has(key))
                findingsMap.set(key, []);
            findingsMap.get(key).push(f);
        }
        applyDiagnostics(diagnosticCollection, findings);
        provider.setFindings(findings);
        const counts = parsed.summary?.counts ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
        const total = findings.length;
        const label = total === 0
            ? "$(check) tf-analyze: clean"
            : `$(shield) tf-analyze: ${total} (C:${counts.CRITICAL} H:${counts.HIGH} M:${counts.MEDIUM})`;
        statusBar.text = label;
        outputChannel.appendLine(`[tf-analyze] Scan complete: ${total} finding(s)`);
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`tf-analyze: ${msg}`);
        statusBar.text = "$(error) tf-analyze: scan failed";
        outputChannel.appendLine(`[tf-analyze] Error: ${msg}`);
    }
    finally {
        provider.setScanRunning(false);
    }
}
// ─── Activation ───────────────────────────────────────────────────────────────
function activate(context) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection("tf-analyze");
    const findingsMap = new Map();
    const provider = new FindingsProvider();
    const outputChannel = vscode.window.createOutputChannel("tf-analyze");
    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBar.command = "tf-analyze.runScan";
    statusBar.text = "$(shield) tf-analyze";
    statusBar.tooltip = "Click to run tf-analyze scan";
    statusBar.show();
    // Second status-bar item: one-click attack-graph open. Sits immediately
    // to the right of the scan shield (priority 99) so the two read as a
    // pair. Hidden until the workspace contains at least one .tf file —
    // there's nothing useful to graph in a non-Terraform project.
    const graphStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 99);
    graphStatusBar.command = "tf-analyze.showAttackGraph";
    graphStatusBar.text = "$(type-hierarchy) Attack Graph";
    graphStatusBar.tooltip = "tf-analyze: open the internet → crown-jewels attack graph for this workspace";
    // The HTML report intentionally has *no* status-bar item — it
    // overlaps semantically with the Findings tree (same data, different
    // presentation) and we want the toolbar reserved for surfaces that
    // give the user net-new information at a glance. The command is
    // still wired up for the palette and the view/title menu so it stays
    // a click away.
    // Third (was fourth): delta. Most "daily loop" valuable surface —
    // what changed since last scan? Priority 98.
    const deltaStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 98);
    deltaStatusBar.command = "tf-analyze.showDelta";
    deltaStatusBar.text = "$(diff) Delta";
    deltaStatusBar.tooltip = "tf-analyze: show new / resolved / unchanged findings since the most recent prior scan";
    // Fourth: compliance. Priority 97. Heavily-requested by audit users.
    const complianceStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 97);
    complianceStatusBar.command = "tf-analyze.showCompliance";
    complianceStatusBar.text = "$(checklist) Compliance";
    complianceStatusBar.tooltip = "tf-analyze: open the compliance gap report (CIS / PCI DSS / SOC 2)";
    // Fifth: remediate. Bulk apply-fixes UX with two-stage preview/apply
    // flow (writes .bak backups). Priority 96.
    const remediateStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 96);
    remediateStatusBar.command = "tf-analyze.remediate";
    remediateStatusBar.text = "$(wand) Remediate";
    remediateStatusBar.tooltip = "tf-analyze: preview and bulk-apply fix_hcl patches across the workspace (--apply-fixes)";
    // Only surface the shortcuts when there's something to scan.
    void vscode.workspace.findFiles("**/*.tf", "**/node_modules/**", 1).then((found) => {
        if (found.length > 0) {
            graphStatusBar.show();
            deltaStatusBar.show();
            complianceStatusBar.show();
            remediateStatusBar.show();
        }
    });
    const treeView = vscode.window.createTreeView("tfAnalyzeFindings", {
        treeDataProvider: provider,
        showCollapseAll: true,
    });
    const codeActionProvider = new TfAnalyzeCodeActionProvider(findingsMap);
    context.subscriptions.push(diagnosticCollection, outputChannel, statusBar, graphStatusBar, deltaStatusBar, complianceStatusBar, remediateStatusBar, treeView, vscode.languages.registerCodeActionsProvider({ language: "terraform", scheme: "file" }, codeActionProvider, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix, vscode.CodeActionKind.Empty] }), vscode.commands.registerCommand("tf-analyze.runScan", () => runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel)), vscode.commands.registerCommand("tf-analyze.clearFindings", () => {
        diagnosticCollection.clear();
        findingsMap.clear();
        provider.clear();
        statusBar.text = "$(shield) tf-analyze";
    }), vscode.commands.registerCommand("tf-analyze.openFinding", (finding) => {
        const panel = vscode.window.createWebviewPanel("tfAnalyzeFinding", `[${finding.id}] ${finding.title}`, vscode.ViewColumn.Beside, {});
        panel.webview.html = buildFindingHtml(finding);
    }), vscode.commands.registerCommand("tf-analyze.applyFix", async (document, _range, finding) => {
        if (!finding.fix_hcl)
            return;
        const edit = new vscode.WorkspaceEdit();
        const lineIdx = Math.max(0, finding.line - 1);
        const lineText = document.lineAt(lineIdx).text;
        const insertPos = new vscode.Position(lineIdx, lineText.length);
        const fixText = `\n\n# tf-analyze fix for ${finding.id}:\n${finding.fix_hcl}`;
        edit.insert(document.uri, insertPos, fixText);
        const ok = await vscode.workspace.applyEdit(edit);
        if (ok) {
            vscode.window.showInformationMessage(`tf-analyze: fix_hcl for ${finding.id} inserted at line ${finding.line}. ` +
                `Review and adjust before applying.`);
        }
    }), vscode.commands.registerCommand("tf-analyze.showAttackGraph", () => {
        attackGraph_1.AttackGraphPanel.createOrShow(context);
    }), vscode.commands.registerCommand("tf-analyze.showHtmlReport", () => {
        htmlReport_1.HtmlReportPanel.createOrShow(context);
    }), vscode.commands.registerCommand("tf-analyze.showDelta", () => {
        deltaPanel_1.DeltaPanel.createOrShow(context);
    }), vscode.commands.registerCommand("tf-analyze.showCompliance", () => {
        compliancePanel_1.CompliancePanel.createOrShow(context);
    }), vscode.commands.registerCommand("tf-analyze.showMitre", () => {
        mitrePanel_1.MitrePanel.createOrShow(context);
    }), vscode.commands.registerCommand("tf-analyze.remediate", () => {
        remediationPanel_1.RemediationPanel.createOrShow(context);
    }), 
    // Baseline / suppression. Right-clicking a finding in the tree
    // (contextValue === "finding") fires this command with the tree
    // item; we pull (id, file, line, resource) off and write it into
    // <ws>/.tf-analyze-baseline.json so subsequent scans suppress it.
    vscode.commands.registerCommand("tf-analyze.suppressFinding", async (item) => {
        const finding = item?.finding ?? (await pickFindingFromMap(findingsMap));
        if (!finding)
            return;
        const ws = workspacePath();
        const added = (0, baseline_1.suppress)(ws, {
            id: finding.id,
            file: finding.file,
            line: finding.line,
            resource: finding.resource,
        });
        void vscode.window.showInformationMessage(added
            ? `tf-analyze: suppressed ${finding.id} at ${path.basename(finding.file)}:${finding.line}. Re-run scan to refresh.`
            : `tf-analyze: ${finding.id} was already in the baseline.`);
        // Trigger a fresh scan so the tree refreshes with the suppression applied.
        void runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel);
    }), vscode.commands.registerCommand("tf-analyze.unsuppressFinding", async (item) => {
        const finding = item?.finding ?? (await pickFindingFromMap(findingsMap));
        if (!finding)
            return;
        const ws = workspacePath();
        const removed = (0, baseline_1.unsuppress)(ws, {
            id: finding.id,
            file: finding.file,
            line: finding.line,
            resource: finding.resource,
        });
        void vscode.window.showInformationMessage(removed
            ? `tf-analyze: removed ${finding.id} from baseline. Re-run scan to refresh.`
            : `tf-analyze: ${finding.id} was not in the baseline.`);
        void runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel);
    }), vscode.commands.registerCommand("tf-analyze.openBaseline", async () => {
        const file = (0, baseline_1.ensureBaselineFile)(workspacePath());
        const doc = await vscode.workspace.openTextDocument(file);
        await vscode.window.showTextDocument(doc);
    }), vscode.workspace.onDidSaveTextDocument((doc) => {
        const cfg = vscode.workspace.getConfiguration("tf-analyze");
        if (!cfg.get("runOnSave"))
            return;
        if (doc.languageId !== "terraform" && !doc.fileName.endsWith(".tf"))
            return;
        // The LSP server already publishes diagnostics on didSave for the
        // file in question. Running the exec-based whole-workspace scan in
        // parallel would double-write to the diagnostic collection (and
        // burn a Python startup per save). When LSP is up, we still want
        // the Findings tree to reflect the wider workspace, so trigger a
        // scan only if the user explicitly hasn't enabled LSP via the
        // configured engine — `isLspRunning()` is true exactly when the
        // server connected.
        if ((0, lspClient_1.isLspRunning)()) {
            outputChannel.appendLine(`[tf-analyze] LSP active; skipping exec-on-save for ${doc.fileName}`);
            return;
        }
        runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel);
    }));
    // Best-effort start the LSP language server. If detect.py isn't
    // present or the server crashes on init, we silently fall back to
    // the exec-on-save path that's been live for every release before
    // 0.1.14 — no user-visible regression.
    void (0, lspClient_1.startLspClient)(context, outputChannel);
    outputChannel.appendLine("[tf-analyze] Extension activated");
}
/** Quick-pick fallback for the suppress / unsuppress commands when
 * they're invoked from the command palette (no tree-item context).
 * Surfaces every currently-listed finding so the user can pick one
 * without having to right-click the tree row. */
async function pickFindingFromMap(findingsMap) {
    const all = [];
    for (const arr of findingsMap.values())
        all.push(...arr);
    if (all.length === 0) {
        void vscode.window.showInformationMessage("tf-analyze: no findings available — run a scan first.");
        return undefined;
    }
    const items = all.map(f => ({
        label: `[${f.urgency}] ${f.id}`,
        description: f.title,
        detail: `${f.file}:${f.line}`,
        finding: f,
    }));
    const picked = await vscode.window.showQuickPick(items, {
        placeHolder: "Pick a finding to suppress / unsuppress",
        matchOnDescription: true,
        matchOnDetail: true,
    });
    return picked?.finding;
}
function deactivate() { }
// ─── Webview ──────────────────────────────────────────────────────────────────
function buildFindingHtml(finding) {
    const urgencyColor = {
        CRITICAL: "#ff4444",
        HIGH: "#ff8800",
        MEDIUM: "#ffcc00",
        LOW: "#88cc88",
    };
    const color = urgencyColor[finding.urgency.toUpperCase()] ?? "#888";
    const escape = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const recommendationHtml = finding.recommendation
        ? `<h3>Recommendation</h3><pre>${escape(finding.recommendation)}</pre>`
        : "";
    const narrativeHtml = finding.narrative
        ? `<h3>Adversarial scenario</h3>
       <p class="narrative">${escape(finding.narrative)}</p>`
        : "";
    const mitreHtml = finding.mitre && finding.mitre.length
        ? `<div class="mitre">MITRE ATT&amp;CK: ${finding.mitre.map(t => `<code>${escape(t)}</code>`).join(" ")}</div>`
        : "";
    const fixHclHtml = finding.fix_hcl
        ? `<h3>fix_hcl</h3>
       <div class="disruption">Disruption: <strong>${finding.fix_disruption ?? "unknown"}</strong></div>
       <pre class="hcl">${escape(finding.fix_hcl)}</pre>`
        : "";
    const excerptHtml = finding.excerpt
        ? `<h3>Source excerpt</h3><pre>${escape(finding.excerpt)}</pre>`
        : "";
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 16px; }
  h1 { font-size: 1.2em; margin-bottom: 4px; }
  .badge { display:inline-block; padding:2px 8px; border-radius:4px; color:#fff;
           background:${color}; font-size:0.85em; font-weight:bold; margin-bottom:12px; }
  .meta { color: var(--vscode-descriptionForeground); font-size:0.9em; margin-bottom:12px; }
  pre { background: var(--vscode-textCodeBlock-background); padding:12px; border-radius:4px;
        overflow-x:auto; white-space:pre-wrap; }
  .hcl { border-left:3px solid ${color}; }
  .disruption { font-size:0.85em; color:var(--vscode-descriptionForeground); margin:-4px 0 8px; }
  .narrative { background: var(--vscode-editorWarning-background, #fff3cd);
                border-left:3px solid ${color}; padding:10px 14px; border-radius:0 4px 4px 0;
                font-style:italic; line-height:1.5; }
  .mitre { font-size:0.85em; margin:8px 0; color:var(--vscode-descriptionForeground); }
  .mitre code { background: var(--vscode-textCodeBlock-background); padding:2px 6px;
                 border-radius:3px; font-size:0.95em; }
  h3 { font-size:1em; margin-bottom:4px; }
</style>
</head>
<body>
<h1>${escape(finding.id)}: ${escape(finding.title)}</h1>
<span class="badge">${escape(finding.urgency)}</span>
<div class="meta">${escape(finding.file)}:${finding.line} &nbsp;|&nbsp; section: ${escape(finding.section)}</div>
${mitreHtml}
${narrativeHtml}
${excerptHtml}
${recommendationHtml}
${fixHclHtml}
</body>
</html>`;
}
//# sourceMappingURL=extension.js.map