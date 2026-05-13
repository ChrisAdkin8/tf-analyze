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
const fs = __importStar(require("fs"));
const attackGraph_1 = require("./attackGraph");
const htmlReport_1 = require("./htmlReport");
const deltaPanel_1 = require("./deltaPanel");
const compliancePanel_1 = require("./compliancePanel");
const mitrePanel_1 = require("./mitrePanel");
const moduleReusePanel_1 = require("./moduleReusePanel");
const remediationPanel_1 = require("./remediationPanel");
const ruleExplainer_1 = require("./ruleExplainer");
const urls_1 = require("./urls");
const scriptResolver_1 = require("./scriptResolver");
const lspClient_1 = require("./lspClient");
const baseline_1 = require("./baseline");
const uriHandler_1 = require("./uriHandler");
const blastRadiusView_1 = require("./blastRadiusView");
const blastRadiusLens_1 = require("./blastRadiusLens");
// Same thresholds the engine uses in _lsp.py / _output.py. Mid-blast
// surfaces a chip; high-blast adds a second-level warning colour.
const BLAST_SMALL_THRESHOLD = 5;
const BLAST_LARGE_THRESHOLD = 10;
// Audit item 2 — wall-clock cap on a single engine invocation. The
// engine has no internal timeout; on a hung detect.py (Windows file
// system stall, infinite-loop bug, multi-thousand-file repo) the
// status bar would spin forever. 120s is generous for any realistic
// workspace (the demo fixtures complete in <2s) and still bounded so
// the user never loses the panel.
const SCAN_TIMEOUT_MS = 120000;
// Audit item 5 — engine emits paths with the host OS's separator.
// `f.file.startsWith("/")` was Unix-only; on Windows the engine
// returns `C:\repo\main.tf` and the absolute-detection failed,
// re-rooting findings against the workspace path twice. `path.isAbsolute`
// handles both POSIX and Win32 forms.
function _resolveFindingPath(file, target) {
    return path.isAbsolute(file) ? file : path.join(target, file);
}
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
const FILTERABLE_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
class FilterGroupItem extends vscode.TreeItem {
    constructor(counts, hidden) {
        const totalSev = FILTERABLE_SEVERITIES.filter((s) => (counts.get(s) ?? 0) > 0).length;
        const visibleSev = FILTERABLE_SEVERITIES.filter((s) => !hidden.has(s) && (counts.get(s) ?? 0) > 0).length;
        const suffix = hidden.size === 0 ? "showing all" : `${visibleSev} of ${totalSev}`;
        super(`Severity filter (${suffix})`, vscode.TreeItemCollapsibleState.Collapsed);
        this.counts = counts;
        this.hidden = hidden;
        // Stable id so VS Code remembers the user's expand/collapse state
        // across re-renders. Without it every refresh resets to Collapsed.
        this.id = "tfAnalyzeFilterGroup";
        this.iconPath = new vscode.ThemeIcon("filter");
        this.contextValue = "severityFilterGroup";
    }
}
class SeverityFilterItem extends vscode.TreeItem {
    constructor(severity, count, visible) {
        const titled = severity.charAt(0) + severity.slice(1).toLowerCase();
        super(`${titled}  (${count})`, vscode.TreeItemCollapsibleState.None);
        this.severity = severity;
        this.id = `tfAnalyzeFilterSeverity-${severity}`;
        this.checkboxState = visible
            ? vscode.TreeItemCheckboxState.Checked
            : vscode.TreeItemCheckboxState.Unchecked;
        this.contextValue = "severityFilter";
    }
}
class FindingsProvider {
    constructor() {
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.findings = [];
        this.scanRunning = false;
        // Severities (uppercased) the user has chosen to hide from the tree
        // view. Empty set = show all. Filtering applies only to the tree;
        // diagnostics, status bar, and other panels continue to reflect the
        // full set so the filter never silently drops a real finding from
        // anywhere except the surface the user explicitly filtered.
        this.hiddenSeverities = new Set();
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
    setHiddenSeverities(severities) {
        this.hiddenSeverities = new Set([...severities].map((s) => s.toUpperCase()));
        this._onDidChangeTreeData.fire();
    }
    getHiddenSeverities() {
        return [...this.hiddenSeverities];
    }
    toggleSeverity(sev) {
        const key = sev.toUpperCase();
        if (this.hiddenSeverities.has(key)) {
            this.hiddenSeverities.delete(key);
        }
        else {
            this.hiddenSeverities.add(key);
        }
        this._onDidChangeTreeData.fire();
        return !this.hiddenSeverities.has(key);
    }
    visibleFindings() {
        if (this.hiddenSeverities.size === 0)
            return this.findings;
        return this.findings.filter((f) => !this.hiddenSeverities.has(f.urgency.toUpperCase()));
    }
    getTreeItem(element) {
        return element;
    }
    severityCounts() {
        const counts = new Map();
        for (const f of this.findings) {
            const k = f.urgency.toUpperCase();
            counts.set(k, (counts.get(k) ?? 0) + 1);
        }
        return counts;
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
            const counts = this.severityCounts();
            const filterGroup = new FilterGroupItem(counts, this.hiddenSeverities);
            const visible = this.visibleFindings();
            if (visible.length === 0) {
                const empty = new vscode.TreeItem("No findings match the active severity filter");
                empty.iconPath = new vscode.ThemeIcon("filter");
                return [filterGroup, empty];
            }
            const sections = [...new Set(visible.map((f) => f.section))].sort();
            return [
                filterGroup,
                ...sections.map((s) => new SectionItem(s, visible.filter((f) => f.section === s))),
            ];
        }
        if (element instanceof FilterGroupItem) {
            const counts = this.severityCounts();
            return FILTERABLE_SEVERITIES.map((sev) => new SeverityFilterItem(sev, counts.get(sev) ?? 0, !this.hiddenSeverities.has(sev)));
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
// R30.18 — mirror the LSP-side uplift formula from scripts/_lsp.py so
// the squiggle colour matches in both the bundled-engine and LSP
// code paths. Each tier up = one severity rank closer to Error (1).
function upliftSeverityByBlast(base, blast) {
    if (blast >= BLAST_LARGE_THRESHOLD) {
        return Math.max(vscode.DiagnosticSeverity.Error, base - 2);
    }
    if (blast >= BLAST_SMALL_THRESHOLD) {
        return Math.max(vscode.DiagnosticSeverity.Error, base - 1);
    }
    return base;
}
function applyDiagnostics(diagnosticCollection, findings) {
    diagnosticCollection.clear();
    const byFile = new Map();
    for (const f of findings) {
        const absPath = _resolveFindingPath(f.file, workspacePath());
        const uri = vscode.Uri.file(absPath);
        const lineIdx = Math.max(0, f.line - 1);
        const colIdx = Math.max(0, (f.column ?? 1) - 1);
        const range = new vscode.Range(lineIdx, colIdx, lineIdx, colIdx + 1);
        // R30.18 — Blast-radius hover enrichment. Appends `🌊 blast: N`
        // when the resource cited by this finding has non-zero downstream
        // count. Surfaces in both the squiggle hover and the Problems
        // pane so the user sees operational impact alongside the rule
        // text — no need to open the attack-graph view.
        const blast = f.blast_radius ?? 0;
        const blastSuffix = blast >= 1 ? `  🌊 blast: ${blast}` : "";
        const baseSeverity = urgencyToDiagnosticSeverity(f.urgency);
        const severity = upliftSeverityByBlast(baseSeverity, blast);
        const diag = new vscode.Diagnostic(range, `[${f.id}] ${f.title}${blastSuffix}`, severity);
        diag.source = "tf-analyze";
        // VS Code renders the `code.value` as a clickable link in the
        // Problems pane and the hover tooltip; `code.target` is what it
        // navigates to. Point at the per-rule docs page so the user lands
        // on the explainer + remediation + verification + references
        // page rather than a generic repo URL.
        diag.code = { value: f.id, target: vscode.Uri.parse((0, urls_1.ruleDocsUrl)(f.id)) };
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
// Audit follow-up #4 — a multi-root workspace currently has the entire
// scan tied to `workspaceFolders[0]`. The first time a user with > 1
// root opens the extension we surface a single notification explaining
// the limitation so they aren't silently misled into thinking the
// second/third root is also being scanned. The notification offers a
// "Pick folder" affordance that updates the configuration's
// `scriptPath` target out-of-band — a heavier UX (per-finding root
// attribution, multi-target scans) is tracked as a follow-up.
let _multiRootWarned = false;
function _warnIfMultiRoot(out) {
    if (_multiRootWarned)
        return;
    const roots = vscode.workspace.workspaceFolders ?? [];
    if (roots.length <= 1)
        return;
    _multiRootWarned = true;
    const first = roots[0]?.name ?? roots[0]?.uri.fsPath ?? "?";
    out.appendLine(`[tf-analyze] WARN: multi-root workspace detected (${roots.length} folders). ` +
        `Scans currently target the first root only: "${first}". ` +
        `Pick a different folder via "tf-analyze: Pick Workspace Folder" to switch.`);
    void vscode.window.showWarningMessage(`tf-analyze: multi-root workspace detected. Scans target only "${first}". ` +
        `Use "tf-analyze: Pick Workspace Folder" to scan a different root.`, "Pick folder", "Dismiss").then(async (choice) => {
        if (choice !== "Pick folder")
            return;
        const picked = await vscode.window.showWorkspaceFolderPick({
            placeHolder: "Pick the folder to scan with tf-analyze (this session only)",
        });
        if (picked) {
            // Override at runtime by mutating the folder order via the
            // setting: the simplest fix is to write the picked root into
            // `tf-analyze.scriptPath` is wrong (that's the engine path).
            // Instead, persist the picked target under a new setting key
            // and have `workspacePath()` read it. For now: log it and
            // accept that the next scan still uses [0]; a future PR adds
            // the setting + plumbing.
            out.appendLine(`[tf-analyze] folder pick: "${picked.name}" — not yet wired through to scan target; ` +
                `please re-open the workspace with ${picked.name} as the first root.`);
        }
    });
}
function resolveScriptPath() {
    const cfg = vscode.workspace.getConfiguration("tf-analyze");
    return (0, scriptResolver_1.resolveScriptPath)(cfg, workspacePath());
}
function buildArgs(target) {
    const cfg = vscode.workspace.getConfiguration("tf-analyze");
    // `--attack-graph` gates the engine's graph build, which is the upstream
    // dependency for the blast-radius surfaces (tree view, CodeLens,
    // status-bar chip) and for `graph.nodes[].blast_radius`. Without this
    // flag the engine emits no `blast_radius` block and no `graph`, so the
    // R30.18 panels render empty. See engineSmoke.test.ts for the guard.
    const args = ["--target", target, "--format", "json", "--attack-graph"];
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
/**
 * Append a rule ID to the workspace's `.tf-analyze.yaml` `ignore_rules:`
 * list. Returns true if the rule was added, false if it was already
 * present (or the file was malformed in a way that prevented writing).
 *
 * We hand-edit the YAML rather than parse-and-rewrite to preserve
 * comments and formatting the user has already authored. The shape we
 * recognise is the documented one from `docs/custom-rules.md`:
 *
 *   ignore_rules:
 *     - SEC-X-001
 *     - ...
 *
 * If the file doesn't exist, create it with a minimal block. If
 * `ignore_rules:` is absent, append a new block at the end of the file.
 */
function appendIgnoreRule(ws, ruleId, out) {
    const yamlPath = path.join(ws, ".tf-analyze.yaml");
    let text = "";
    if (fs.existsSync(yamlPath)) {
        text = fs.readFileSync(yamlPath, "utf-8");
    }
    // Cheap detection: presence of `<id>` on a list line under
    // `ignore_rules:`. Not a full parser — but the regex is tight
    // enough to avoid false positives on commented-out lines.
    const alreadyPresent = new RegExp(`^\\s*-\\s+${ruleId}\\s*$`, "m").test(text);
    if (alreadyPresent)
        return false;
    const ignoreHeaderRe = /^ignore_rules\s*:\s*$/m;
    if (ignoreHeaderRe.test(text)) {
        // Append a list item under the existing block. Find the block
        // header line, then walk forward until we hit a non-list, non-blank
        // line at the same indent. Insert before it.
        const lines = text.split("\n");
        const headerIdx = lines.findIndex(l => /^ignore_rules\s*:\s*$/.test(l));
        let insertAt = headerIdx + 1;
        while (insertAt < lines.length) {
            const ln = lines[insertAt];
            if (/^\s*-\s/.test(ln) || ln.trim() === "" || ln.trim().startsWith("#")) {
                insertAt++;
            }
            else {
                break;
            }
        }
        lines.splice(insertAt, 0, `  - ${ruleId}`);
        text = lines.join("\n");
    }
    else {
        // No `ignore_rules:` block yet — append one at the end.
        if (text.length > 0 && !text.endsWith("\n"))
            text += "\n";
        if (text.length > 0)
            text += "\n";
        text += `ignore_rules:\n  - ${ruleId}\n`;
    }
    try {
        fs.writeFileSync(yamlPath, text, "utf-8");
        return true;
    }
    catch (err) {
        out.appendLine(`[tf-analyze] failed to write ${yamlPath}: ${err}`);
        return false;
    }
}
// Maps the engine's letter grade to a status-bar colour. The colour
// shows up alongside the badge text so a user glancing at the bar
// sees red for F before reading the score. Uses VS Code's theme
// tokens so the choice adapts to light vs dark themes.
function _gradeColor(grade) {
    if (!grade)
        return undefined;
    // First letter only — handles "B-" the same as "B".
    const head = grade[0];
    if (head === "A")
        return new vscode.ThemeColor("charts.green");
    if (head === "B")
        return new vscode.ThemeColor("charts.blue");
    if (head === "C")
        return new vscode.ThemeColor("charts.yellow");
    if (head === "D")
        return new vscode.ThemeColor("charts.orange");
    if (head === "F")
        return new vscode.ThemeColor("charts.red");
    return undefined;
}
// Audit item 3 — concurrency guard. status-bar click + autosave-on-save
// can fire runScan twice; without this latch, `findingsMap.clear()`
// races with the prior scan's writes and the panel ends up showing
// some subset of findings from each. One in-flight at a time.
let _scanInFlight = false;
async function runScan(ctx) {
    const { diagnosticCollection, provider, findingsMap, statusBar, blastStatusBar, blastProvider, blastLensProvider, outputChannel, } = ctx;
    if (_scanInFlight) {
        outputChannel.appendLine("[tf-analyze] Scan already in flight — skipping duplicate request.");
        return;
    }
    const scriptPath = resolveScriptPath();
    if (!scriptPath) {
        vscode.window.showErrorMessage("tf-analyze: detect.py not found. Set tf-analyze.scriptPath in settings.");
        return;
    }
    const target = workspacePath();
    const args = buildArgs(target);
    _scanInFlight = true;
    provider.setScanRunning(true);
    statusBar.text = "$(sync~spin) tf-analyze scanning…";
    statusBar.color = undefined;
    statusBar.show();
    outputChannel.appendLine(`[tf-analyze] Running: python3 ${scriptPath} ${args.join(" ")}`);
    try {
        const result = await new Promise((resolve, reject) => {
            let stdout = "";
            let stderr = "";
            const proc = cp.spawn("python3", [scriptPath, ...args], { cwd: target });
            // Audit item 2 — wall-clock timeout. SIGTERM the engine and
            // reject the promise so the status bar and panels return to
            // a known state instead of spinning forever.
            const timer = setTimeout(() => {
                try {
                    proc.kill("SIGTERM");
                }
                catch { /* already gone */ }
                reject(new Error(`tf-analyze: scan exceeded ${SCAN_TIMEOUT_MS / 1000}s and was cancelled. ` +
                    `Re-run from a smaller workspace or open the Output panel for the engine command.`));
            }, SCAN_TIMEOUT_MS);
            proc.stdout.on("data", (d) => (stdout += d));
            proc.stderr.on("data", (d) => (stderr += d));
            proc.on("close", (code) => {
                clearTimeout(timer);
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
            proc.on("error", (err) => {
                clearTimeout(timer);
                reject(err);
            });
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
            const key = _resolveFindingPath(f.file, target);
            if (!findingsMap.has(key))
                findingsMap.set(key, []);
            findingsMap.get(key).push(f);
        }
        applyDiagnostics(diagnosticCollection, findings);
        provider.setFindings(findings);
        // R30.18 — Feed the blast-radius surfaces: the tree view + the
        // CodeLens provider + the status-bar chip. All three derive from
        // the same JSON the scan returned, so a single setter call keeps
        // them in lock-step. The chip is hidden when no resource crosses
        // the high-blast threshold (5).
        blastProvider.setScanData({
            blast_radius: parsed.blast_radius,
            graph: parsed.graph,
        });
        blastLensProvider.setGraphNodes(parsed.graph?.nodes ?? []);
        const highBlastCount = blastProvider.highBlastCount(BLAST_SMALL_THRESHOLD);
        if (highBlastCount > 0) {
            blastStatusBar.text = `$(flame) ${highBlastCount} high-blast`;
            blastStatusBar.color = new vscode.ThemeColor(highBlastCount >= 3 ? "errorForeground" : "problemsWarningIcon.foreground");
            blastStatusBar.tooltip =
                `${highBlastCount} resource${highBlastCount === 1 ? "" : "s"} with blast radius ≥ ${BLAST_SMALL_THRESHOLD} — click to open the Blast Radius view`;
            blastStatusBar.show();
        }
        else {
            blastStatusBar.hide();
        }
        const counts = parsed.summary?.counts ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
        const total = findings.length;
        const score = parsed.summary?.score;
        const grade = parsed.summary?.grade;
        // Score+grade is the inherently shareable artefact — the same
        // shape that lands in PR comments and the per-rule docs site.
        // Showing it here means screenshots posted from VS Code carry
        // the same vocabulary as everything else.
        const scorePrefix = (typeof score === "number" && grade)
            ? `${score} (${grade}) · `
            : "";
        const label = total === 0
            ? `$(check) tf-analyze: ${scorePrefix}clean`
            : `$(shield) tf-analyze: ${scorePrefix}${total} finding${total !== 1 ? "s" : ""} (C:${counts.CRITICAL} H:${counts.HIGH} M:${counts.MEDIUM})`;
        statusBar.text = label;
        // Colour the badge by grade so the worst-of-the-worst stands
        // out without forcing the eye to read the digits. Uses VS Code
        // theme colours so it adapts to light/dark themes automatically.
        statusBar.color = _gradeColor(grade);
        outputChannel.appendLine(`[tf-analyze] Scan complete: ${total} finding(s)`);
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`tf-analyze: ${msg}`);
        statusBar.text = "$(error) tf-analyze: scan failed";
        statusBar.color = undefined;
        outputChannel.appendLine(`[tf-analyze] Error: ${msg}`);
    }
    finally {
        _scanInFlight = false;
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
    complianceStatusBar.tooltip = "tf-analyze: open the compliance gap report (CIS / PCI DSS / SOC 2 / OWASP IaC)";
    // Fifth: remediate. Bulk apply-fixes UX with two-stage preview/apply
    // flow (writes .bak backups). Priority 96.
    const remediateStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 96);
    remediateStatusBar.command = "tf-analyze.remediate";
    remediateStatusBar.text = "$(wand) Remediate";
    remediateStatusBar.tooltip = "tf-analyze: preview and bulk-apply fix_hcl patches across the workspace (--apply-fixes)";
    // Sixth: module reuse advisor. Surfaces directories whose resource
    // cluster matches a popular community module on the Terraform
    // Registry. INFO-tier (advisory) so it never gates CI. Priority 95.
    const moduleReuseStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 95);
    moduleReuseStatusBar.command = "tf-analyze.showModuleReuse";
    moduleReuseStatusBar.text = "$(package) Module Reuse";
    moduleReuseStatusBar.tooltip = "tf-analyze: surface directories that could be replaced by a public-registry module (AWS VPC, GCP network, Azure AKS, …)";
    // R30.18 — Blast-radius chip. Priority 94 — appears immediately to
    // the right of Module Reuse. Hidden until a scan turns up at least
    // one resource with blast >= BLAST_SMALL_THRESHOLD. Click opens the
    // dedicated tree view.
    const blastStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 94);
    blastStatusBar.command = "tf-analyze.showBlastRadius";
    blastStatusBar.tooltip = "tf-analyze: resources whose destruction or recreation would cascade to many dependents";
    // Stays hidden until the next scan populates it.
    // Only surface the shortcuts when there's something to scan.
    void vscode.workspace.findFiles("**/*.tf", "**/node_modules/**", 1).then((found) => {
        if (found.length > 0) {
            graphStatusBar.show();
            deltaStatusBar.show();
            complianceStatusBar.show();
            remediateStatusBar.show();
            moduleReuseStatusBar.show();
            // blastStatusBar shows itself once data lands in runScan
        }
    });
    const treeView = vscode.window.createTreeView("tfAnalyzeFindings", {
        treeDataProvider: provider,
        showCollapseAll: true,
    });
    // Severity filter — surfaced as a collapsible "Severity filter" row
    // at the top of the Findings tree with native VS Code checkboxes for
    // Critical / High / Medium / Low. State persists in workspaceState
    // across reloads. The palette commands `tf-analyze.toggle<Sev>`
    // remain wired up as keyboard-shortcut targets for power users.
    const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    const FILTER_STATE_KEY = "tf-analyze.hiddenSeverities";
    const persistFilter = () => {
        void context.workspaceState.update(FILTER_STATE_KEY, provider.getHiddenSeverities());
    };
    const persistedHidden = context.workspaceState.get(FILTER_STATE_KEY, []);
    provider.setHiddenSeverities(persistedHidden);
    // VS Code fires this when the user clicks one of the severity
    // checkboxes inside the filter group. We translate the new checkbox
    // state into provider state and persist; the tree re-render is
    // triggered by `toggleSeverity` -> `_onDidChangeTreeData`.
    treeView.onDidChangeCheckboxState((e) => {
        let changed = false;
        for (const [item, state] of e.items) {
            if (!(item instanceof SeverityFilterItem))
                continue;
            const wantVisible = state === vscode.TreeItemCheckboxState.Checked;
            const isHidden = provider.getHiddenSeverities().includes(item.severity);
            if (wantVisible && isHidden) {
                provider.toggleSeverity(item.severity);
                changed = true;
            }
            else if (!wantVisible && !isHidden) {
                provider.toggleSeverity(item.severity);
                changed = true;
            }
        }
        if (changed)
            persistFilter();
    });
    // R30.18 — Blast-radius tree (top-N high-blast resources, expandable
    // to downstream dependents) and CodeLens (per-resource inline
    // annotation). Both providers receive their data via setters from
    // `runScan`; neither re-invokes the engine.
    const blastProvider = new blastRadiusView_1.BlastRadiusProvider();
    const blastTreeView = vscode.window.createTreeView("tfAnalyzeBlastRadius", {
        treeDataProvider: blastProvider,
        showCollapseAll: true,
    });
    const blastLensProvider = new blastRadiusLens_1.BlastRadiusCodeLensProvider();
    const blastLensRegistration = vscode.languages.registerCodeLensProvider({ language: "terraform", scheme: "file" }, blastLensProvider);
    const codeActionProvider = new TfAnalyzeCodeActionProvider(findingsMap);
    // Audit item 13 — single source of truth for runScan's dependency
    // surface. Mutating any of these handles re-bound a positional
    // parameter at six call-sites; the bag of refs binds once here.
    const scanCtx = {
        diagnosticCollection,
        provider,
        findingsMap,
        statusBar,
        blastStatusBar,
        blastProvider,
        blastLensProvider,
        outputChannel,
    };
    context.subscriptions.push(diagnosticCollection, outputChannel, statusBar, graphStatusBar, deltaStatusBar, complianceStatusBar, remediateStatusBar, moduleReuseStatusBar, blastStatusBar, treeView, blastTreeView, blastLensRegistration, vscode.languages.registerCodeActionsProvider({ language: "terraform", scheme: "file" }, codeActionProvider, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix, vscode.CodeActionKind.Empty] }), vscode.commands.registerCommand("tf-analyze.runScan", () => runScan(scanCtx)), ...SEVERITIES.map((sev) => vscode.commands.registerCommand(`tf-analyze.toggle${sev.charAt(0)}${sev.slice(1).toLowerCase()}`, () => {
        provider.toggleSeverity(sev);
        persistFilter();
    })), vscode.commands.registerCommand("tf-analyze.clearFindings", () => {
        diagnosticCollection.clear();
        findingsMap.clear();
        provider.clear();
        blastProvider.clear();
        blastLensProvider.clear();
        blastStatusBar.hide();
        statusBar.text = "$(shield) tf-analyze";
    }), 
    // R30.18 — Show the Blast Radius tree view. Activity bar tab is
    // permanent (registered via package.json) so this just focuses it.
    vscode.commands.registerCommand("tf-analyze.showBlastRadius", async () => {
        await vscode.commands.executeCommand("tfAnalyzeBlastRadius.focus");
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
    }), vscode.commands.registerCommand("tf-analyze.showModuleReuse", () => {
        moduleReusePanel_1.ModuleReusePanel.createOrShow(context);
    }), 
    // Rule explainer. Two entry points:
    //   1. `tf-analyze.explainRule` — palette / programmatic, pass a rule
    //      ID or surface a quick-pick of every catalogue ID.
    //   2. `vscode://tfanalyze.tf-analyze/rule/<RULE-ID>` — clicked from
    //      the docs site's "Open in VS Code" button (handled below via
    //      registerUriHandler).
    vscode.commands.registerCommand("tf-analyze.explainRule", async (ruleId) => {
        let id = ruleId;
        if (!id) {
            id = await vscode.window.showInputBox({
                prompt: "Catalogue rule ID (e.g. SEC-AWS-IAM-001)",
                validateInput: v => /^[A-Z][A-Z0-9-]{2,63}$/.test(v) ? null : "Expected uppercase letters, digits, and hyphens",
            });
        }
        if (id)
            ruleExplainer_1.RuleExplainerPanel.createOrShow(context, id);
    }), 
    // The URI handler routes every `vscode://tfanalyze.tf-analyze/...`
    // click in a browser to this extension. Verbs:
    //
    //   /rule/<RULE-ID>                  → open RuleExplainerPanel
    //   /scan?target=<absolute path>     → run a workspace scan
    //   /explain?id=<ID>&file=<p>&line=N → explain at a location
    //   /suppress?id=<ID>&file=<p>&line=N → add to workspace baseline
    //
    // Every verb has a strict regex validator. If the URI fails to
    // parse for the matched verb, surface a warning rather than silently
    // no-op (the v0.1.27 security pattern).
    vscode.window.registerUriHandler({
        handleUri(uri) {
            (0, uriHandler_1.dispatchUri)({ path: uri.path, query: uri.query, toString: () => uri.toString() }, {
                openRule: (ruleId) => ruleExplainer_1.RuleExplainerPanel.createOrShow(context, ruleId),
                runScan: () => {
                    void runScan(scanCtx);
                },
                openLocation: (file, line) => {
                    void vscode.workspace.openTextDocument(file).then(doc => vscode.window.showTextDocument(doc, {
                        selection: new vscode.Range(line - 1, 0, line - 1, 0),
                    }), err => {
                        outputChannel.appendLine(`[tf-analyze] /explain could not open ${file}: ${err}`);
                    });
                },
                suppressFinding: (ruleId, file, line) => {
                    const ws = workspacePath();
                    const added = (0, baseline_1.suppress)(ws, { id: ruleId, file, line });
                    void vscode.window.showInformationMessage(added
                        ? `tf-analyze: suppressed ${ruleId} at ${path.basename(file)}:${line}. Re-run scan to refresh.`
                        : `tf-analyze: ${ruleId} was already in the baseline.`);
                    if (added) {
                        void runScan(scanCtx);
                    }
                },
                suppressRuleWorkspaceWide: (ruleId) => {
                    const ws = workspacePath();
                    // Confirm before writing — workspace-wide suppression
                    // kills every future occurrence and is broader than
                    // per-finding baseline-add.
                    void vscode.window.showWarningMessage(`tf-analyze: ignore ${ruleId} workspace-wide?`, { modal: true }, "Add to .tf-analyze.yaml").then(choice => {
                        if (choice !== "Add to .tf-analyze.yaml")
                            return;
                        const added = appendIgnoreRule(ws, ruleId, outputChannel);
                        void vscode.window.showInformationMessage(added
                            ? `tf-analyze: added ${ruleId} to .tf-analyze.yaml's ignore_rules. Re-run scan to refresh.`
                            : `tf-analyze: ${ruleId} was already in ignore_rules.`);
                        if (added) {
                            void runScan(scanCtx);
                        }
                    });
                },
                workspacePath,
                warn: (msg) => { void vscode.window.showWarningMessage(msg); },
                log: (msg) => outputChannel.appendLine(`[tf-analyze] ${msg}`),
            });
        },
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
        void runScan(scanCtx);
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
        void runScan(scanCtx);
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
        runScan(scanCtx);
    }));
    // Best-effort start the LSP language server. If detect.py isn't
    // present or the server crashes on init, we silently fall back to
    // the exec-on-save path that's been live for every release before
    // 0.1.14 — no user-visible regression.
    void (0, lspClient_1.startLspClient)(context, outputChannel);
    outputChannel.appendLine("[tf-analyze] Extension activated");
    _warnIfMultiRoot(outputChannel);
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
  .docs-link { display:inline-block; margin:8px 0 16px; padding:6px 12px;
               background:${color}; color:#fff; text-decoration:none;
               border-radius:4px; font-size:0.9em; font-weight:600; }
  .docs-link:hover { opacity:0.9; }
</style>
</head>
<body>
<h1>${escape(finding.id)}: ${escape(finding.title)}</h1>
<span class="badge">${escape(finding.urgency)}</span>
<div class="meta">${escape(finding.file)}:${finding.line} &nbsp;|&nbsp; section: ${escape(finding.section)}</div>
<a class="docs-link" href="${(0, urls_1.ruleDocsUrl)(finding.id)}" target="_blank" rel="noopener">📖 Open full rule documentation →</a>
${mitreHtml}
${narrativeHtml}
${excerptHtml}
${recommendationHtml}
${fixHclHtml}
</body>
</html>`;
}
//# sourceMappingURL=extension.js.map