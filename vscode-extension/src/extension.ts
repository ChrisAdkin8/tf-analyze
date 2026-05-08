import * as vscode from "vscode";
import * as cp from "child_process";
import * as path from "path";
import * as fs from "fs";
import { AttackGraphPanel } from "./attackGraph";

interface Finding {
  id: string;
  title: string;
  urgency: string;
  section: string;
  file: string;
  line: number;
  column?: number;
  excerpt?: string;
  recommendation?: string;
  fix_hcl?: string;
  fix_disruption?: string;
  narrative?: string;
  mitre?: string[];
}

interface ScanResult {
  findings: Finding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

// ─── Tree view ────────────────────────────────────────────────────────────────

class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly finding: Finding,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState
  ) {
    super(
      `[${finding.urgency}] ${finding.id}`,
      collapsibleState
    );
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
  constructor(
    public readonly label: string,
    public readonly findings: Finding[]
  ) {
    super(label, vscode.TreeItemCollapsibleState.Expanded);
    this.description = `${findings.length} finding${findings.length !== 1 ? "s" : ""}`;
    this.iconPath = new vscode.ThemeIcon("folder");
  }
}

type TreeNode = SectionItem | FindingItem;

function urgencyIcon(urgency: string): vscode.ThemeIcon {
  switch (urgency.toUpperCase()) {
    case "CRITICAL": return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
    case "HIGH":     return new vscode.ThemeIcon("warning", new vscode.ThemeColor("problemsWarningIcon.foreground"));
    case "MEDIUM":   return new vscode.ThemeIcon("info", new vscode.ThemeColor("problemsInfoIcon.foreground"));
    default:         return new vscode.ThemeIcon("circle-outline");
  }
}

class FindingsProvider implements vscode.TreeDataProvider<TreeNode> {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findings: Finding[] = [];
  private scanRunning = false;

  setFindings(findings: Finding[]): void {
    this.findings = findings;
    this._onDidChangeTreeData.fire();
  }

  setScanRunning(running: boolean): void {
    this.scanRunning = running;
    this._onDidChangeTreeData.fire();
  }

  clear(): void {
    this.findings = [];
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeNode): TreeNode[] {
    if (this.scanRunning && !element) {
      const item = new vscode.TreeItem("Scanning…");
      item.iconPath = new vscode.ThemeIcon("sync~spin");
      return [item as unknown as TreeNode];
    }

    if (!element) {
      if (this.findings.length === 0) {
        const item = new vscode.TreeItem("No findings");
        item.iconPath = new vscode.ThemeIcon("check");
        return [item as unknown as TreeNode];
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

function urgencyToDiagnosticSeverity(urgency: string): vscode.DiagnosticSeverity {
  const cfg = vscode.workspace.getConfiguration("tf-analyze");
  const failOn: string = cfg.get("failOn") ?? "HIGH";
  const order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const failIdx = order.indexOf(failOn.toUpperCase());
  const findingIdx = order.indexOf(urgency.toUpperCase());

  if (findingIdx >= failIdx) return vscode.DiagnosticSeverity.Error;
  if (findingIdx >= order.indexOf("MEDIUM")) return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

function applyDiagnostics(
  diagnosticCollection: vscode.DiagnosticCollection,
  findings: Finding[]
): void {
  diagnosticCollection.clear();

  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const f of findings) {
    const absPath = f.file.startsWith("/") ? f.file : path.join(workspacePath(), f.file);
    const uri = vscode.Uri.file(absPath);
    const lineIdx = Math.max(0, f.line - 1);
    const colIdx = Math.max(0, (f.column ?? 1) - 1);
    const range = new vscode.Range(lineIdx, colIdx, lineIdx, colIdx + 1);
    const diag = new vscode.Diagnostic(
      range,
      `[${f.id}] ${f.title}`,
      urgencyToDiagnosticSeverity(f.urgency)
    );
    diag.source = "tf-analyze";
    diag.code = { value: f.id, target: vscode.Uri.parse(`https://github.com/example/tf-analyze`) };

    const key = uri.fsPath;
    if (!byFile.has(key)) byFile.set(key, []);
    byFile.get(key)!.push(diag);
  }

  for (const [fsPath, diags] of byFile) {
    diagnosticCollection.set(vscode.Uri.file(fsPath), diags);
  }
}

// ─── Code actions (Quick Fix) ─────────────────────────────────────────────────

class TfAnalyzeCodeActionProvider implements vscode.CodeActionProvider {
  constructor(private readonly findingsMap: Map<string, Finding[]>) {}

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const filePath = document.uri.fsPath;
    const findings = this.findingsMap.get(filePath) ?? [];

    for (const diag of context.diagnostics) {
      if (diag.source !== "tf-analyze") continue;

      const idMatch = /^\[([A-Z0-9-]+)\]/.exec(diag.message);
      if (!idMatch) continue;
      const id = idMatch[1];

      const finding = findings.find((f) => f.id === id && f.line === diag.range.start.line + 1);
      if (!finding?.fix_hcl) continue;

      const action = new vscode.CodeAction(
        `tf-analyze: Apply fix for ${id}`,
        vscode.CodeActionKind.QuickFix
      );
      action.diagnostics = [diag];
      action.isPreferred = true;
      action.command = {
        command: "tf-analyze.applyFix",
        title: `Apply fix for ${id}`,
        arguments: [document, diag.range, finding],
      };
      actions.push(action);

      const docAction = new vscode.CodeAction(
        `tf-analyze: View recommendation for ${id}`,
        vscode.CodeActionKind.Empty
      );
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

function workspacePath(): string {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();
}

function resolveScriptPath(): string | null {
  const cfg = vscode.workspace.getConfiguration("tf-analyze");
  const configured: string = cfg.get("scriptPath") ?? "";
  if (configured && fs.existsSync(configured)) return configured;

  const candidates = [
    path.join(workspacePath(), "scripts", "detect.py"),
    path.join(workspacePath(), "detect.py"),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return null;
}

function buildArgs(target: string): string[] {
  const cfg = vscode.workspace.getConfiguration("tf-analyze");
  const args = ["--target", target, "--format", "json"];
  const section: string = cfg.get("section") ?? "";
  if (section) args.push("--section", section);
  const extra: string[] = cfg.get("extraArgs") ?? [];
  args.push(...extra);
  return args;
}

async function runScan(
  diagnosticCollection: vscode.DiagnosticCollection,
  provider: FindingsProvider,
  findingsMap: Map<string, Finding[]>,
  statusBar: vscode.StatusBarItem,
  outputChannel: vscode.OutputChannel
): Promise<void> {
  const scriptPath = resolveScriptPath();
  if (!scriptPath) {
    vscode.window.showErrorMessage(
      "tf-analyze: detect.py not found. Set tf-analyze.scriptPath in settings."
    );
    return;
  }

  const target = workspacePath();
  const args = buildArgs(target);

  provider.setScanRunning(true);
  statusBar.text = "$(sync~spin) tf-analyze scanning…";
  statusBar.show();
  outputChannel.appendLine(`[tf-analyze] Running: python3 ${scriptPath} ${args.join(" ")}`);

  try {
    const result = await new Promise<string>((resolve, reject) => {
      let stdout = "";
      let stderr = "";
      const proc = cp.spawn("python3", [scriptPath, ...args], { cwd: target });
      proc.stdout.on("data", (d) => (stdout += d));
      proc.stderr.on("data", (d) => (stderr += d));
      proc.on("close", (code) => {
        if (stderr) outputChannel.appendLine(`[tf-analyze] stderr: ${stderr}`);
        // exit 1 = findings found, exit 0 = clean — both are valid
        if (code !== null && code > 1) {
          reject(new Error(`detect.py exited with code ${code}: ${stderr}`));
        } else {
          resolve(stdout);
        }
      });
      proc.on("error", reject);
    });

    let parsed: ScanResult;
    try {
      parsed = JSON.parse(result);
    } catch {
      outputChannel.appendLine("[tf-analyze] Failed to parse JSON output. Raw output:");
      outputChannel.appendLine(result.substring(0, 2000));
      throw new Error("tf-analyze output is not valid JSON. Check the Output panel.");
    }

    const findings: Finding[] = parsed.findings ?? [];
    findingsMap.clear();
    for (const f of findings) {
      const key = f.file.startsWith("/") ? f.file : path.join(target, f.file);
      if (!findingsMap.has(key)) findingsMap.set(key, []);
      findingsMap.get(key)!.push(f);
    }

    applyDiagnostics(diagnosticCollection, findings);
    provider.setFindings(findings);

    const summary = parsed.summary ?? { total: findings.length, critical: 0, high: 0, medium: 0, low: 0 };
    const label = summary.total === 0
      ? "$(check) tf-analyze: clean"
      : `$(shield) tf-analyze: ${summary.total} (C:${summary.critical} H:${summary.high} M:${summary.medium})`;
    statusBar.text = label;
    outputChannel.appendLine(`[tf-analyze] Scan complete: ${summary.total} finding(s)`);

  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`tf-analyze: ${msg}`);
    statusBar.text = "$(error) tf-analyze: scan failed";
    outputChannel.appendLine(`[tf-analyze] Error: ${msg}`);
  } finally {
    provider.setScanRunning(false);
  }
}

// ─── Activation ───────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  const diagnosticCollection = vscode.languages.createDiagnosticCollection("tf-analyze");
  const findingsMap = new Map<string, Finding[]>();
  const provider = new FindingsProvider();
  const outputChannel = vscode.window.createOutputChannel("tf-analyze");

  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = "tf-analyze.runScan";
  statusBar.text = "$(shield) tf-analyze";
  statusBar.tooltip = "Click to run tf-analyze scan";
  statusBar.show();

  const treeView = vscode.window.createTreeView("tfAnalyzeFindings", {
    treeDataProvider: provider,
    showCollapseAll: true,
  });

  const codeActionProvider = new TfAnalyzeCodeActionProvider(findingsMap);

  context.subscriptions.push(
    diagnosticCollection,
    outputChannel,
    statusBar,
    treeView,

    vscode.languages.registerCodeActionsProvider(
      { language: "terraform", scheme: "file" },
      codeActionProvider,
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix, vscode.CodeActionKind.Empty] }
    ),

    vscode.commands.registerCommand("tf-analyze.runScan", () =>
      runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel)
    ),

    vscode.commands.registerCommand("tf-analyze.clearFindings", () => {
      diagnosticCollection.clear();
      findingsMap.clear();
      provider.clear();
      statusBar.text = "$(shield) tf-analyze";
    }),

    vscode.commands.registerCommand("tf-analyze.openFinding", (finding: Finding) => {
      const panel = vscode.window.createWebviewPanel(
        "tfAnalyzeFinding",
        `[${finding.id}] ${finding.title}`,
        vscode.ViewColumn.Beside,
        {}
      );
      panel.webview.html = buildFindingHtml(finding);
    }),

    vscode.commands.registerCommand(
      "tf-analyze.applyFix",
      async (document: vscode.TextDocument, _range: vscode.Range, finding: Finding) => {
        if (!finding.fix_hcl) return;

        const edit = new vscode.WorkspaceEdit();
        const lineIdx = Math.max(0, finding.line - 1);
        const lineText = document.lineAt(lineIdx).text;
        const insertPos = new vscode.Position(lineIdx, lineText.length);
        const fixText = `\n\n# tf-analyze fix for ${finding.id}:\n${finding.fix_hcl}`;
        edit.insert(document.uri, insertPos, fixText);

        const ok = await vscode.workspace.applyEdit(edit);
        if (ok) {
          vscode.window.showInformationMessage(
            `tf-analyze: fix_hcl for ${finding.id} inserted at line ${finding.line}. ` +
            `Review and adjust before applying.`
          );
        }
      }
    ),

    vscode.commands.registerCommand("tf-analyze.showAttackGraph", () => {
      AttackGraphPanel.createOrShow(context);
    }),

    vscode.workspace.onDidSaveTextDocument((doc) => {
      const cfg = vscode.workspace.getConfiguration("tf-analyze");
      if (!cfg.get<boolean>("runOnSave")) return;
      if (doc.languageId !== "terraform" && !doc.fileName.endsWith(".tf")) return;
      runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel);
    })
  );

  outputChannel.appendLine("[tf-analyze] Extension activated");
}

export function deactivate(): void {}

// ─── Webview ──────────────────────────────────────────────────────────────────

function buildFindingHtml(finding: Finding): string {
  const urgencyColor: Record<string, string> = {
    CRITICAL: "#ff4444",
    HIGH: "#ff8800",
    MEDIUM: "#ffcc00",
    LOW: "#88cc88",
  };
  const color = urgencyColor[finding.urgency.toUpperCase()] ?? "#888";

  const escape = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

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
