import * as vscode from "vscode";
import * as cp from "child_process";
import * as path from "path";
import * as fs from "fs";
import { AttackGraphPanel } from "./attackGraph";
import { HtmlReportPanel } from "./htmlReport";
import { DeltaPanel } from "./deltaPanel";
import { CompliancePanel } from "./compliancePanel";
import { MitrePanel } from "./mitrePanel";
import { ModuleReusePanel } from "./moduleReusePanel";
import { RemediationPanel } from "./remediationPanel";
import { RuleExplainerPanel } from "./ruleExplainer";
import { ruleDocsUrl, ruleAnchorHtml } from "./urls";
import { resolveScriptPath as sharedResolve } from "./scriptResolver";
import { startLspClient, isLspRunning } from "./lspClient";
import { baselineExists, baselinePath, ensureBaselineFile, suppress, unsuppress } from "./baseline";
import { dispatchUri } from "./uriHandler";

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
    score?: number;
    grade?: string;
    counts: {
      CRITICAL: number;
      HIGH: number;
      MEDIUM: number;
      LOW: number;
      INFO: number;
    };
    suppressed_count?: number;
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
    // VS Code renders the `code.value` as a clickable link in the
    // Problems pane and the hover tooltip; `code.target` is what it
    // navigates to. Point at the per-rule docs page so the user lands
    // on the explainer + remediation + verification + references
    // page rather than a generic repo URL.
    diag.code = { value: f.id, target: vscode.Uri.parse(ruleDocsUrl(f.id)) };

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
  return sharedResolve(cfg, workspacePath());
}

function buildArgs(target: string): string[] {
  const cfg = vscode.workspace.getConfiguration("tf-analyze");
  const args = ["--target", target, "--format", "json"];
  const section: string = cfg.get("section") ?? "";
  if (section) args.push("--section", section);
  // Auto-pin a baseline file if one exists at the workspace root.
  // The engine will then suppress matching findings — this is the
  // sole consumer surface for the baseline UI's writes.
  if (baselineExists(target)) {
    args.push("--baseline", baselinePath(target));
  }
  const extra: string[] = cfg.get("extraArgs") ?? [];
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
function appendIgnoreRule(
  ws: string,
  ruleId: string,
  out: vscode.OutputChannel,
): boolean {
  const yamlPath = path.join(ws, ".tf-analyze.yaml");
  let text = "";
  if (fs.existsSync(yamlPath)) {
    text = fs.readFileSync(yamlPath, "utf-8");
  }
  // Cheap detection: presence of `<id>` on a list line under
  // `ignore_rules:`. Not a full parser — but the regex is tight
  // enough to avoid false positives on commented-out lines.
  const alreadyPresent = new RegExp(
    `^\\s*-\\s+${ruleId}\\s*$`, "m",
  ).test(text);
  if (alreadyPresent) return false;

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
      } else {
        break;
      }
    }
    lines.splice(insertAt, 0, `  - ${ruleId}`);
    text = lines.join("\n");
  } else {
    // No `ignore_rules:` block yet — append one at the end.
    if (text.length > 0 && !text.endsWith("\n")) text += "\n";
    if (text.length > 0) text += "\n";
    text += `ignore_rules:\n  - ${ruleId}\n`;
  }
  try {
    fs.writeFileSync(yamlPath, text, "utf-8");
    return true;
  } catch (err) {
    out.appendLine(`[tf-analyze] failed to write ${yamlPath}: ${err}`);
    return false;
  }
}

// Maps the engine's letter grade to a status-bar colour. The colour
// shows up alongside the badge text so a user glancing at the bar
// sees red for F before reading the score. Uses VS Code's theme
// tokens so the choice adapts to light vs dark themes.
function _gradeColor(grade: string | undefined): vscode.ThemeColor | undefined {
  if (!grade) return undefined;
  // First letter only — handles "B-" the same as "B".
  const head = grade[0];
  if (head === "A") return new vscode.ThemeColor("charts.green");
  if (head === "B") return new vscode.ThemeColor("charts.blue");
  if (head === "C") return new vscode.ThemeColor("charts.yellow");
  if (head === "D") return new vscode.ThemeColor("charts.orange");
  if (head === "F") return new vscode.ThemeColor("charts.red");
  return undefined;
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
  statusBar.color = undefined;
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

  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`tf-analyze: ${msg}`);
    statusBar.text = "$(error) tf-analyze: scan failed";
    statusBar.color = undefined;
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

  // Only surface the shortcuts when there's something to scan.
  void vscode.workspace.findFiles("**/*.tf", "**/node_modules/**", 1).then((found) => {
    if (found.length > 0) {
      graphStatusBar.show();
      deltaStatusBar.show();
      complianceStatusBar.show();
      remediateStatusBar.show();
      moduleReuseStatusBar.show();
    }
  });

  const treeView = vscode.window.createTreeView("tfAnalyzeFindings", {
    treeDataProvider: provider,
    showCollapseAll: true,
  });

  const codeActionProvider = new TfAnalyzeCodeActionProvider(findingsMap);

  context.subscriptions.push(
    diagnosticCollection,
    outputChannel,
    statusBar,
    graphStatusBar,
    deltaStatusBar,
    complianceStatusBar,
    remediateStatusBar,
    moduleReuseStatusBar,
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

    vscode.commands.registerCommand("tf-analyze.showHtmlReport", () => {
      HtmlReportPanel.createOrShow(context);
    }),

    vscode.commands.registerCommand("tf-analyze.showDelta", () => {
      DeltaPanel.createOrShow(context);
    }),

    vscode.commands.registerCommand("tf-analyze.showCompliance", () => {
      CompliancePanel.createOrShow(context);
    }),

    vscode.commands.registerCommand("tf-analyze.showMitre", () => {
      MitrePanel.createOrShow(context);
    }),

    vscode.commands.registerCommand("tf-analyze.remediate", () => {
      RemediationPanel.createOrShow(context);
    }),

    vscode.commands.registerCommand("tf-analyze.showModuleReuse", () => {
      ModuleReusePanel.createOrShow(context);
    }),

    // Rule explainer. Two entry points:
    //   1. `tf-analyze.explainRule` — palette / programmatic, pass a rule
    //      ID or surface a quick-pick of every catalogue ID.
    //   2. `vscode://tfanalyze.tf-analyze/rule/<RULE-ID>` — clicked from
    //      the docs site's "Open in VS Code" button (handled below via
    //      registerUriHandler).
    vscode.commands.registerCommand("tf-analyze.explainRule", async (ruleId?: string) => {
      let id = ruleId;
      if (!id) {
        id = await vscode.window.showInputBox({
          prompt: "Catalogue rule ID (e.g. SEC-AWS-IAM-001)",
          validateInput: v => /^[A-Z][A-Z0-9-]{2,63}$/.test(v) ? null : "Expected uppercase letters, digits, and hyphens",
        });
      }
      if (id) RuleExplainerPanel.createOrShow(context, id);
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
      handleUri(uri: vscode.Uri) {
        dispatchUri(
          { path: uri.path, query: uri.query, toString: () => uri.toString() },
          {
            openRule: (ruleId) => RuleExplainerPanel.createOrShow(context, ruleId),
            runScan: () => {
              void runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel);
            },
            openLocation: (file, line) => {
              void vscode.workspace.openTextDocument(file).then(
                doc => vscode.window.showTextDocument(doc, {
                  selection: new vscode.Range(line - 1, 0, line - 1, 0),
                }),
                err => {
                  outputChannel.appendLine(
                    `[tf-analyze] /explain could not open ${file}: ${err}`,
                  );
                },
              );
            },
            suppressFinding: (ruleId, file, line) => {
              const ws = workspacePath();
              const added = suppress(ws, { id: ruleId, file, line });
              void vscode.window.showInformationMessage(
                added
                  ? `tf-analyze: suppressed ${ruleId} at ${path.basename(file)}:${line}. Re-run scan to refresh.`
                  : `tf-analyze: ${ruleId} was already in the baseline.`,
              );
              if (added) {
                void runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel);
              }
            },
            suppressRuleWorkspaceWide: (ruleId) => {
              const ws = workspacePath();
              // Confirm before writing — workspace-wide suppression
              // kills every future occurrence and is broader than
              // per-finding baseline-add.
              void vscode.window.showWarningMessage(
                `tf-analyze: ignore ${ruleId} workspace-wide?`,
                { modal: true },
                "Add to .tf-analyze.yaml",
              ).then(choice => {
                if (choice !== "Add to .tf-analyze.yaml") return;
                const added = appendIgnoreRule(ws, ruleId, outputChannel);
                void vscode.window.showInformationMessage(
                  added
                    ? `tf-analyze: added ${ruleId} to .tf-analyze.yaml's ignore_rules. Re-run scan to refresh.`
                    : `tf-analyze: ${ruleId} was already in ignore_rules.`,
                );
                if (added) {
                  void runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel);
                }
              });
            },
            workspacePath,
            warn: (msg) => { void vscode.window.showWarningMessage(msg); },
            log: (msg) => outputChannel.appendLine(`[tf-analyze] ${msg}`),
          },
        );
      },
    }),

    // Baseline / suppression. Right-clicking a finding in the tree
    // (contextValue === "finding") fires this command with the tree
    // item; we pull (id, file, line, resource) off and write it into
    // <ws>/.tf-analyze-baseline.json so subsequent scans suppress it.
    vscode.commands.registerCommand("tf-analyze.suppressFinding", async (item: FindingItem | undefined) => {
      const finding = item?.finding ?? (await pickFindingFromMap(findingsMap));
      if (!finding) return;
      const ws = workspacePath();
      const added = suppress(ws, {
        id: finding.id,
        file: finding.file,
        line: finding.line,
        resource: (finding as Finding & { resource?: string }).resource,
      });
      void vscode.window.showInformationMessage(
        added
          ? `tf-analyze: suppressed ${finding.id} at ${path.basename(finding.file)}:${finding.line}. Re-run scan to refresh.`
          : `tf-analyze: ${finding.id} was already in the baseline.`
      );
      // Trigger a fresh scan so the tree refreshes with the suppression applied.
      void runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel);
    }),

    vscode.commands.registerCommand("tf-analyze.unsuppressFinding", async (item: FindingItem | undefined) => {
      const finding = item?.finding ?? (await pickFindingFromMap(findingsMap));
      if (!finding) return;
      const ws = workspacePath();
      const removed = unsuppress(ws, {
        id: finding.id,
        file: finding.file,
        line: finding.line,
        resource: (finding as Finding & { resource?: string }).resource,
      });
      void vscode.window.showInformationMessage(
        removed
          ? `tf-analyze: removed ${finding.id} from baseline. Re-run scan to refresh.`
          : `tf-analyze: ${finding.id} was not in the baseline.`
      );
      void runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel);
    }),

    vscode.commands.registerCommand("tf-analyze.openBaseline", async () => {
      const file = ensureBaselineFile(workspacePath());
      const doc = await vscode.workspace.openTextDocument(file);
      await vscode.window.showTextDocument(doc);
    }),

    vscode.workspace.onDidSaveTextDocument((doc) => {
      const cfg = vscode.workspace.getConfiguration("tf-analyze");
      if (!cfg.get<boolean>("runOnSave")) return;
      if (doc.languageId !== "terraform" && !doc.fileName.endsWith(".tf")) return;
      // The LSP server already publishes diagnostics on didSave for the
      // file in question. Running the exec-based whole-workspace scan in
      // parallel would double-write to the diagnostic collection (and
      // burn a Python startup per save). When LSP is up, we still want
      // the Findings tree to reflect the wider workspace, so trigger a
      // scan only if the user explicitly hasn't enabled LSP via the
      // configured engine — `isLspRunning()` is true exactly when the
      // server connected.
      if (isLspRunning()) {
        outputChannel.appendLine(`[tf-analyze] LSP active; skipping exec-on-save for ${doc.fileName}`);
        return;
      }
      runScan(diagnosticCollection, provider, findingsMap, statusBar, outputChannel);
    })
  );

  // Best-effort start the LSP language server. If detect.py isn't
  // present or the server crashes on init, we silently fall back to
  // the exec-on-save path that's been live for every release before
  // 0.1.14 — no user-visible regression.
  void startLspClient(context, outputChannel);

  outputChannel.appendLine("[tf-analyze] Extension activated");
}

/** Quick-pick fallback for the suppress / unsuppress commands when
 * they're invoked from the command palette (no tree-item context).
 * Surfaces every currently-listed finding so the user can pick one
 * without having to right-click the tree row. */
async function pickFindingFromMap(
  findingsMap: Map<string, Finding[]>
): Promise<Finding | undefined> {
  const all: Finding[] = [];
  for (const arr of findingsMap.values()) all.push(...arr);
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
<a class="docs-link" href="${ruleDocsUrl(finding.id)}" target="_blank" rel="noopener">📖 Open full rule documentation →</a>
${mitreHtml}
${narrativeHtml}
${excerptHtml}
${recommendationHtml}
${fixHclHtml}
</body>
</html>`;
}
