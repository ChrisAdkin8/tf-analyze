// R30.18 — CodeLens above resource declarations whose blast radius is
// at or above the small threshold. Contextual: appears while editing,
// not just in the panel. Click → opens the blast-radius tree view
// focused on this resource.
//
// Resolves blast values from the per-node graph data the engine
// already emits when --attack-graph ran. We don't re-parse the HCL —
// we look up the line numbers in the graph's nodes list directly,
// because the engine has already done the work of resolving each
// resource's declaration site.

import * as vscode from "vscode";

interface GraphNode {
  id: string;
  file?: string;
  line?: number;
  blast_radius?: number;
}

const SHOW_LENS_THRESHOLD = 3;

export class BlastRadiusCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  private nodesByFile = new Map<string, GraphNode[]>();

  setGraphNodes(nodes: GraphNode[]): void {
    this.nodesByFile.clear();
    for (const n of nodes) {
      if (!n.file || !n.line || !n.blast_radius) continue;
      if (n.blast_radius < SHOW_LENS_THRESHOLD) continue;
      // INTERNET is synthetic — no real file to anchor a lens to.
      if (n.id === "INTERNET") continue;
      const key = n.file;
      if (!this.nodesByFile.has(key)) this.nodesByFile.set(key, []);
      this.nodesByFile.get(key)!.push(n);
    }
    this._onDidChangeCodeLenses.fire();
  }

  clear(): void {
    this.nodesByFile.clear();
    this._onDidChangeCodeLenses.fire();
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const nodes = this.nodesByFile.get(document.uri.fsPath);
    if (!nodes) return [];
    const lenses: vscode.CodeLens[] = [];
    for (const node of nodes) {
      const line = Math.max(0, (node.line ?? 1) - 1);
      const range = new vscode.Range(line, 0, line, 0);
      lenses.push(
        new vscode.CodeLens(range, {
          title: `🌊 ${node.blast_radius} downstream — destroying this would touch ${node.blast_radius} other resource${node.blast_radius === 1 ? "" : "s"}`,
          command: "tf-analyze.showBlastRadius",
          tooltip: `${node.id} sits upstream of ${node.blast_radius} other resources. Click to open the Blast Radius view.`,
          arguments: [node.id],
        }),
      );
    }
    return lenses;
  }
}
