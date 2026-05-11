// R30.18 — Blast-radius surfaces in the activity bar.
//
// Two-level tree:
//   ▸ aws_vpc.main · 12 downstream · 🌐 inet
//     ├── aws_subnet.public
//     ├── aws_subnet.private
//     └── …
//   ▸ aws_security_group.web · 7 downstream
//     └── aws_instance.web[0..2]
//
// Click a row → editor jumps to the resource declaration. Mirrors the
// shape of the Module-Reuse tree (priority 95) but priority 85 in the
// activity bar so the Findings + Attack-Graph icons stay on top.
//
// Data flows in from `runScan` via `setScanResult({blast_radius, graph})`.
// The tree never re-runs the engine — it's a pure renderer over the
// scan JSON the extension already holds.

import * as vscode from "vscode";

interface BlastEntry {
  resource: string;
  type: string;
  file: string;
  line: number;
  blast_radius: number;
  is_crown_jewel: boolean;
  internet_reachable: boolean;
}

interface GraphEdge {
  from: string;
  to: string;
  label: string;
}

interface GraphNode {
  id: string;
  file?: string;
  line?: number;
  blast_radius?: number;
  is_crown_jewel?: boolean;
  internet_reachable?: boolean;
}

interface ScanData {
  blast_radius?: BlastEntry[];
  graph?: { nodes: GraphNode[]; edges: GraphEdge[] };
}

/** A top-N blast-radius row. Expandable. */
class BlastRootItem extends vscode.TreeItem {
  constructor(public readonly entry: BlastEntry, public readonly downstream: GraphNode[]) {
    super(
      entry.resource.split(".").slice(-1)[0] || entry.resource,
      downstream.length > 0
        ? vscode.TreeItemCollapsibleState.Collapsed
        : vscode.TreeItemCollapsibleState.None,
    );
    const flags: string[] = [];
    if (entry.is_crown_jewel) flags.push("💎 crown");
    if (entry.internet_reachable) flags.push("🌐 inet");
    this.description =
      `${entry.blast_radius} downstream${flags.length ? " · " + flags.join(" · ") : ""}`;
    this.tooltip =
      `${entry.resource}\n` +
      `Touches ${entry.blast_radius} downstream resource(s) when destroyed or recreated.\n` +
      `${entry.file}:${entry.line}`;
    this.iconPath = severityIcon(entry.blast_radius);
    this.contextValue = "blastRoot";
    if (entry.file && entry.line) {
      this.command = {
        command: "vscode.open",
        title: "Open resource",
        arguments: [
          vscode.Uri.file(entry.file),
          { selection: new vscode.Range(entry.line - 1, 0, entry.line - 1, 0) },
        ],
      };
    }
  }
}

/** A downstream resource (child of a root). */
class BlastChildItem extends vscode.TreeItem {
  constructor(public readonly node: GraphNode) {
    super(node.id.split(".").slice(-1)[0] || node.id, vscode.TreeItemCollapsibleState.None);
    this.description = node.id;
    this.tooltip = `${node.id} — depends on the parent resource (would be touched if it's destroyed/recreated)`;
    this.iconPath = new vscode.ThemeIcon("symbol-method");
    if (node.file && node.line) {
      this.command = {
        command: "vscode.open",
        title: "Open downstream resource",
        arguments: [
          vscode.Uri.file(node.file),
          { selection: new vscode.Range(node.line - 1, 0, node.line - 1, 0) },
        ],
      };
    }
  }
}

type BlastTreeNode = BlastRootItem | BlastChildItem;

function severityIcon(blast: number): vscode.ThemeIcon {
  if (blast >= 10) return new vscode.ThemeIcon("flame", new vscode.ThemeColor("errorForeground"));
  if (blast >= 5) return new vscode.ThemeIcon("warning", new vscode.ThemeColor("problemsWarningIcon.foreground"));
  return new vscode.ThemeIcon("circle-large-outline");
}

export class BlastRadiusProvider implements vscode.TreeDataProvider<BlastTreeNode> {
  private _onDidChangeTreeData = new vscode.EventEmitter<BlastTreeNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private blast: BlastEntry[] = [];
  private nodeIndex = new Map<string, GraphNode>();
  private adjacency = new Map<string, string[]>();

  /** Called from `runScan` after a successful scan. */
  setScanData(data: ScanData): void {
    this.blast = data.blast_radius ?? [];
    this.nodeIndex.clear();
    this.adjacency.clear();
    const graph = data.graph;
    if (graph) {
      for (const node of graph.nodes ?? []) this.nodeIndex.set(node.id, node);
      for (const edge of graph.edges ?? []) {
        if (!this.adjacency.has(edge.from)) this.adjacency.set(edge.from, []);
        this.adjacency.get(edge.from)!.push(edge.to);
      }
    }
    this._onDidChangeTreeData.fire();
  }

  clear(): void {
    this.blast = [];
    this.nodeIndex.clear();
    this.adjacency.clear();
    this._onDidChangeTreeData.fire();
  }

  /** Cap children to 25 — past that the tree gets unreadable. */
  private downstreamOf(rootId: string): GraphNode[] {
    const visited = new Set<string>();
    const out: GraphNode[] = [];
    const stack = [...(this.adjacency.get(rootId) ?? [])];
    while (stack.length && out.length < 25) {
      const cur = stack.pop()!;
      if (visited.has(cur) || cur === rootId) continue;
      visited.add(cur);
      const node = this.nodeIndex.get(cur);
      if (node) out.push(node);
      stack.push(...(this.adjacency.get(cur) ?? []));
    }
    return out;
  }

  getTreeItem(element: BlastTreeNode): vscode.TreeItem {
    return element;
  }

  getChildren(element?: BlastTreeNode): BlastTreeNode[] {
    if (!element) {
      if (this.blast.length === 0) return [];
      return this.blast.map(
        (e) => new BlastRootItem(e, this.downstreamOf(e.resource)),
      );
    }
    if (element instanceof BlastRootItem) {
      return this.downstreamOf(element.entry.resource).map(
        (n) => new BlastChildItem(n),
      );
    }
    return [];
  }

  /** Count of resources at/above the high-blast threshold. */
  highBlastCount(threshold = 5): number {
    return this.blast.filter((e) => e.blast_radius >= threshold).length;
  }
}
