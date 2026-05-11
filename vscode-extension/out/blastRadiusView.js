"use strict";
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
exports.BlastRadiusProvider = void 0;
const vscode = __importStar(require("vscode"));
/** A top-N blast-radius row. Expandable. */
class BlastRootItem extends vscode.TreeItem {
    constructor(entry, downstream) {
        super(entry.resource.split(".").slice(-1)[0] || entry.resource, downstream.length > 0
            ? vscode.TreeItemCollapsibleState.Collapsed
            : vscode.TreeItemCollapsibleState.None);
        this.entry = entry;
        this.downstream = downstream;
        const flags = [];
        if (entry.is_crown_jewel)
            flags.push("💎 crown");
        if (entry.internet_reachable)
            flags.push("🌐 inet");
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
    constructor(node) {
        super(node.id.split(".").slice(-1)[0] || node.id, vscode.TreeItemCollapsibleState.None);
        this.node = node;
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
function severityIcon(blast) {
    if (blast >= 10)
        return new vscode.ThemeIcon("flame", new vscode.ThemeColor("errorForeground"));
    if (blast >= 5)
        return new vscode.ThemeIcon("warning", new vscode.ThemeColor("problemsWarningIcon.foreground"));
    return new vscode.ThemeIcon("circle-large-outline");
}
class BlastRadiusProvider {
    constructor() {
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.blast = [];
        this.nodeIndex = new Map();
        this.adjacency = new Map();
    }
    /** Called from `runScan` after a successful scan. */
    setScanData(data) {
        this.blast = data.blast_radius ?? [];
        this.nodeIndex.clear();
        this.adjacency.clear();
        const graph = data.graph;
        if (graph) {
            for (const node of graph.nodes ?? [])
                this.nodeIndex.set(node.id, node);
            for (const edge of graph.edges ?? []) {
                if (!this.adjacency.has(edge.from))
                    this.adjacency.set(edge.from, []);
                this.adjacency.get(edge.from).push(edge.to);
            }
        }
        this._onDidChangeTreeData.fire();
    }
    clear() {
        this.blast = [];
        this.nodeIndex.clear();
        this.adjacency.clear();
        this._onDidChangeTreeData.fire();
    }
    /** Cap children to 25 — past that the tree gets unreadable. */
    downstreamOf(rootId) {
        const visited = new Set();
        const out = [];
        const stack = [...(this.adjacency.get(rootId) ?? [])];
        while (stack.length && out.length < 25) {
            const cur = stack.pop();
            if (visited.has(cur) || cur === rootId)
                continue;
            visited.add(cur);
            const node = this.nodeIndex.get(cur);
            if (node)
                out.push(node);
            stack.push(...(this.adjacency.get(cur) ?? []));
        }
        return out;
    }
    getTreeItem(element) {
        return element;
    }
    getChildren(element) {
        if (!element) {
            if (this.blast.length === 0)
                return [];
            return this.blast.map((e) => new BlastRootItem(e, this.downstreamOf(e.resource)));
        }
        if (element instanceof BlastRootItem) {
            return this.downstreamOf(element.entry.resource).map((n) => new BlastChildItem(n));
        }
        return [];
    }
    /** Count of resources at/above the high-blast threshold. */
    highBlastCount(threshold = 5) {
        return this.blast.filter((e) => e.blast_radius >= threshold).length;
    }
}
exports.BlastRadiusProvider = BlastRadiusProvider;
//# sourceMappingURL=blastRadiusView.js.map