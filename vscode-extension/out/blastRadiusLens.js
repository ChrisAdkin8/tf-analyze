"use strict";
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
exports.BlastRadiusCodeLensProvider = void 0;
const vscode = __importStar(require("vscode"));
const SHOW_LENS_THRESHOLD = 3;
class BlastRadiusCodeLensProvider {
    constructor() {
        this._onDidChangeCodeLenses = new vscode.EventEmitter();
        this.onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;
        this.nodesByFile = new Map();
    }
    setGraphNodes(nodes) {
        this.nodesByFile.clear();
        for (const n of nodes) {
            if (!n.file || !n.line || !n.blast_radius)
                continue;
            if (n.blast_radius < SHOW_LENS_THRESHOLD)
                continue;
            // INTERNET is synthetic — no real file to anchor a lens to.
            if (n.id === "INTERNET")
                continue;
            const key = n.file;
            if (!this.nodesByFile.has(key))
                this.nodesByFile.set(key, []);
            this.nodesByFile.get(key).push(n);
        }
        this._onDidChangeCodeLenses.fire();
    }
    clear() {
        this.nodesByFile.clear();
        this._onDidChangeCodeLenses.fire();
    }
    provideCodeLenses(document) {
        const nodes = this.nodesByFile.get(document.uri.fsPath);
        if (!nodes)
            return [];
        const lenses = [];
        for (const node of nodes) {
            const line = Math.max(0, (node.line ?? 1) - 1);
            const range = new vscode.Range(line, 0, line, 0);
            lenses.push(new vscode.CodeLens(range, {
                title: `🌊 ${node.blast_radius} downstream — destroying this would touch ${node.blast_radius} other resource${node.blast_radius === 1 ? "" : "s"}`,
                command: "tf-analyze.showBlastRadius",
                tooltip: `${node.id} sits upstream of ${node.blast_radius} other resources. Click to open the Blast Radius view.`,
                arguments: [node.id],
            }));
        }
        return lenses;
    }
}
exports.BlastRadiusCodeLensProvider = BlastRadiusCodeLensProvider;
//# sourceMappingURL=blastRadiusLens.js.map