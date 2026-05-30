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
exports.startLspClient = startLspClient;
exports.isLspRunning = isLspRunning;
const vscode = __importStar(require("vscode"));
const node_1 = require("vscode-languageclient/node");
const scriptResolver_1 = require("./scriptResolver");
let client;
/** Spin up `python3 detect.py --lsp` as a JSON-RPC LSP server over
 * stdio and connect it as the diagnostics source for `.tf` files.
 *
 * The engine implements a minimal subset (initialize, didOpen,
 * didSave, didClose, codeAction, shutdown). That's enough to drive
 * real-time per-file diagnostics + Quick Fix without exec'ing a fresh
 * Python process on every save.
 *
 * Coexists with the workspace-wide `tf-analyze.runScan` exec path,
 * which is still needed for files that aren't currently open in an
 * editor (the LSP server only sees URIs after didOpen). The two write
 * to separate diagnostic collections so they never overlap.
 *
 * Returns true if the client started, false if no detect.py was found
 * (the caller falls back to the legacy exec-on-save path silently).
 */
async function startLspClient(context, outputChannel) {
    const cfg = vscode.workspace.getConfiguration('tf-analyze');
    const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
    const absScript = (0, scriptResolver_1.resolveScriptPath)(cfg, wsFolder);
    if (!absScript) {
        outputChannel.appendLine('[tf-analyze] LSP: detect.py not found, skipping language-server start.');
        return false;
    }
    const serverOptions = {
        run: {
            command: (0, scriptResolver_1.resolvePython)(cfg),
            args: [absScript, '--lsp'],
            transport: node_1.TransportKind.stdio,
        },
        debug: {
            command: (0, scriptResolver_1.resolvePython)(cfg),
            args: [absScript, '--lsp'],
            transport: node_1.TransportKind.stdio,
        },
    };
    const clientOptions = {
        // Match the way VS Code identifies HCL — both common ids used in
        // practice. The engine itself disambiguates by file extension, so
        // this only governs which buffers VS Code routes to the server.
        documentSelector: [
            { scheme: 'file', language: 'terraform' },
            { scheme: 'file', language: 'hcl' },
            { scheme: 'file', pattern: '**/*.tf' },
        ],
        outputChannel,
        // Surface Python tracebacks/stderr in the same channel as the rest
        // of the extension so users have one place to look when something
        // breaks.
        revealOutputChannelOn: 4, // RevealOutputChannelOn.Never — we surface explicitly
    };
    client = new node_1.LanguageClient('tfAnalyzeLsp', 'tf-analyze (LSP)', serverOptions, clientOptions);
    try {
        await client.start();
        outputChannel.appendLine('[tf-analyze] LSP: server started, real-time diagnostics enabled.');
        context.subscriptions.push({
            dispose: () => {
                if (client) {
                    // best-effort shutdown; ignore errors during disposal
                    void client.stop();
                }
            },
        });
        return true;
    }
    catch (err) {
        outputChannel.appendLine(`[tf-analyze] LSP: start failed — ${err.message}. Falling back to exec-on-save.`);
        client = undefined;
        return false;
    }
}
/** True iff the LSP client started successfully and is currently
 * managing diagnostics. Used by the runOnSave handler to skip the
 * exec-based scan for the file the LSP already covers. */
function isLspRunning() {
    return client !== undefined && client.isRunning();
}
//# sourceMappingURL=lspClient.js.map