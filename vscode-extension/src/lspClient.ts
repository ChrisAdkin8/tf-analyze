import * as vscode from 'vscode';
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from 'vscode-languageclient/node';
import { resolveScriptPath, resolvePython } from './scriptResolver';

let client: LanguageClient | undefined;

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
export async function startLspClient(
  context: vscode.ExtensionContext,
  outputChannel: vscode.OutputChannel,
): Promise<boolean> {
  const cfg = vscode.workspace.getConfiguration('tf-analyze');
  const wsFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '.';
  const absScript = resolveScriptPath(cfg, wsFolder);
  if (!absScript) {
    outputChannel.appendLine('[tf-analyze] LSP: detect.py not found, skipping language-server start.');
    return false;
  }

  const serverOptions: ServerOptions = {
    run: {
      command: resolvePython(cfg),
      args: [absScript, '--lsp'],
      transport: TransportKind.stdio,
    },
    debug: {
      command: resolvePython(cfg),
      args: [absScript, '--lsp'],
      transport: TransportKind.stdio,
    },
  };

  const clientOptions: LanguageClientOptions = {
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
    revealOutputChannelOn: 4 satisfies number, // RevealOutputChannelOn.Never — we surface explicitly
  };

  client = new LanguageClient(
    'tfAnalyzeLsp',
    'tf-analyze (LSP)',
    serverOptions,
    clientOptions,
  );

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
  } catch (err) {
    outputChannel.appendLine(`[tf-analyze] LSP: start failed — ${(err as Error).message}. Falling back to exec-on-save.`);
    client = undefined;
    return false;
  }
}

/** True iff the LSP client started successfully and is currently
 * managing diagnostics. Used by the runOnSave handler to skip the
 * exec-based scan for the file the LSP already covers. */
export function isLspRunning(): boolean {
  return client !== undefined && client.isRunning();
}
