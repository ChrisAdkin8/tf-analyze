"use strict";
// Shared engine-spawn helper for every panel that runs detect.py.
//
// Audit (2026-05-11 follow-up) closed three findings at once via this seam:
//
//   #1  Webview message-handler / panel `cp.execFile` callback bookkeeping
//       was duplicated across six panels. Without one helper, fixes had to
//       be applied six times — and a forgotten copy was the original
//       blast-radius regression source pattern.
//   #3  No wall-clock timeout on panel-triggered engine invocations.
//       R30.8 added the timeout to the main `runScan` only; every panel
//       (`remediationPanel`, `compliancePanel`, `deltaPanel`, `htmlReport`,
//       `moduleReusePanel`, `mitrePanel`) could hang the webview forever.
//   #9  The boilerplate (`cmdLine` building, exit-code interpretation,
//       buffer limit, stderr surfacing) was copy-pasted with minor
//       variations.  Drift between copies was actively shipping (#3 was
//       only fixed for runScan; the panels never got it).
//
// The helper owns the spawn, the timeout, and the `cmdLine` string used in
// error rendering.  Callers receive a uniform `EngineResult` and decide how
// to render success vs. failure — the rendering pathways are panel-specific
// (each panel formats the engine's output differently) so they stay in the
// caller, but the *boilerplate around them* lives here.
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
exports.ENGINE_MAX_BUFFER = exports.ENGINE_TIMEOUT_MS = void 0;
exports.runEngine = runEngine;
exports.classifyEngineResult = classifyEngineResult;
const cp = __importStar(require("child_process"));
const vscode = __importStar(require("vscode"));
const scriptResolver_1 = require("./scriptResolver");
// 120 seconds matches the constant in `extension.ts` so a panel-spawned
// engine has the same patience as the main scan.  A hung detect.py
// (Windows FS stall, infinite loop in a new rule, multi-thousand-file
// repo) terminates after this many ms; the caller renders the timeout
// message just like any other engine failure.
exports.ENGINE_TIMEOUT_MS = 120000;
// 50 MiB matches the buffer every panel previously declared individually.
// Big enough for compliance HTML on terragoat (~3 MiB), the full delta
// JSON, and the mitre matrix render — small enough that we still bail
// rather than OOM the renderer on a runaway output.
exports.ENGINE_MAX_BUFFER = 50 * 1024 * 1024;
/**
 * Spawn the engine and surface its output uniformly.  See module-level
 * docstring for the audit items this seam closes.
 *
 * @param scriptPath  Absolute path to `detect.py`.
 * @param args        Argv after `detect.py` (e.g. `['--target', '/a', '--format', 'json']`).
 * @param cb          Receives the engine result once the process exits or
 *                    the timeout fires.  Always called exactly once.
 */
function runEngine(scriptPath, args, cb) {
    const py = (0, scriptResolver_1.resolvePython)(vscode.workspace.getConfiguration('tf-analyze'));
    // Build the pretty cmdLine FIRST so error paths can quote it even if the
    // spawn itself fails synchronously.  The panel renderers display it back
    // to the user so they can re-run from a terminal.
    const cmdLine = `${py} ${[scriptPath, ...args]
        .map(a => /\s/.test(a) ? `"${a}"` : a)
        .join(' ')}`;
    let settled = false;
    const finish = (result) => {
        // Belt-and-braces: never call back twice.  The timer-vs-exit race
        // would otherwise let both paths fire if a slow detect.py prints
        // output exactly as the kill SIGTERM lands.
        if (settled)
            return;
        settled = true;
        clearTimeout(timer);
        cb(result);
    };
    const proc = cp.execFile(py, [scriptPath, ...args], { maxBuffer: exports.ENGINE_MAX_BUFFER }, (err, stdout, stderr) => {
        finish({
            err: err,
            stdout: stdout || '',
            stderr: stderr || '',
            cmdLine,
            timedOut: false,
        });
    });
    const timer = setTimeout(() => {
        try {
            proc.kill('SIGTERM');
        }
        catch { /* already gone */ }
        finish({
            err: { name: 'TimeoutError', message: `engine exceeded ${exports.ENGINE_TIMEOUT_MS / 1000}s and was cancelled`, code: 124 },
            stdout: '',
            stderr: `tf-analyze: engine exceeded ${exports.ENGINE_TIMEOUT_MS / 1000}s and was cancelled. Re-run from a smaller workspace or open the Output panel for the engine command.`,
            cmdLine,
            timedOut: true,
        });
    }, exports.ENGINE_TIMEOUT_MS);
}
/**
 * Convenience wrapper that converts an `EngineResult` into a `{ok, ...}`
 * union the caller can destructure.  `ok: false` carries the rendered
 * exit-code / stderr / cmdLine bundle every panel uses.  Callers can
 * still inspect the raw `EngineResult` if they need to (e.g. modules
 * that interpret a partial stdout on exit 1).
 */
function classifyEngineResult(result) {
    const exitCode = result.err?.code;
    const exitGtOne = typeof exitCode === 'number' && exitCode > 1;
    const stdoutEmpty = !result.stdout || !result.stdout.trim();
    return {
        // Engine convention: exit 0 = clean, exit 1 = findings present, both
        // are "success" for a render.  Exit ≥ 2 OR an empty stdout means the
        // engine crashed before emitting a payload — treat as failure.
        ok: !exitGtOne && !stdoutEmpty,
        exitCode,
        stdoutEmpty,
    };
}
//# sourceMappingURL=engineRunner.js.map