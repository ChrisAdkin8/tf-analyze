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
exports.BUNDLED_ENGINE_PATH = void 0;
exports.resolveScriptPath = resolveScriptPath;
exports.resolvePython = resolvePython;
exports.filterWorkspaceExtraArgs = filterWorkspaceExtraArgs;
exports.resolveExtraArgs = resolveExtraArgs;
exports.defaultSearchPaths = defaultSearchPaths;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
/** Path to the detect.py shipped inside the .vsix. The extension MUST
 * be self-contained — this path is the canonical engine location and
 * is checked first by `resolveScriptPath`, before any workspace
 * fallbacks or the user's `tf-analyze.scriptPath` setting.
 *
 * `__dirname` resolves to the runtime location of the compiled .js
 * (typically `<extensionRoot>/out/`). The bundled engine sits at
 * `<extensionRoot>/engine/detect.py`, populated by
 * `scripts/bundle-engine.js` at build time.
 *
 * Exported so callers (and tests) can verify the path without
 * re-deriving it. */
exports.BUNDLED_ENGINE_PATH = path.resolve(__dirname, '..', 'engine', 'scripts', 'detect.py');
function resolveScriptPath(cfg, wsFolder, options) {
    const isFile = (p) => {
        try {
            return fs.statSync(p).isFile();
        }
        catch {
            return false;
        }
    };
    const isDir = (p) => {
        try {
            return fs.statSync(p).isDirectory();
        }
        catch {
            return false;
        }
    };
    // 1. Bundled engine — checked first so the .vsix is self-contained
    //    and works on any workspace, regardless of layout. If this is
    //    missing, the extension was packaged incorrectly (the
    //    `bundle-engine` npm script didn't run before vsce package).
    const bundled = options?.bundledEnginePath === undefined
        ? exports.BUNDLED_ENGINE_PATH
        : options.bundledEnginePath;
    if (bundled && isFile(bundled))
        return bundled;
    // 2. Engine-developer override.
    const configured = cfg.get('scriptPath', '').trim();
    if (configured) {
        const abs = path.isAbsolute(configured) ? configured : path.join(wsFolder, configured);
        if (isFile(abs))
            return abs;
        if (isDir(abs)) {
            const inDir = path.join(abs, 'detect.py');
            if (isFile(inDir))
                return inDir;
        }
    }
    // 3. Workspace-relative fallbacks. Mostly historical now that the
    //    .vsix bundles its own engine, but kept for engine devs who run
    //    the extension via F5 against a workspace that has its own copy.
    for (const cand of [
        path.join(wsFolder, 'scripts', 'detect.py'),
        path.join(wsFolder, 'detect.py'),
        path.join(wsFolder, '..', 'tf-analyze', 'scripts', 'detect.py'),
    ]) {
        if (isFile(cand))
            return cand;
    }
    // 4. Parent walk for nested fixtures / submodules.
    let dir = wsFolder;
    for (let i = 0; i < 6; i++) {
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
        const cand = path.join(parent, 'scripts', 'detect.py');
        if (isFile(cand))
            return cand;
        dir = parent;
    }
    return null;
}
/** Resolve the Python interpreter to spawn the engine with.
 *
 * `tf-analyze.pythonPath` wins when set (absolute path or a name on PATH).
 * Otherwise default by platform: Windows installs almost always provide
 * `python` and frequently lack `python3`, so the previous hardcoded
 * `python3` made every scan/panel/LSP fail with ENOENT on Windows.
 * Takes `cfg` (rather than reading the config itself) so this module stays
 * value-import-free and unit-testable outside VS Code, like
 * `resolveScriptPath`. */
function resolvePython(cfg) {
    const configured = (cfg.get('pythonPath', '') ?? '').trim();
    if (configured)
        return configured;
    return process.platform === 'win32' ? 'python' : 'python3';
}
/** Engine flags a workspace's own settings may add through
 * `tf-analyze.extraArgs`: they only filter or annotate the report. Flags
 * that write files (`--apply-fixes`, `--output`, `--gen-tests` …), load
 * other rules or config (`--catalog`, `--config`), reach the network
 * (`--check-registry`, `--rank-by`, `--mode pr-review`) or change the
 * output format the extension parses are dropped, because a cloned
 * repository controls its `.vscode/settings.json`. Values from the
 * user's own settings are trusted and passed through unchanged. Maps
 * each allowed flag to whether it takes a value. */
const WORKSPACE_SAFE_FLAGS = new Map([
    ['--focus', true],
    ['--fail-on', true],
    ['--mitre-tactic', true],
    ['--compliance-framework', true],
    ['--show-fixes', false],
    ['--show-info', false],
    ['--no-suppress', false],
    ['--fail-on-parse-error', false],
    ['--blast-radius', false],
    ['--explain-score', false],
    ['--compliance', false],
    ['--include-stubs', false],
    ['--no-threat-intel', false],
    ['--no-project-config', false],
]);
/** Keep only `WORKSPACE_SAFE_FLAGS` (and their values) from `args`;
 * returns `[kept, dropped]`. Accepts `--flag value` and `--flag=value`. */
function filterWorkspaceExtraArgs(args) {
    const kept = [];
    const dropped = [];
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        const [flag, inline] = arg.split(/=(.*)/s, 2);
        const takesValue = WORKSPACE_SAFE_FLAGS.get(flag);
        if (takesValue === undefined) {
            dropped.push(arg);
            continue;
        }
        if (!takesValue || inline !== undefined) {
            kept.push(arg);
        }
        else if (i + 1 < args.length) {
            kept.push(arg, args[++i]);
        }
    }
    return [kept, dropped];
}
/** `tf-analyze.extraArgs` for the engine command line. When the value
 * comes from workspace or folder settings it is filtered through
 * `filterWorkspaceExtraArgs`; `onDropped` receives anything removed. */
function resolveExtraArgs(cfg, onDropped) {
    const clean = (v) => Array.isArray(v) ? v.filter((a) => typeof a === 'string' && a.length > 0) : [];
    const info = cfg.inspect('extraArgs');
    const fromWorkspace = info?.workspaceFolderValue ?? info?.workspaceValue;
    if (fromWorkspace === undefined)
        return clean(cfg.get('extraArgs', []));
    const [kept, dropped] = filterWorkspaceExtraArgs(clean(fromWorkspace));
    if (dropped.length && onDropped)
        onDropped(dropped);
    return kept;
}
/** A short list of representative paths checked, useful for surfacing
 * "we looked here" guidance in error panels. Not exhaustive — the
 * parent walk in resolveScriptPath checks more locations than this. */
function defaultSearchPaths(wsFolder) {
    return [
        path.join(wsFolder, 'scripts', 'detect.py'),
        path.join(wsFolder, 'detect.py'),
        path.join(wsFolder, '..', 'tf-analyze', 'scripts', 'detect.py'),
    ];
}
//# sourceMappingURL=scriptResolver.js.map