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