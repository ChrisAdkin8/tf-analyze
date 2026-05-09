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
exports.resolveScriptPath = resolveScriptPath;
exports.defaultSearchPaths = defaultSearchPaths;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
/** Resolve `scripts/detect.py` from the workspace + user setting.
 *
 * Strategy (mirrored across every surface that shells out to the engine
 * so users hit the same lookup whether they invoke runScan, the attack
 * graph, or the HTML report):
 *
 *  1. Honour `tf-analyze.scriptPath` if set. A configured *directory*
 *     is treated as "look for detect.py inside" — a common
 *     misconfiguration that used to produce `python3 <dir>` →
 *     `can't find '__main__' module`.
 *  2. Workspace-relative fallbacks: `<ws>/scripts/detect.py`,
 *     `<ws>/detect.py`, and the sibling-clone case
 *     `<ws>/../tf-analyze/scripts/detect.py`.
 *  3. Walk up to six parent directories of the workspace looking for
 *     `scripts/detect.py`. Catches the case where the workspace is a
 *     fixture or submodule nested inside the tf-analyze repo.
 *
 * Returns an absolute file path, or null if no `detect.py` was found.
 * The result is always a regular file — `python3 <dir>` would
 * otherwise fail before emitting JSON.
 */
function resolveScriptPath(cfg, wsFolder) {
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
    for (const cand of [
        path.join(wsFolder, 'scripts', 'detect.py'),
        path.join(wsFolder, 'detect.py'),
        path.join(wsFolder, '..', 'tf-analyze', 'scripts', 'detect.py'),
    ]) {
        if (isFile(cand))
            return cand;
    }
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