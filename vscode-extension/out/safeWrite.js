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
exports.writeFileNoFollow = writeFileNoFollow;
exports.writePrivateTempFile = writePrivateTempFile;
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
/** Write `text` to `file` without following a symlink at that path.
 *
 * `fs.writeFileSync` writes through a symlink, so a repository that
 * commits `.tf-analyze-baseline.json -> ../../.bashrc` would have that
 * file overwritten when the user suppresses a finding. This refuses a
 * symlinked target outright, then writes a fresh sibling file (`wx`
 * fails if anything already sits at that name) and renames it into
 * place: a rename replaces the directory entry itself, so a symlink
 * swapped in between the check and the write is replaced, not followed.
 * Mirrors the engine's `--apply-fixes` guard. */
function writeFileNoFollow(file, text) {
    let st;
    try {
        st = fs.lstatSync(file);
    }
    catch {
        st = undefined;
    }
    if (st && st.isSymbolicLink()) {
        throw new Error(`refusing to write ${file}: it is a symlink`);
    }
    if (st && !st.isFile()) {
        throw new Error(`refusing to write ${file}: not a regular file`);
    }
    const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
    try {
        fs.writeFileSync(tmp, text, { encoding: 'utf8', flag: 'wx', mode: st ? st.mode & 0o777 : 0o644 });
        fs.renameSync(tmp, file);
    }
    catch (e) {
        try {
            fs.unlinkSync(tmp);
        }
        catch { /* already renamed or never created */ }
        throw e;
    }
}
/** Write `text` to a new file in a private temp directory and return its
 * path. A fixed or guessable name in the shared temp dir could be a
 * symlink another local user planted; `mkdtemp` gives a fresh 0700
 * directory, so nothing else can be waiting at the name. */
function writePrivateTempFile(name, text) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tf-analyze-'));
    const file = path.join(dir, name);
    fs.writeFileSync(file, text, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    return file;
}
//# sourceMappingURL=safeWrite.js.map