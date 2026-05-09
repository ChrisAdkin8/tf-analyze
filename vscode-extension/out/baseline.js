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
exports.BASELINE_FILENAME = void 0;
exports.baselinePath = baselinePath;
exports.baselineExists = baselineExists;
exports.suppress = suppress;
exports.unsuppress = unsuppress;
exports.ensureBaselineFile = ensureBaselineFile;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
/** Filename relative to the workspace root. Picked to be discoverable
 * by users (visible in the file tree, not hidden in `.vscode/`) but
 * obviously a config file (leading dot, kebab-case). */
exports.BASELINE_FILENAME = '.tf-analyze-baseline.json';
function baselinePath(wsFolder) {
    return path.join(wsFolder, exports.BASELINE_FILENAME);
}
function baselineExists(wsFolder) {
    try {
        return fs.statSync(baselinePath(wsFolder)).isFile();
    }
    catch {
        return false;
    }
}
function read(wsFolder) {
    if (!baselineExists(wsFolder))
        return { findings: [] };
    try {
        const raw = fs.readFileSync(baselinePath(wsFolder), 'utf8');
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed.findings))
            return { findings: [] };
        return parsed;
    }
    catch {
        return { findings: [] };
    }
}
function write(wsFolder, data) {
    data.meta = { ...(data.meta ?? {}), last_updated: new Date().toISOString(), created_by: 'tf-analyze (vscode-extension)' };
    fs.writeFileSync(baselinePath(wsFolder), JSON.stringify(data, null, 2) + '\n', 'utf8');
}
/** Match key compatible with the engine's (id, file, line, resource)
 * suppression criterion. Keep this in sync with detect.py — if the
 * engine ever loosens the criterion, remove fields from the key here
 * to mirror it. */
function key(f) {
    return [f.id, f.file, f.line, f.resource ?? ''].join('|');
}
/** Add a finding to the baseline. Idempotent — re-suppressing the same
 * finding is a no-op. Returns true if the file changed. */
function suppress(wsFolder, finding) {
    const data = read(wsFolder);
    const existing = new Set(data.findings.map(key));
    if (existing.has(key(finding)))
        return false;
    data.findings.push({
        id: finding.id,
        file: finding.file,
        line: finding.line,
        ...(finding.resource ? { resource: finding.resource } : {}),
    });
    write(wsFolder, data);
    return true;
}
/** Remove a finding from the baseline. Returns true if a record was
 * actually removed. */
function unsuppress(wsFolder, finding) {
    if (!baselineExists(wsFolder))
        return false;
    const data = read(wsFolder);
    const before = data.findings.length;
    const k = key(finding);
    data.findings = data.findings.filter(f => key(f) !== k);
    if (data.findings.length === before)
        return false;
    write(wsFolder, data);
    return true;
}
/** Ensure a baseline file exists on disk. Returns the path. The
 * VS Code-side caller (extension.ts) opens the document via its own
 * `vscode.workspace.openTextDocument` call so this module stays free
 * of the runtime vscode import — which makes it unit-testable from
 * plain node, without spinning up an Electron host. */
function ensureBaselineFile(wsFolder) {
    if (!baselineExists(wsFolder)) {
        write(wsFolder, { findings: [] });
    }
    return baselinePath(wsFolder);
}
//# sourceMappingURL=baseline.js.map