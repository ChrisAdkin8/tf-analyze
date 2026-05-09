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
const node_test_1 = require("node:test");
const assert = __importStar(require("node:assert/strict"));
const fs = __importStar(require("node:fs"));
const os = __importStar(require("node:os"));
const path = __importStar(require("node:path"));
const scriptResolver_1 = require("../scriptResolver");
/** Stub for vscode.WorkspaceConfiguration. The resolver only calls
 * `cfg.get<string>('scriptPath', '')` so a minimal {get} object is
 * enough — typed loosely to match the shape without bringing the
 * vscode runtime in. */
function cfg(scriptPath) {
    return {
        get(section, defaultValue) {
            if (section === 'scriptPath')
                return scriptPath;
            return defaultValue;
        },
    };
}
function makeRepoLayout() {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-resolver-'));
    fs.mkdirSync(path.join(repo, 'scripts'));
    const scriptFile = path.join(repo, 'scripts', 'detect.py');
    fs.writeFileSync(scriptFile, '#!/usr/bin/env python3\nprint("stub")\n');
    return { repo, scriptFile };
}
(0, node_test_1.test)('resolves a configured absolute file path verbatim', () => {
    const { repo, scriptFile } = makeRepoLayout();
    try {
        const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg(scriptFile), repo);
        assert.equal(resolved, scriptFile);
    }
    finally {
        fs.rmSync(repo, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('configured directory is treated as "look for detect.py inside"', () => {
    const { repo, scriptFile } = makeRepoLayout();
    try {
        // Point scriptPath at the directory, not the file — the
        // misconfiguration that produced `python3 <dir>` and the
        // "can't find '__main__' module" crash before 0.1.11.
        const dir = path.dirname(scriptFile);
        const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg(dir), repo);
        assert.equal(resolved, scriptFile);
    }
    finally {
        fs.rmSync(repo, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('falls back to <ws>/scripts/detect.py when the configured path is invalid', () => {
    const { repo, scriptFile } = makeRepoLayout();
    try {
        const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg('/nonexistent/path/detect.py'), repo);
        assert.equal(resolved, scriptFile);
    }
    finally {
        fs.rmSync(repo, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('walks parent directories to find scripts/detect.py when workspace is a nested fixture', () => {
    const { repo, scriptFile } = makeRepoLayout();
    try {
        // Workspace is a fixture two levels deep — none of the workspace-
        // relative fallbacks match, only the parent walk does.
        const fixture = path.join(repo, 'fixtures', 'attack_graph_demo');
        fs.mkdirSync(fixture, { recursive: true });
        fs.writeFileSync(path.join(fixture, 'main.tf'), 'resource "aws_s3_bucket" "x" {}');
        const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg(''), fixture);
        assert.equal(resolved, scriptFile);
    }
    finally {
        fs.rmSync(repo, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('returns null when no detect.py is reachable', () => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-resolver-empty-'));
    try {
        const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg(''), ws);
        assert.equal(resolved, null);
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('configured path that points at a non-script directory falls through to fallbacks', () => {
    const { repo, scriptFile } = makeRepoLayout();
    try {
        // Point scriptPath at a directory that has no detect.py inside —
        // resolver should fall through to the workspace fallback.
        const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-resolver-empty-cfg-'));
        try {
            const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg(empty), repo);
            assert.equal(resolved, scriptFile);
        }
        finally {
            fs.rmSync(empty, { recursive: true, force: true });
        }
    }
    finally {
        fs.rmSync(repo, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('defaultSearchPaths produces the workspace-relative trio', () => {
    const ws = '/tmp/some-ws';
    const paths = (0, scriptResolver_1.defaultSearchPaths)(ws);
    assert.equal(paths.length, 3);
    assert.equal(paths[0], path.join(ws, 'scripts', 'detect.py'));
    assert.equal(paths[1], path.join(ws, 'detect.py'));
    // Sibling-clone case
    assert.ok(paths[2].endsWith(path.join('tf-analyze', 'scripts', 'detect.py')));
});
//# sourceMappingURL=scriptResolver.test.js.map