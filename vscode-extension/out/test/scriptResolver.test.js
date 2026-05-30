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
function pyCfg(pythonPath) {
    return {
        get(section, defaultValue) {
            return (section === 'pythonPath' ? pythonPath : defaultValue);
        },
    };
}
(0, node_test_1.test)('resolvePython honours tf-analyze.pythonPath when set', () => {
    assert.equal((0, scriptResolver_1.resolvePython)(pyCfg('/opt/venv/bin/python')), '/opt/venv/bin/python');
});
(0, node_test_1.test)('resolvePython falls back to a platform interpreter when unset', () => {
    // 'python' on win32, 'python3' elsewhere — assert it picked one of them
    // (the old hardcoded 'python3' broke Windows installs lacking it).
    const got = (0, scriptResolver_1.resolvePython)(pyCfg(''));
    assert.ok(got === 'python' || got === 'python3', `unexpected default: ${got}`);
});
// Every test in this file disables the bundled-engine check unless it
// specifically wants to exercise it. The bundled engine ships at
// `<extensionRoot>/engine/detect.py` after `npm run bundle-engine`,
// and would otherwise win over every workspace stub the tests build.
const NO_BUNDLE = { bundledEnginePath: null };
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
        const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg(scriptFile), repo, NO_BUNDLE);
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
        const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg(dir), repo, NO_BUNDLE);
        assert.equal(resolved, scriptFile);
    }
    finally {
        fs.rmSync(repo, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('falls back to <ws>/scripts/detect.py when the configured path is invalid', () => {
    const { repo, scriptFile } = makeRepoLayout();
    try {
        const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg('/nonexistent/path/detect.py'), repo, NO_BUNDLE);
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
        const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg(''), fixture, NO_BUNDLE);
        assert.equal(resolved, scriptFile);
    }
    finally {
        fs.rmSync(repo, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('returns null when no detect.py is reachable', () => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-resolver-empty-'));
    try {
        const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg(''), ws, NO_BUNDLE);
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
            const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg(empty), repo, NO_BUNDLE);
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
// ─── Bundled-engine path ────────────────────────────────────────────
(0, node_test_1.test)('BUNDLED_ENGINE_PATH points at <extensionRoot>/engine/scripts/detect.py', () => {
    // resolveScriptPath uses path.resolve(__dirname, '..', 'engine',
    // 'scripts', 'detect.py'). The engine/ subtree mirrors the source
    // repo's layout so detect.py's default `--catalog` lookup
    // (Path(__file__).parent.parent / "catalog") resolves to the
    // bundled catalog at engine/catalog/ without any extension-side
    // flag plumbing.
    assert.ok(scriptResolver_1.BUNDLED_ENGINE_PATH.endsWith(path.join('engine', 'scripts', 'detect.py')), `expected bundled path to end with engine/scripts/detect.py, got ${scriptResolver_1.BUNDLED_ENGINE_PATH}`);
});
(0, node_test_1.test)('resolver picks the bundled engine first when present', () => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-resolver-bundled-'));
    try {
        // Even though a workspace-relative detect.py exists, the bundled
        // path should win — that's what makes the .vsix self-contained.
        fs.mkdirSync(path.join(ws, 'scripts'));
        fs.writeFileSync(path.join(ws, 'scripts', 'detect.py'), '#!/usr/bin/env python3\nprint("workspace")');
        const fakeBundled = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-bundled-'));
        const fakeBundledFile = path.join(fakeBundled, 'detect.py');
        fs.writeFileSync(fakeBundledFile, '#!/usr/bin/env python3\nprint("bundled")');
        try {
            const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg(''), ws, { bundledEnginePath: fakeBundledFile });
            assert.equal(resolved, fakeBundledFile, 'bundled engine should win over workspace fallback');
        }
        finally {
            fs.rmSync(fakeBundled, { recursive: true, force: true });
        }
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('resolver falls back to workspace search when bundled engine is missing', () => {
    const { repo, scriptFile } = makeRepoLayout();
    try {
        const resolved = (0, scriptResolver_1.resolveScriptPath)(cfg(''), repo, { bundledEnginePath: '/nonexistent/bundled/detect.py' });
        assert.equal(resolved, scriptFile);
    }
    finally {
        fs.rmSync(repo, { recursive: true, force: true });
    }
});
//# sourceMappingURL=scriptResolver.test.js.map