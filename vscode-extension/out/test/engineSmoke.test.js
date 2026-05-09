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
const node_child_process_1 = require("node:child_process");
const fs = __importStar(require("node:fs"));
const os = __importStar(require("node:os"));
const path = __importStar(require("node:path"));
/** End-to-end engine smoke tests for the remediation surface. These
 * spawn the real `python3 detect.py` so they catch upstream regressions
 * (the kind that broke compliance + apply-fixes earlier in this
 * release cycle) before users hit them through the panel.
 *
 * The test suite is skipped when python3 isn't on PATH or the engine
 * isn't located via the same parent-walk strategy the resolver uses —
 * keeping CI green on contributor laptops without the repo cloned.
 */
function findEngine() {
    // Walk up from this file's compiled location toward repo root looking
    // for scripts/detect.py. node:test runs from out/test, so the repo is
    // 4 levels up at most.
    let dir = __dirname;
    for (let i = 0; i < 8; i++) {
        const cand = path.join(dir, 'scripts', 'detect.py');
        if (fs.existsSync(cand) && fs.statSync(cand).isFile())
            return cand;
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    return null;
}
function pythonAvailable() {
    try {
        (0, node_child_process_1.execFileSync)('python3', ['--version'], { stdio: 'ignore' });
        return true;
    }
    catch {
        return false;
    }
}
function copyFixture(src) {
    const dst = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-engine-'));
    for (const entry of fs.readdirSync(src)) {
        fs.copyFileSync(path.join(src, entry), path.join(dst, entry));
    }
    return dst;
}
const engine = findEngine();
const py = pythonAvailable();
const skip = !engine || !py;
const skipReason = !py ? 'python3 not on PATH' : !engine ? 'detect.py not located' : '';
(0, node_test_1.test)('engine: --apply-fixes dry-run produces a unified diff for the demo fixture', { skip: skip && skipReason }, () => {
    const repo = path.dirname(path.dirname(engine));
    const fixture = path.join(repo, 'fixtures', 'attack_graph_demo');
    if (!fs.existsSync(fixture)) {
        // No fixture in this checkout — skip gracefully rather than fail
        return;
    }
    const target = copyFixture(fixture);
    try {
        let stdout = '';
        try {
            stdout = (0, node_child_process_1.execFileSync)('python3', [engine, '--target', target, '--apply-fixes', 'dry-run'], {
                encoding: 'utf8',
                maxBuffer: 50 * 1024 * 1024,
            });
        }
        catch (e) {
            const err = e;
            // exit 1 = findings present, expected for the demo
            stdout = err.stdout ?? '';
        }
        assert.ok(stdout.includes('--- '), 'dry-run should emit at least one unified-diff file header');
        assert.ok(stdout.includes('+++ '), 'dry-run should emit the +++ side of the unified diff');
        assert.ok(stdout.includes('@@'), 'dry-run should emit at least one hunk header');
    }
    finally {
        fs.rmSync(target, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('engine: --apply-fixes apply mutates source and writes a .bak alongside', { skip: skip && skipReason }, () => {
    const repo = path.dirname(path.dirname(engine));
    const fixture = path.join(repo, 'fixtures', 'attack_graph_demo');
    if (!fs.existsSync(fixture))
        return;
    const target = copyFixture(fixture);
    try {
        const sourceFile = path.join(target, 'main.tf');
        const backupFile = sourceFile + '.bak';
        const before = fs.readFileSync(sourceFile, 'utf8');
        assert.equal(fs.existsSync(backupFile), false, 'no .bak should exist before apply');
        try {
            (0, node_child_process_1.execFileSync)('python3', [engine, '--target', target, '--apply-fixes', 'apply'], {
                encoding: 'utf8',
                maxBuffer: 50 * 1024 * 1024,
            });
        }
        catch (e) {
            // Engine exits 1 when findings remain — expected.
            const err = e;
            if (err.status !== undefined && err.status > 1)
                throw e;
        }
        assert.ok(fs.existsSync(backupFile), 'apply should leave a .bak alongside the patched file');
        const backupContent = fs.readFileSync(backupFile, 'utf8');
        const after = fs.readFileSync(sourceFile, 'utf8');
        assert.equal(backupContent, before, '.bak should be a verbatim copy of the original');
        assert.notEqual(after, before, 'patched file should differ from the original');
        // Spot-check: the demo fixture is missing aws_instance metadata_options;
        // the engine's fix_hcl should have inserted that block.
        assert.ok(after.includes('metadata_options'), 'patched main.tf should contain the metadata_options block the engine inserted');
    }
    finally {
        fs.rmSync(target, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('engine: --apply-fixes survives findings whose `file` is the target directory (regression for IsADirectoryError)', { skip: skip && skipReason }, () => {
    const repo = path.dirname(path.dirname(engine));
    const fixture = path.join(repo, 'fixtures', 'attack_graph_demo');
    if (!fs.existsSync(fixture))
        return;
    const target = copyFixture(fixture);
    try {
        // The demo fixture emits absent-resource findings (e.g.
        // ROB-AWS-BACKUP-001 with file=<target dir>:0). Pre-fix this
        // crashed _handle_apply_fixes with IsADirectoryError — the call
        // below should now exit cleanly with code 0 or 1 (findings).
        let exit = 0;
        try {
            (0, node_child_process_1.execFileSync)('python3', [engine, '--target', target, '--apply-fixes', 'dry-run'], {
                encoding: 'utf8',
                maxBuffer: 50 * 1024 * 1024,
            });
        }
        catch (e) {
            const err = e;
            exit = err.status ?? 0;
            // If we did crash, surface the traceback so the regression is obvious.
            if (exit > 1)
                throw new Error(`apply-fixes regressed (exit ${exit}): ${err.stderr ?? ''}`);
        }
        assert.ok(exit === 0 || exit === 1, `expected exit 0 or 1, got ${exit}`);
    }
    finally {
        fs.rmSync(target, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('engine: --format compliance runs without TypeError on str/int sort (regression for _ctrl_sort_key)', { skip: skip && skipReason }, () => {
    const repo = path.dirname(path.dirname(engine));
    const target = path.join(repo, 'examples', 'terragoat', 'aws');
    if (!fs.existsSync(target))
        return;
    let stdout = '';
    try {
        stdout = (0, node_child_process_1.execFileSync)('python3', [engine, '--target', target, '--format', 'compliance', '--compliance-framework', 'cis'], {
            encoding: 'utf8',
            maxBuffer: 50 * 1024 * 1024,
        });
    }
    catch (e) {
        const err = e;
        // Exit 1 is fine (findings present); >1 indicates a crash.
        if ((err.status ?? 0) > 1)
            throw new Error(`compliance regressed: ${err.stderr ?? ''}`);
        stdout = err.stdout ?? '';
    }
    assert.ok(stdout.includes('Compliance Gap Report'), 'compliance output should include the gap-report heading');
    assert.ok(stdout.includes('CIS'), 'compliance output should mention the requested framework');
});
//# sourceMappingURL=engineSmoke.test.js.map