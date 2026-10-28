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
const safeWrite_1 = require("../safeWrite");
const baseline_1 = require("../baseline");
function fresh() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-safewrite-'));
}
(0, node_test_1.test)('a symlinked baseline is refused and its target left alone', () => {
    const root = fresh();
    try {
        const ws = path.join(root, 'ws');
        fs.mkdirSync(ws);
        const victim = path.join(root, 'victim');
        fs.writeFileSync(victim, 'keep me\n');
        // A cloned repo can commit this link.
        fs.symlinkSync(victim, path.join(ws, baseline_1.BASELINE_FILENAME));
        assert.throws(() => (0, baseline_1.suppress)(ws, { id: 'SEC-AWS-SG-001', file: 'main.tf', line: 1 }), /symlink/);
        assert.equal(fs.readFileSync(victim, 'utf8'), 'keep me\n');
        assert.equal(fs.readdirSync(ws).length, 1, 'no temp file left behind');
    }
    finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('a symlinked .tf-analyze.yaml is refused', () => {
    const root = fresh();
    try {
        const victim = path.join(root, 'victim');
        fs.writeFileSync(victim, 'keep me\n');
        const link = path.join(root, '.tf-analyze.yaml');
        fs.symlinkSync(victim, link);
        assert.throws(() => (0, safeWrite_1.writeFileNoFollow)(link, 'ignore_rules:\n  - X\n'), /symlink/);
        assert.equal(fs.readFileSync(victim, 'utf8'), 'keep me\n');
    }
    finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('a directory at the path is refused', () => {
    const root = fresh();
    try {
        const dir = path.join(root, baseline_1.BASELINE_FILENAME);
        fs.mkdirSync(dir);
        assert.throws(() => (0, safeWrite_1.writeFileNoFollow)(dir, '{}'), /not a regular file/);
    }
    finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('a regular file is replaced and keeps its mode', () => {
    const ws = fresh();
    try {
        const file = (0, baseline_1.ensureBaselineFile)(ws);
        fs.chmodSync(file, 0o640);
        assert.equal((0, baseline_1.suppress)(ws, { id: 'SEC-AWS-SG-001', file: 'main.tf', line: 1 }), true);
        assert.match(fs.readFileSync(file, 'utf8'), /SEC-AWS-SG-001/);
        assert.equal(fs.statSync(file).mode & 0o777, 0o640);
        assert.deepEqual(fs.readdirSync(ws), [baseline_1.BASELINE_FILENAME]);
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('report temp files go in a fresh private directory', () => {
    const a = (0, safeWrite_1.writePrivateTempFile)('tf-analyze-ws.html', '<p>a</p>');
    const b = (0, safeWrite_1.writePrivateTempFile)('tf-analyze-ws.html', '<p>b</p>');
    try {
        assert.notEqual(path.dirname(a), path.dirname(b));
        assert.equal(fs.readFileSync(a, 'utf8'), '<p>a</p>');
        assert.equal(fs.statSync(path.dirname(a)).mode & 0o077, 0);
        assert.equal(fs.statSync(a).mode & 0o077, 0);
    }
    finally {
        fs.rmSync(path.dirname(a), { recursive: true, force: true });
        fs.rmSync(path.dirname(b), { recursive: true, force: true });
    }
});
//# sourceMappingURL=safeWrite.test.js.map