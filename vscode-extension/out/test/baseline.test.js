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
const baseline_1 = require("../baseline");
/** Create a fresh temp workspace dir for each test. Returned dir is
 * cleaned up by the caller — node:test doesn't have a built-in
 * teardown the way mocha does, so we do it inline at the end of each
 * test. */
function freshWs() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-baseline-'));
}
function read(ws) {
    const raw = fs.readFileSync((0, baseline_1.baselinePath)(ws), 'utf8');
    return JSON.parse(raw);
}
(0, node_test_1.test)('baselinePath joins workspace + filename', () => {
    const ws = '/tmp/whatever';
    assert.equal((0, baseline_1.baselinePath)(ws), path.join(ws, baseline_1.BASELINE_FILENAME));
});
(0, node_test_1.test)('baselineExists returns false on a fresh workspace', () => {
    const ws = freshWs();
    try {
        assert.equal((0, baseline_1.baselineExists)(ws), false);
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('ensureBaselineFile creates an empty findings array when missing', () => {
    const ws = freshWs();
    try {
        const p = (0, baseline_1.ensureBaselineFile)(ws);
        assert.equal(p, (0, baseline_1.baselinePath)(ws));
        assert.equal((0, baseline_1.baselineExists)(ws), true);
        const parsed = read(ws);
        assert.deepEqual(parsed.findings, []);
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('ensureBaselineFile is non-destructive when the file already exists', () => {
    const ws = freshWs();
    try {
        fs.writeFileSync((0, baseline_1.baselinePath)(ws), JSON.stringify({ findings: [{ id: 'PRE', file: 'a.tf', line: 1 }] }));
        (0, baseline_1.ensureBaselineFile)(ws);
        const parsed = read(ws);
        assert.equal(parsed.findings.length, 1);
        assert.equal(parsed.findings[0].id, 'PRE');
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('suppress adds a finding and returns true; second call is a no-op returning false', () => {
    const ws = freshWs();
    try {
        const f = { id: 'SEC-AWS-S3-001', file: 'main.tf', line: 17, resource: 'aws_s3_bucket.x' };
        assert.equal((0, baseline_1.suppress)(ws, f), true);
        assert.equal((0, baseline_1.suppress)(ws, f), false, 'second suppress for same key should be a no-op');
        const parsed = read(ws);
        assert.equal(parsed.findings.length, 1);
        assert.equal(parsed.findings[0].id, 'SEC-AWS-S3-001');
        assert.equal(parsed.findings[0].file, 'main.tf');
        assert.equal(parsed.findings[0].line, 17);
        assert.equal(parsed.findings[0].resource, 'aws_s3_bucket.x');
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('suppress preserves multiple findings with distinct keys', () => {
    const ws = freshWs();
    try {
        (0, baseline_1.suppress)(ws, { id: 'A', file: 'x.tf', line: 1 });
        (0, baseline_1.suppress)(ws, { id: 'A', file: 'x.tf', line: 2 }); // same id, different line
        (0, baseline_1.suppress)(ws, { id: 'B', file: 'x.tf', line: 1 }); // same line, different id
        (0, baseline_1.suppress)(ws, { id: 'A', file: 'y.tf', line: 1 }); // same id+line, different file
        (0, baseline_1.suppress)(ws, { id: 'A', file: 'x.tf', line: 1, resource: 'r' }); // same id+file+line, different resource
        const parsed = read(ws);
        assert.equal(parsed.findings.length, 5, 'each distinct (id, file, line, resource) should produce a record');
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('unsuppress removes the matching finding and returns true; missing keys return false', () => {
    const ws = freshWs();
    try {
        (0, baseline_1.suppress)(ws, { id: 'A', file: 'x.tf', line: 1 });
        (0, baseline_1.suppress)(ws, { id: 'B', file: 'x.tf', line: 2 });
        assert.equal((0, baseline_1.unsuppress)(ws, { id: 'A', file: 'x.tf', line: 1 }), true);
        assert.equal((0, baseline_1.unsuppress)(ws, { id: 'A', file: 'x.tf', line: 1 }), false, 'already removed key should return false');
        assert.equal((0, baseline_1.unsuppress)(ws, { id: 'NOPE', file: 'x.tf', line: 99 }), false);
        const parsed = read(ws);
        assert.equal(parsed.findings.length, 1);
        assert.equal(parsed.findings[0].id, 'B');
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('unsuppress on a non-existent baseline file is a safe no-op', () => {
    const ws = freshWs();
    try {
        assert.equal((0, baseline_1.baselineExists)(ws), false);
        assert.equal((0, baseline_1.unsuppress)(ws, { id: 'A', file: 'x.tf', line: 1 }), false);
        assert.equal((0, baseline_1.baselineExists)(ws), false, 'unsuppress should not create the file just to remove nothing');
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('write injects meta.last_updated timestamp', () => {
    const ws = freshWs();
    try {
        (0, baseline_1.suppress)(ws, { id: 'A', file: 'x.tf', line: 1 });
        const parsed = read(ws);
        const meta = parsed.meta;
        assert.ok(meta?.last_updated, 'meta.last_updated should be present');
        assert.ok(meta?.created_by?.includes('vscode-extension'), 'meta.created_by should identify the writer');
        // Timestamp should be a valid ISO string
        assert.ok(!isNaN(Date.parse(meta?.last_updated ?? '')), 'meta.last_updated should be parseable as ISO 8601');
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('a corrupted baseline file is treated as empty rather than crashing', () => {
    const ws = freshWs();
    try {
        fs.writeFileSync((0, baseline_1.baselinePath)(ws), 'this is not JSON {{{', 'utf8');
        // suppress should still succeed — read() returns {findings: []} on parse error
        const added = (0, baseline_1.suppress)(ws, { id: 'A', file: 'x.tf', line: 1 });
        assert.equal(added, true);
        const parsed = read(ws);
        assert.equal(parsed.findings.length, 1, 'corrupted file should be replaced with one containing only the new finding');
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
(0, node_test_1.test)('a baseline file without a findings array is treated as empty', () => {
    const ws = freshWs();
    try {
        fs.writeFileSync((0, baseline_1.baselinePath)(ws), JSON.stringify({ meta: { foo: 1 } }));
        const added = (0, baseline_1.suppress)(ws, { id: 'A', file: 'x.tf', line: 1 });
        assert.equal(added, true);
        const parsed = read(ws);
        assert.equal(parsed.findings.length, 1);
    }
    finally {
        fs.rmSync(ws, { recursive: true, force: true });
    }
});
//# sourceMappingURL=baseline.test.js.map