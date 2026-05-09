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
const uriHandler_1 = require("../uriHandler");
/**
 * Tests for the `vscode://tfanalyze.tf-analyze/<verb>` URI surface.
 *
 * The extension exposes four verbs (`/rule/`, `/scan`, `/explain`,
 * `/suppress`) that browsers can route to VS Code via the OS handler.
 * Each verb has a strict validator. These tests pin:
 *
 *   * The validator regex for rule IDs (mirrors detect.py's expectation)
 *   * Path-traversal / null-byte / non-absolute rejection on every
 *     path-shaped argument
 *   * Workspace-scoping on /scan and /suppress (a hostile link must
 *     not be able to scan or write outside the active workspace)
 *   * Both shapes of /suppress (with and without file+line)
 *
 * The dispatcher is intentionally pure — it takes a `ParsedUri` and a
 * record of side-effect callbacks, so we can simulate any URI shape
 * without spinning up VS Code.
 */
const WS = "/Users/me/projects/example";
function makeUri(path, query = "") {
    return {
        path,
        query,
        toString: () => `vscode://tfanalyze.tf-analyze${path}${query ? `?${query}` : ""}`,
    };
}
function makeHandlers(workspacePath = WS) {
    const calls = {
        openRule: [],
        runScan: [],
        openLocation: [],
        suppressFinding: [],
        suppressRuleWorkspaceWide: [],
        warn: [],
        log: [],
    };
    const handlers = {
        openRule: (id) => calls.openRule.push(id),
        runScan: (target) => calls.runScan.push(target),
        openLocation: (file, line) => calls.openLocation.push({ file, line }),
        suppressFinding: (ruleId, file, line) => calls.suppressFinding.push({ ruleId, file, line }),
        suppressRuleWorkspaceWide: (id) => calls.suppressRuleWorkspaceWide.push(id),
        workspacePath: () => workspacePath,
        warn: (msg) => calls.warn.push(msg),
        log: (msg) => calls.log.push(msg),
    };
    return { handlers, calls };
}
// ─── Validator helpers ──────────────────────────────────────────────────
(0, node_test_1.test)('RULE_ID_RE accepts canonical catalogue IDs', () => {
    for (const id of [
        'SEC-AWS-IAM-001', 'ROB-AWS-RDS-001', 'STK-AWS-EKS-001',
        'OPS-ENV-001', 'MOD-PIN-001', 'COST-AWS-RISK-001',
        'INT-INTENT-001', 'CI-TEST-001', 'CUSTOM-X-001',
        // Realistic 4-segment IDs.
        'SEC-AWS-IAM-POLICY-001', 'SEC-K8S-HELM-002',
    ]) {
        assert.ok(uriHandler_1.RULE_ID_RE.test(id), `must accept ${id}`);
    }
});
(0, node_test_1.test)('RULE_ID_RE rejects malformed IDs (lowercase, spaces, traversal)', () => {
    for (const bad of [
        '', 'sec-aws-iam-001', 'SEC AWS IAM 001', 'SEC/AWS/IAM/001',
        '../etc/passwd', 'A', 'AB', 'SEC-001\n', 'SEC-001;rm',
    ]) {
        assert.equal(uriHandler_1.RULE_ID_RE.test(bad), false, `must reject ${JSON.stringify(bad)}`);
    }
});
(0, node_test_1.test)('safePath accepts well-formed absolute paths', () => {
    assert.equal((0, uriHandler_1.safePath)('/Users/me/repo/main.tf'), '/Users/me/repo/main.tf');
    assert.equal((0, uriHandler_1.safePath)('/'), '/');
});
(0, node_test_1.test)('safePath rejects relative, null-byte, traversal, and oversize paths', () => {
    assert.equal((0, uriHandler_1.safePath)(null), null);
    assert.equal((0, uriHandler_1.safePath)(undefined), null);
    assert.equal((0, uriHandler_1.safePath)(''), null);
    assert.equal((0, uriHandler_1.safePath)('relative/path.tf'), null);
    assert.equal((0, uriHandler_1.safePath)('/path/with\0null'), null);
    assert.equal((0, uriHandler_1.safePath)('/etc/../etc/passwd'), null);
    assert.equal((0, uriHandler_1.safePath)('/a/b/../c'), null);
    assert.equal((0, uriHandler_1.safePath)('/' + 'a'.repeat(2000)), null);
});
(0, node_test_1.test)('safeLine accepts 1-based positive integers', () => {
    assert.equal((0, uriHandler_1.safeLine)('1'), 1);
    assert.equal((0, uriHandler_1.safeLine)('42'), 42);
    assert.equal((0, uriHandler_1.safeLine)('1000000'), 1000000);
});
(0, node_test_1.test)('safeLine rejects zero, negative, non-integer, oversize values', () => {
    assert.equal((0, uriHandler_1.safeLine)(null), null);
    assert.equal((0, uriHandler_1.safeLine)(''), null);
    assert.equal((0, uriHandler_1.safeLine)('0'), null);
    assert.equal((0, uriHandler_1.safeLine)('-1'), null);
    assert.equal((0, uriHandler_1.safeLine)('1.5'), null);
    assert.equal((0, uriHandler_1.safeLine)('1e3'), null);
    assert.equal((0, uriHandler_1.safeLine)('abc'), null);
    assert.equal((0, uriHandler_1.safeLine)('1000001'), null);
});
// ─── /rule verb ─────────────────────────────────────────────────────────
(0, node_test_1.test)('/rule/<ID> → openRule', () => {
    const { handlers, calls } = makeHandlers();
    const result = (0, uriHandler_1.dispatchUri)(makeUri('/rule/SEC-AWS-IAM-001'), handlers);
    assert.deepEqual(result, { kind: 'rule', ruleId: 'SEC-AWS-IAM-001' });
    assert.deepEqual(calls.openRule, ['SEC-AWS-IAM-001']);
    assert.equal(calls.warn.length, 0);
});
(0, node_test_1.test)('/rule/ with malformed ID is rejected (no openRule)', () => {
    const { handlers, calls } = makeHandlers();
    const result = (0, uriHandler_1.dispatchUri)(makeUri('/rule/sec-aws-001'), handlers);
    assert.equal(result.kind, 'rejected');
    assert.equal(calls.openRule.length, 0);
    assert.equal(calls.warn.length, 1);
});
// ─── /scan verb ─────────────────────────────────────────────────────────
(0, node_test_1.test)('/scan?target=<workspace path> triggers runScan', () => {
    const { handlers, calls } = makeHandlers();
    const result = (0, uriHandler_1.dispatchUri)(makeUri('/scan', `target=${encodeURIComponent(WS)}`), handlers);
    assert.deepEqual(result, { kind: 'scan', target: WS });
    assert.deepEqual(calls.runScan, [WS]);
});
(0, node_test_1.test)('/scan?target=<inside workspace> triggers runScan', () => {
    const { handlers, calls } = makeHandlers();
    const inside = `${WS}/modules/network`;
    (0, uriHandler_1.dispatchUri)(makeUri('/scan', `target=${encodeURIComponent(inside)}`), handlers);
    assert.deepEqual(calls.runScan, [inside]);
});
(0, node_test_1.test)('/scan rejects targets outside the active workspace', () => {
    const { handlers, calls } = makeHandlers();
    const result = (0, uriHandler_1.dispatchUri)(makeUri('/scan', 'target=%2Fetc%2Fshadow'), handlers);
    assert.equal(result.kind, 'rejected');
    assert.equal(calls.runScan.length, 0);
    assert.match(calls.warn[0], /outside the active workspace/);
});
(0, node_test_1.test)('/scan with missing or malformed target is rejected', () => {
    const { handlers, calls } = makeHandlers();
    (0, uriHandler_1.dispatchUri)(makeUri('/scan'), handlers);
    (0, uriHandler_1.dispatchUri)(makeUri('/scan', 'target='), handlers);
    (0, uriHandler_1.dispatchUri)(makeUri('/scan', 'target=relative'), handlers);
    assert.equal(calls.runScan.length, 0);
    assert.equal(calls.warn.length, 3);
});
// ─── /explain verb ──────────────────────────────────────────────────────
(0, node_test_1.test)('/explain?id=<ID> opens rule explainer (no editor jump)', () => {
    const { handlers, calls } = makeHandlers();
    const result = (0, uriHandler_1.dispatchUri)(makeUri('/explain', 'id=SEC-AWS-IAM-001'), handlers);
    assert.equal(result.kind, 'explain');
    assert.deepEqual(calls.openRule, ['SEC-AWS-IAM-001']);
    assert.equal(calls.openLocation.length, 0);
});
(0, node_test_1.test)('/explain with valid id+file+line opens rule and jumps to location', () => {
    const { handlers, calls } = makeHandlers();
    (0, uriHandler_1.dispatchUri)(makeUri('/explain', `id=SEC-AWS-IAM-001&file=${encodeURIComponent(WS + '/main.tf')}&line=42`), handlers);
    assert.deepEqual(calls.openRule, ['SEC-AWS-IAM-001']);
    assert.deepEqual(calls.openLocation, [{ file: WS + '/main.tf', line: 42 }]);
});
(0, node_test_1.test)('/explain with invalid file or line opens rule but skips editor jump', () => {
    const { handlers, calls } = makeHandlers();
    (0, uriHandler_1.dispatchUri)(makeUri('/explain', `id=SEC-AWS-IAM-001&file=relative&line=42`), handlers);
    assert.deepEqual(calls.openRule, ['SEC-AWS-IAM-001']);
    assert.equal(calls.openLocation.length, 0);
});
(0, node_test_1.test)('/explain without id is rejected', () => {
    const { handlers, calls } = makeHandlers();
    (0, uriHandler_1.dispatchUri)(makeUri('/explain'), handlers);
    (0, uriHandler_1.dispatchUri)(makeUri('/explain', 'id=lowercase'), handlers);
    assert.equal(calls.openRule.length, 0);
    assert.equal(calls.warn.length, 2);
});
// ─── /suppress verb ─────────────────────────────────────────────────────
(0, node_test_1.test)('/suppress?id+file+line → per-finding baseline-add', () => {
    const { handlers, calls } = makeHandlers();
    const result = (0, uriHandler_1.dispatchUri)(makeUri('/suppress', `id=SEC-AWS-IAM-001&file=${encodeURIComponent(WS + '/main.tf')}&line=12`), handlers);
    assert.equal(result.kind, 'suppress-finding');
    assert.deepEqual(calls.suppressFinding, [
        { ruleId: 'SEC-AWS-IAM-001', file: WS + '/main.tf', line: 12 },
    ]);
    assert.equal(calls.suppressRuleWorkspaceWide.length, 0);
});
(0, node_test_1.test)('/suppress?id only → workspace-wide rule ignore', () => {
    const { handlers, calls } = makeHandlers();
    const result = (0, uriHandler_1.dispatchUri)(makeUri('/suppress', 'id=SEC-AWS-IAM-001'), handlers);
    assert.equal(result.kind, 'suppress-rule');
    assert.deepEqual(calls.suppressRuleWorkspaceWide, ['SEC-AWS-IAM-001']);
    assert.equal(calls.suppressFinding.length, 0);
});
(0, node_test_1.test)('/suppress refuses to baseline-add for files outside the workspace', () => {
    const { handlers, calls } = makeHandlers();
    const result = (0, uriHandler_1.dispatchUri)(makeUri('/suppress', 'id=SEC-AWS-IAM-001&file=%2Fetc%2Fshadow&line=1'), handlers);
    assert.equal(result.kind, 'rejected');
    assert.equal(calls.suppressFinding.length, 0);
    assert.match(calls.warn[0], /outside the active workspace/);
});
(0, node_test_1.test)('/suppress with malformed id is rejected', () => {
    const { handlers, calls } = makeHandlers();
    (0, uriHandler_1.dispatchUri)(makeUri('/suppress', 'id=lowercase'), handlers);
    (0, uriHandler_1.dispatchUri)(makeUri('/suppress'), handlers);
    assert.equal(calls.suppressFinding.length, 0);
    assert.equal(calls.suppressRuleWorkspaceWide.length, 0);
    assert.equal(calls.warn.length, 2);
});
(0, node_test_1.test)('/suppress with id + line but no file falls back to workspace-wide', () => {
    // file is missing but line is present → "id+file+line" branch
    // does not match (file is null), so the dispatcher falls to the
    // id-only branch.
    const { handlers, calls } = makeHandlers();
    const result = (0, uriHandler_1.dispatchUri)(makeUri('/suppress', 'id=SEC-AWS-IAM-001&line=12'), handlers);
    assert.equal(result.kind, 'suppress-rule');
    assert.deepEqual(calls.suppressRuleWorkspaceWide, ['SEC-AWS-IAM-001']);
});
// ─── Unknown / malicious paths ──────────────────────────────────────────
(0, node_test_1.test)('unknown path is rejected with a helpful message', () => {
    const { handlers, calls } = makeHandlers();
    const result = (0, uriHandler_1.dispatchUri)(makeUri('/admin/wipe'), handlers);
    assert.equal(result.kind, 'rejected');
    assert.match(calls.warn[0], /unrecognized URI path/);
});
(0, node_test_1.test)('empty path is rejected', () => {
    const { handlers, calls } = makeHandlers();
    const result = (0, uriHandler_1.dispatchUri)(makeUri(''), handlers);
    assert.equal(result.kind, 'rejected');
    assert.equal(calls.warn.length, 1);
});
// ─── Round-trip consistency: every successful dispatch returns its
// matched verb's discriminator, and every rejection includes a reason.
// ───────────────────────────────────────────────────────────────────────
(0, node_test_1.test)('every dispatched verb returns a stable discriminator', () => {
    const samples = [
        { uri: makeUri('/rule/SEC-AWS-IAM-001'), expectedKind: 'rule' },
        { uri: makeUri('/scan', `target=${encodeURIComponent(WS)}`), expectedKind: 'scan' },
        { uri: makeUri('/explain', 'id=SEC-AWS-IAM-001'), expectedKind: 'explain' },
        { uri: makeUri('/suppress', 'id=SEC-AWS-IAM-001'), expectedKind: 'suppress-rule' },
        {
            uri: makeUri('/suppress', `id=SEC-AWS-IAM-001&file=${encodeURIComponent(WS + '/x.tf')}&line=1`),
            expectedKind: 'suppress-finding',
        },
        { uri: makeUri('/nope'), expectedKind: 'rejected' },
    ];
    for (const s of samples) {
        const { handlers } = makeHandlers();
        const result = (0, uriHandler_1.dispatchUri)(s.uri, handlers);
        assert.equal(result.kind, s.expectedKind, `for ${s.uri.toString()}`);
    }
});
//# sourceMappingURL=uriHandler.test.js.map