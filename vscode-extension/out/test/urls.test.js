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
const urls_1 = require("../urls");
/**
 * Public-contract tests for the per-rule docs URL surface.
 *
 * Every clickable rule ID surface in the extension goes through these
 * helpers — diagnostic.code in the Problems pane, the recommendation
 * webview, the delta panel, the MITRE view. If a future change moves
 * the URL pattern (e.g. to a custom domain), these tests force the
 * matching update in scripts/detect.py:RULE_DOCS_URL_BASE.
 */
(0, node_test_1.test)('RULE_DOCS_URL_BASE points at the GitHub Pages site', () => {
    assert.equal(urls_1.RULE_DOCS_URL_BASE, 'https://chrisadkin8.github.io/tf-analyze/rules/', 'URL base drifted from the engine\'s RULE_DOCS_URL_BASE — both must match.');
});
(0, node_test_1.test)('ruleDocsUrl appends <id>/ (pretty URL, not .html)', () => {
    // GitHub Pages serves Jekyll pages at pretty-URL paths.
    // `/<id>.html` returns 404; `/<id>/` is the canonical form.
    assert.equal((0, urls_1.ruleDocsUrl)('SEC-AWS-IAM-001'), 'https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-001/');
});
(0, node_test_1.test)('ruleDocsUrl handles all known rule prefixes', () => {
    for (const prefix of ['SEC', 'ROB', 'STK', 'OPS', 'MOD', 'COST', 'INT', 'CI', 'STYLE', 'CUSTOM']) {
        const id = `${prefix}-EXAMPLE-001`;
        assert.match((0, urls_1.ruleDocsUrl)(id), new RegExp(`^https://chrisadkin8\\.github\\.io/tf-analyze/rules/${id}/$`), `bad URL for prefix ${prefix}: ${(0, urls_1.ruleDocsUrl)(id)}`);
    }
});
(0, node_test_1.test)('ruleAnchorHtml produces a valid anchor with target="_blank"', () => {
    const html = (0, urls_1.ruleAnchorHtml)('SEC-AWS-EBS-001');
    assert.match(html, /<a href="https:\/\/chrisadkin8\.github\.io\/tf-analyze\/rules\/SEC-AWS-EBS-001\/"/);
    assert.match(html, /target="_blank"/);
    assert.match(html, /rel="noopener"/);
    assert.match(html, /title="Open rule documentation"/);
    assert.match(html, /<code>SEC-AWS-EBS-001<\/code>/);
});
(0, node_test_1.test)('ruleAnchorHtml supports a custom label', () => {
    const html = (0, urls_1.ruleAnchorHtml)('SEC-AWS-EBS-001', 'Custom Label');
    assert.match(html, /<code>Custom Label<\/code>/);
});
//# sourceMappingURL=urls.test.js.map