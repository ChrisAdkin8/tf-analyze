"use strict";
// Single source of truth for the per-rule documentation URL pattern.
// The engine's `RULE_DOCS_URL_BASE` (in scripts/detect.py) holds the
// matching string; both must point at the same Pages site so the
// Problems pane, hover tooltips, recommendation webview, MITRE view,
// delta view, and compliance panel all agree on where rule IDs land.
//
// Switching to a custom domain (e.g. https://tf-analyze.dev/rules/...)
// is a one-line edit here AND in scripts/detect.py.
Object.defineProperty(exports, "__esModule", { value: true });
exports.RULE_DOCS_URL_BASE = void 0;
exports.ruleDocsUrl = ruleDocsUrl;
exports.ruleAnchorHtml = ruleAnchorHtml;
exports.RULE_DOCS_URL_BASE = 'https://chrisadkin8.github.io/tf-analyze/rules/';
/** Resolve a rule ID to its canonical docs URL. */
function ruleDocsUrl(ruleId) {
    return `${exports.RULE_DOCS_URL_BASE}${ruleId}.html`;
}
/** Wrap a rule ID for HTML output as an anchor that opens in a new tab. */
function ruleAnchorHtml(ruleId, label) {
    const url = ruleDocsUrl(ruleId);
    const text = label ?? ruleId;
    return `<a href="${url}" target="_blank" rel="noopener" title="Open rule documentation"><code>${text}</code></a>`;
}
//# sourceMappingURL=urls.js.map