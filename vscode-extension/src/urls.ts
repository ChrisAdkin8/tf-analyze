// Single source of truth for the per-rule documentation URL pattern.
// The engine's `RULE_DOCS_URL_BASE` (in scripts/detect.py) holds the
// matching string; both must point at the same Pages site so the
// Problems pane, hover tooltips, recommendation webview, MITRE view,
// delta view, and compliance panel all agree on where rule IDs land.
//
// Switching to a custom domain (e.g. https://tf-analyze.dev/rules/...)
// is a one-line edit here AND in scripts/detect.py.

export const RULE_DOCS_URL_BASE =
  'https://chrisadkin8.github.io/tf-analyze/rules/';

/** Resolve a rule ID to its canonical docs URL.
 *
 * GitHub Pages serves Jekyll-rendered pages at pretty-URL paths
 * (`/rules/<id>/`), not at `/rules/<id>.html` — the .html extension
 * returns 404. The trailing slash matches what Pages publishes and
 * matches RULE_DOCS_URL_BASE in scripts/detect.py.
 */
export function ruleDocsUrl(ruleId: string): string {
  return `${RULE_DOCS_URL_BASE}${ruleId}/`;
}

/** Wrap a rule ID for HTML output as an anchor that opens in a new tab. */
export function ruleAnchorHtml(ruleId: string, label?: string): string {
  const url = ruleDocsUrl(ruleId);
  const text = label ?? ruleId;
  return `<a href="${url}" target="_blank" rel="noopener" title="Open rule documentation"><code>${text}</code></a>`;
}
