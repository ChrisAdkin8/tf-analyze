import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { RULE_DOCS_URL_BASE, ruleDocsUrl, ruleAnchorHtml } from '../urls';

/**
 * Public-contract tests for the per-rule docs URL surface.
 *
 * Every clickable rule ID surface in the extension goes through these
 * helpers — diagnostic.code in the Problems pane, the recommendation
 * webview, the delta panel, the MITRE view. If a future change moves
 * the URL pattern (e.g. to a custom domain), these tests force the
 * matching update in scripts/detect.py:RULE_DOCS_URL_BASE.
 */

test('RULE_DOCS_URL_BASE points at the GitHub Pages site', () => {
  assert.equal(
    RULE_DOCS_URL_BASE,
    'https://chrisadkin8.github.io/tf-analyze/rules/',
    'URL base drifted from the engine\'s RULE_DOCS_URL_BASE — both must match.'
  );
});

test('ruleDocsUrl appends <id>/ (pretty URL, not .html)', () => {
  // GitHub Pages serves Jekyll pages at pretty-URL paths.
  // `/<id>.html` returns 404; `/<id>/` is the canonical form.
  assert.equal(
    ruleDocsUrl('SEC-AWS-IAM-001'),
    'https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-001/'
  );
});

test('ruleDocsUrl handles all known rule prefixes', () => {
  for (const prefix of ['SEC', 'ROB', 'STK', 'OPS', 'MOD', 'COST', 'INT', 'CI', 'STYLE', 'CUSTOM']) {
    const id = `${prefix}-EXAMPLE-001`;
    assert.match(
      ruleDocsUrl(id),
      new RegExp(`^https://chrisadkin8\\.github\\.io/tf-analyze/rules/${id}/$`),
      `bad URL for prefix ${prefix}: ${ruleDocsUrl(id)}`
    );
  }
});

test('ruleAnchorHtml produces a valid anchor with target="_blank"', () => {
  const html = ruleAnchorHtml('SEC-AWS-EBS-001');
  assert.match(html, /<a href="https:\/\/chrisadkin8\.github\.io\/tf-analyze\/rules\/SEC-AWS-EBS-001\/"/);
  assert.match(html, /target="_blank"/);
  assert.match(html, /rel="noopener"/);
  assert.match(html, /title="Open rule documentation"/);
  assert.match(html, /<code>SEC-AWS-EBS-001<\/code>/);
});

test('ruleAnchorHtml supports a custom label', () => {
  const html = ruleAnchorHtml('SEC-AWS-EBS-001', 'Custom Label');
  assert.match(html, /<code>Custom Label<\/code>/);
});
