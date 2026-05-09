import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { injectLinkInterceptor, LINK_BRIDGE_PARENT_JS } from '../iframeBridge';

/**
 * Without the bridge, every external link inside the compliance and
 * HTML-report panels' iframes is a silent no-op — VS Code webview
 * iframes are sandboxed and target="_blank" doesn't navigate. These
 * tests lock the bridge's contract: the iframe-side script forwards
 * link clicks to the parent webview, which forwards to the extension
 * host's onDidReceiveMessage, which calls vscode.env.openExternal.
 */

test('injectLinkInterceptor adds a click handler before </body>', () => {
  const input = '<html><body><a href="https://example.com">x</a></body></html>';
  const out = injectLinkInterceptor(input);
  assert.match(out, /'openLink'/);
  assert.match(out, /window\.parent\.postMessage/);
  assert.match(out, /preventDefault/);
  // Marker is injected before </body>, not after.
  assert.ok(out.indexOf("'openLink'") < out.indexOf('</body>'),
    'interceptor script should land before </body> so it parses inside the document body');
});

test('injectLinkInterceptor is idempotent', () => {
  const input = '<html><body><a href="https://example.com">x</a></body></html>';
  const once = injectLinkInterceptor(input);
  const twice = injectLinkInterceptor(once);
  assert.equal(once, twice,
    'a re-render of the same panel must not stack the interceptor on every refresh');
});

test('injectLinkInterceptor falls back to append when </body> is missing', () => {
  const input = '<a href="https://example.com">no body tag</a>';
  const out = injectLinkInterceptor(input);
  assert.match(out, /'openLink'/);
  assert.ok(out.startsWith(input),
    'fallback path should preserve the original content unchanged');
});

test('injectLinkInterceptor returns empty input unchanged', () => {
  assert.equal(injectLinkInterceptor(''), '');
});

test('LINK_BRIDGE_PARENT_JS forwards iframe messages to the extension host', () => {
  // Sanity: the parent-side script listens for the same `command` the
  // iframe sends, narrows on it, and re-posts via the webview API.
  assert.match(LINK_BRIDGE_PARENT_JS, /addEventListener\(\s*'message'/);
  assert.match(LINK_BRIDGE_PARENT_JS, /'openLink'/);
  assert.match(LINK_BRIDGE_PARENT_JS, /vscode\.postMessage/);
});
