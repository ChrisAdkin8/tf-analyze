"use strict";
// Bridge that lets <a href="http..."> links inside a webview's
// `<iframe srcdoc>` actually open in the user's browser.
//
// VS Code webview iframes are sandboxed; clicking a regular external
// link does nothing (no parent context to navigate, no target="_blank"
// resolution). The standard fix is a three-hop message chain:
//
//   1. iframe content → window.parent.postMessage({command:'openLink', url})
//   2. parent webview script → vscode.postMessage(...)
//   3. extension host onDidReceiveMessage → vscode.env.openExternal(url)
//
// `injectLinkInterceptor` adds the (1) script to the end of the
// engine's HTML before it goes into `srcdoc`. `LINK_BRIDGE_PARENT_JS`
// is the (2) snippet for the wrapper webview's <script>. The
// extension-host (3) handler is per-panel and lives next to the rest
// of the panel's `onDidReceiveMessage` cases.
Object.defineProperty(exports, "__esModule", { value: true });
exports.LINK_BRIDGE_PARENT_JS = void 0;
exports.injectLinkInterceptor = injectLinkInterceptor;
exports.injectReportCsp = injectReportCsp;
// Audit follow-up #22 — a sentinel HTML comment identifies the bridge
// uniquely so the idempotency check can't false-positive on a
// legitimate `'openLink'` occurrence in unmodified engine HTML.
//
// Round-3 audit fix #18 — double-confirm via a CSS class on the
// injected `<script>` tag. If a future render template happens to
// include the same comment text, the class attribute is far less
// likely to collide; the idempotency check below already prefers
// the comment but the class lets a downstream linter / verifier
// confirm injection independently.
const INTERCEPTOR_SENTINEL = '<!-- tfanalyze-link-bridge-v1 -->';
const INTERCEPTOR_SCRIPT = `
${INTERCEPTOR_SENTINEL}
<script class="tfanalyze-link-bridge" data-version="1">
(function () {
  // Intercept clicks on any anchor with an http/https href and forward
  // the URL to the parent webview. preventDefault stops the iframe
  // from doing its no-op navigation.
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest && e.target.closest('a[href]');
    if (!a) return;
    var href = a.getAttribute('href');
    if (!href) return;
    if (/^https?:\\/\\//i.test(href)) {
      e.preventDefault();
      try {
        window.parent.postMessage({ command: 'openLink', url: href }, '*');
      } catch (_) {}
    }
  }, true);
})();
</script>
`;
/**
 * Append the click-interceptor script to the end of the engine's HTML
 * report so iframe-internal links forward to the parent webview.
 *
 * Idempotent: if the marker is already present (a re-render of the
 * same panel), this returns the input unchanged.
 */
function injectLinkInterceptor(html) {
    // Audit follow-up #22 — match on a unique sentinel comment, not the
    // substring `'openLink'` (which is also referenced verbatim in
    // documentation and could legitimately appear in engine-rendered HTML).
    if (!html || html.indexOf(INTERCEPTOR_SENTINEL) !== -1)
        return html;
    // Engine HTML reliably ends with `</body></html>`; inject just
    // before the closing body tag. If the layout ever changes, fall
    // back to appending — the iframe will load it either way.
    if (html.includes('</body>')) {
        return html.replace('</body>', INTERCEPTOR_SCRIPT + '</body>');
    }
    return html + INTERCEPTOR_SCRIPT;
}
/**
 * The JS to add inside the wrapper webview's `<script>` block — it
 * forwards iframe link-click messages to the extension host. Drop
 * this snippet alongside the existing `acquireVsCodeApi()` line.
 *
 * Returns a string (not a `<script>` tag) so the caller can splice it
 * into existing inline JS without nesting `<script>` blocks.
 */
exports.LINK_BRIDGE_PARENT_JS = `
  window.addEventListener('message', function (e) {
    if (e && e.data && e.data.command === 'openLink' && typeof e.data.url === 'string') {
      vscode.postMessage({ command: 'openLink', url: e.data.url });
    }
  });
`;
/**
 * Content-Security-Policy `<meta>` injected into the engine's report HTML
 * before it goes into an `<iframe srcdoc>`. Defence-in-depth alongside the
 * iframe's `sandbox="allow-scripts"` (opaque origin): the report is
 * self-contained (inline CSS + inline SVG/JS, no external CDN), so
 * `default-src 'none'` with inline script/style allowed costs nothing but
 * blocks network exfiltration (`connect-src 'none'`) and external loads if
 * an injected finding field ever slips past the engine's HTML escaping.
 * Mirrors the attack-graph panel's CSP posture.
 */
const REPORT_CSP_META = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; ` +
    `script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; ` +
    `connect-src 'none'; font-src 'none';">`;
/**
 * Insert {@link REPORT_CSP_META} right after the report's opening `<head>`
 * so the policy is parsed before the document's inline scripts/styles.
 * Idempotent; falls back to prepending when there's no `<head>` (the
 * iframe's `sandbox` attribute still isolates it either way).
 */
function injectReportCsp(html) {
    if (!html || html.indexOf('Content-Security-Policy') !== -1)
        return html;
    const m = html.match(/<head[^>]*>/i);
    if (m && m.index !== undefined) {
        const at = m.index + m[0].length;
        return html.slice(0, at) + REPORT_CSP_META + html.slice(at);
    }
    return REPORT_CSP_META + html;
}
//# sourceMappingURL=iframeBridge.js.map