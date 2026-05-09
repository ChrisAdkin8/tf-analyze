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
const iframeBridge_1 = require("../iframeBridge");
/**
 * Without the bridge, every external link inside the compliance and
 * HTML-report panels' iframes is a silent no-op — VS Code webview
 * iframes are sandboxed and target="_blank" doesn't navigate. These
 * tests lock the bridge's contract: the iframe-side script forwards
 * link clicks to the parent webview, which forwards to the extension
 * host's onDidReceiveMessage, which calls vscode.env.openExternal.
 */
(0, node_test_1.test)('injectLinkInterceptor adds a click handler before </body>', () => {
    const input = '<html><body><a href="https://example.com">x</a></body></html>';
    const out = (0, iframeBridge_1.injectLinkInterceptor)(input);
    assert.match(out, /'openLink'/);
    assert.match(out, /window\.parent\.postMessage/);
    assert.match(out, /preventDefault/);
    // Marker is injected before </body>, not after.
    assert.ok(out.indexOf("'openLink'") < out.indexOf('</body>'), 'interceptor script should land before </body> so it parses inside the document body');
});
(0, node_test_1.test)('injectLinkInterceptor is idempotent', () => {
    const input = '<html><body><a href="https://example.com">x</a></body></html>';
    const once = (0, iframeBridge_1.injectLinkInterceptor)(input);
    const twice = (0, iframeBridge_1.injectLinkInterceptor)(once);
    assert.equal(once, twice, 'a re-render of the same panel must not stack the interceptor on every refresh');
});
(0, node_test_1.test)('injectLinkInterceptor falls back to append when </body> is missing', () => {
    const input = '<a href="https://example.com">no body tag</a>';
    const out = (0, iframeBridge_1.injectLinkInterceptor)(input);
    assert.match(out, /'openLink'/);
    assert.ok(out.startsWith(input), 'fallback path should preserve the original content unchanged');
});
(0, node_test_1.test)('injectLinkInterceptor returns empty input unchanged', () => {
    assert.equal((0, iframeBridge_1.injectLinkInterceptor)(''), '');
});
(0, node_test_1.test)('LINK_BRIDGE_PARENT_JS forwards iframe messages to the extension host', () => {
    // Sanity: the parent-side script listens for the same `command` the
    // iframe sends, narrows on it, and re-posts via the webview API.
    assert.match(iframeBridge_1.LINK_BRIDGE_PARENT_JS, /addEventListener\(\s*'message'/);
    assert.match(iframeBridge_1.LINK_BRIDGE_PARENT_JS, /'openLink'/);
    assert.match(iframeBridge_1.LINK_BRIDGE_PARENT_JS, /vscode\.postMessage/);
});
//# sourceMappingURL=iframeBridge.test.js.map