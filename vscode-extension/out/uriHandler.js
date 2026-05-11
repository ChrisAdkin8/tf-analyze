"use strict";
/**
 * Pure dispatch logic for the `vscode://tfanalyze.tf-analyze/<verb>` URI
 * surface. Extracted from extension.ts so the routing + validation can
 * be unit-tested under `node --test` without spinning up VS Code.
 *
 * Verbs (as documented in extension.ts → registerUriHandler):
 *
 *   /rule/<RULE-ID>                                   → open rule explainer
 *   /scan?target=<absolute path>                      → run a workspace scan
 *   /explain?id=<RULE-ID>&file=<path>&line=<n>        → open at location
 *   /suppress?id=<RULE-ID>[&file=<path>&line=<n>]     → baseline-add or
 *                                                       workspace-wide ignore
 *
 * Every verb has a strict validator. Anything that fails to parse for
 * the matched verb is reported via the `warn` callback rather than
 * silently no-opping.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.RULE_ID_RE = void 0;
exports.safePath = safePath;
exports.safeLine = safeLine;
exports.dispatchUri = dispatchUri;
exports.RULE_ID_RE = /^[A-Z][A-Z0-9-]{2,63}$/;
/** Validate an absolute POSIX path string, rejecting traversal and
 *  embedded nulls. Returns the path on success, null on rejection. */
function safePath(raw) {
    if (!raw)
        return null;
    if (raw.indexOf("\0") !== -1)
        return null;
    if (raw.split("/").some(seg => seg === ".."))
        return null;
    if (!raw.startsWith("/"))
        return null;
    if (raw.length > 1024)
        return null;
    return raw;
}
/** Validate a 1-based line number string; returns the parsed number
 *  or null on rejection. Caps at 1,000,000 lines to bound input. */
function safeLine(raw) {
    if (!raw)
        return null;
    if (!/^\d{1,7}$/.test(raw))
        return null;
    const n = Number(raw);
    return n >= 1 && n <= 1000000 ? n : null;
}
/**
 * Pure dispatcher. Inspects `uri`, validates the parameters for the
 * matched verb, calls the appropriate handler, and returns a
 * description of what was dispatched (or rejected). Side effects are
 * confined to the handler callbacks — the function itself never
 * touches `vscode.*`.
 */
function dispatchUri(uri, handlers) {
    // /rule/<RULE-ID>
    const ruleMatch = /^\/rule\/([A-Z][A-Z0-9-]{2,63})$/.exec(uri.path);
    if (ruleMatch) {
        handlers.openRule(ruleMatch[1]);
        return { kind: "rule", ruleId: ruleMatch[1] };
    }
    const params = new URLSearchParams(uri.query);
    if (uri.path === "/scan") {
        const target = safePath(params.get("target"));
        if (!target) {
            const reason = `tf-analyze: /scan requires a valid absolute target path; got ${uri.toString()}`;
            handlers.warn(reason);
            return { kind: "rejected", reason };
        }
        const ws = handlers.workspacePath();
        if (target !== ws && !target.startsWith(ws + "/")) {
            const reason = (`tf-analyze: /scan target ${target} is outside the active ` +
                `workspace (${ws}). Open that folder first.`);
            handlers.warn(reason);
            return { kind: "rejected", reason };
        }
        handlers.runScan(target);
        return { kind: "scan", target };
    }
    if (uri.path === "/explain") {
        const ruleId = params.get("id") ?? "";
        if (!exports.RULE_ID_RE.test(ruleId)) {
            const reason = `tf-analyze: /explain requires id=<RULE-ID>; got ${uri.toString()}`;
            handlers.warn(reason);
            return { kind: "rejected", reason };
        }
        handlers.openRule(ruleId);
        const file = safePath(params.get("file"));
        const line = safeLine(params.get("line"));
        // Audit follow-up #8 — gate the `file` argument to the workspace
        // root the same way `/scan` and `/suppress` do. Previously /explain
        // accepted any absolute path; a crafted link
        // (`vscode://…/explain?id=X&file=/etc/passwd&line=1`) would open
        // a host file outside the workspace. The rule pane still opens
        // (handlers.openRule called above) — we only gate the editor jump.
        if (file && line !== null) {
            const ws = handlers.workspacePath();
            if (file !== ws && !file.startsWith(ws + "/")) {
                handlers.warn(`tf-analyze: /explain file ${file} is outside the active ` +
                    `workspace (${ws}); refusing to open it.`);
                return { kind: "explain", ruleId, file: null, line };
            }
            handlers.openLocation(file, line);
        }
        return { kind: "explain", ruleId, file, line };
    }
    if (uri.path === "/suppress") {
        const ruleId = params.get("id") ?? "";
        if (!exports.RULE_ID_RE.test(ruleId)) {
            const reason = `tf-analyze: /suppress requires id=<RULE-ID>; got ${uri.toString()}`;
            handlers.warn(reason);
            return { kind: "rejected", reason };
        }
        const file = safePath(params.get("file"));
        const line = safeLine(params.get("line"));
        const ws = handlers.workspacePath();
        if (file && line !== null) {
            // Per-finding baseline-add. Restrict baseline writes to the
            // active workspace — a hostile link must not silently mutate
            // state outside it.
            if (file !== ws && !file.startsWith(ws + "/")) {
                const reason = (`tf-analyze: /suppress target ${file} is outside the active ` +
                    `workspace (${ws}); refusing to write to baseline.`);
                handlers.warn(reason);
                return { kind: "rejected", reason };
            }
            handlers.suppressFinding(ruleId, file, line);
            return { kind: "suppress-finding", ruleId, file, line };
        }
        // id-only → workspace-wide rule ignore.
        handlers.suppressRuleWorkspaceWide(ruleId);
        return { kind: "suppress-rule", ruleId };
    }
    const reason = (`tf-analyze: unrecognized URI path "${uri.path}". ` +
        `Expected /rule/<RULE-ID>, /scan, /explain, or /suppress.`);
    handlers.warn(reason);
    return { kind: "rejected", reason };
}
//# sourceMappingURL=uriHandler.js.map