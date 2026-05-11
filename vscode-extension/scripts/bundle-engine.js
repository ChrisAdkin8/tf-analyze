#!/usr/bin/env node
/**
 * Bundle scripts/detect.py from the parent tf-analyze repo into the
 * extension's engine/ directory.
 *
 * Self-containment is a hard product requirement: the extension must
 * ship with its own detect.py so end users never have to clone the
 * tf-analyze repo, set tf-analyze.scriptPath, or open the engine source
 * as part of their workspace. scriptResolver.ts checks the bundled
 * path FIRST, before any workspace fallbacks, so a packaged .vsix
 * always works out of the box.
 *
 * This script runs as part of `npm run compile` and `vsce package`,
 * so the engine is always fresh against the current repo HEAD when
 * the extension is built.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const here = __dirname;                                            // vscode-extension/scripts/
const extensionRoot = path.dirname(here);                          // vscode-extension/
const repoRoot = path.dirname(extensionRoot);                      // tf-analyze/

// Mirror the source repo's layout inside `engine/` so detect.py's
// default `--catalog` resolution (Path(__file__).parent.parent /
// "catalog") finds the catalog automatically. With this layout:
//   engine/scripts/detect.py
//   engine/scripts/_mitre.py            ← sibling helper modules
//   engine/catalog/*.yaml
// the engine works with no extension-side flag bookkeeping.
//
// Audit follow-up #16 — the file list used to be maintained by hand,
// which meant every new `scripts/_xyz.py` extract had to be added in
// two places (the extract itself plus this array). Forgotten entries
// ship a .vsix that crashes at first import of the missing module,
// and the smoke test only catches it when detect.py imports the
// module at startup — lazy-imported modules (`from _registry import
// …` inside a per-rule branch) slip through silently.
//
// We now discover siblings by globbing `scripts/_*.py`, then concat
// `detect.py` at the front so the bundle order remains stable. A
// runtime sanity check below still enforces a minimum count (the
// previous guard against an accidentally-empty array) and a fixed
// list of NEVER_BUNDLE entries lets us deliberately exclude a file
// (none today, but keeps the door open for test-only helpers).
const NEVER_BUNDLE = new Set([]);
const sourceScriptsDirEarly = path.join(path.dirname(__dirname), '..', 'scripts');
const ENGINE_SIBLING_FILES = (
  fs.existsSync(sourceScriptsDirEarly)
    ? fs.readdirSync(sourceScriptsDirEarly)
        .filter(n => /^_[a-zA-Z0-9_]+\.py$/.test(n) && !NEVER_BUNDLE.has(n))
        .sort()
    : []
);
ENGINE_SIBLING_FILES.unshift('detect.py');
// Minimum sibling count is a safety net: today's catalogue has 18 of
// them, so a sudden drop to 5 (e.g. a glob bug that misses underscore-
// prefixed files) fails the build instead of shipping a half-bundle.
//
// Round-3 audit fix #16 — the threshold is ≈ current count − 3,
// chosen to allow one or two legitimate module consolidations per
// round while still catching glob breakage. Raising this value
// when the actual count grows is safe; lowering it past 12 should
// be avoided because the four R30.0 → R30.7 seams (`_hcl`,
// `_catalog`, `_versions`, `_scoring`) plus `detect.py` itself
// already total 5 and they're load-bearing.
const MIN_SIBLING_COUNT = 15;
if (ENGINE_SIBLING_FILES.length < MIN_SIBLING_COUNT) {
  console.error(
    `[bundle-engine] FATAL: glob picked only ${ENGINE_SIBLING_FILES.length} sibling files, ` +
    `expected ≥ ${MIN_SIBLING_COUNT}. The glob (\`scripts/_*.py\`) probably ran against the wrong cwd.`,
  );
  process.exit(1);
}

const sourceScriptsDir = path.join(repoRoot, 'scripts');
const sourceCatalogDir = path.join(repoRoot, 'catalog');
const engineRoot = path.join(extensionRoot, 'engine');
const targetScriptsDir = path.join(engineRoot, 'scripts');
const targetCatalogDir = path.join(engineRoot, 'catalog');
const targetEngineFile = path.join(targetScriptsDir, 'detect.py');

function fail(msg) {
  console.error(`[bundle-engine] FATAL: ${msg}`);
  console.error('[bundle-engine] The extension must be built from inside the tf-analyze repo so the engine + catalog can be bundled.');
  process.exit(1);
}

if (!fs.existsSync(sourceCatalogDir)) fail(`${sourceCatalogDir} not found`);
for (const name of ENGINE_SIBLING_FILES) {
  if (!fs.existsSync(path.join(sourceScriptsDir, name))) {
    fail(`${path.join(sourceScriptsDir, name)} not found`);
  }
}

// Reset engine/ on every run so deletions in the source repo don't
// leave orphaned files behind in the extension bundle.
if (fs.existsSync(engineRoot)) fs.rmSync(engineRoot, { recursive: true, force: true });
fs.mkdirSync(targetScriptsDir, { recursive: true });
fs.mkdirSync(targetCatalogDir, { recursive: true });

let scriptsBytes = 0;
for (const name of ENGINE_SIBLING_FILES) {
  const src = path.join(sourceScriptsDir, name);
  const dst = path.join(targetScriptsDir, name);
  fs.copyFileSync(src, dst);
  scriptsBytes += fs.statSync(dst).size;
}

let catalogCount = 0;
let catalogBytes = 0;
for (const entry of fs.readdirSync(sourceCatalogDir)) {
  const src = path.join(sourceCatalogDir, entry);
  if (!fs.statSync(src).isFile()) continue;
  const dst = path.join(targetCatalogDir, entry);
  fs.copyFileSync(src, dst);
  catalogCount++;
  catalogBytes += fs.statSync(dst).size;
}

console.log(`[bundle-engine] scripts: ${ENGINE_SIBLING_FILES.length} files, ${(scriptsBytes / 1024).toFixed(1)} KB -> ${targetScriptsDir}`);
console.log(`[bundle-engine] catalog: ${catalogCount} entries, ${(catalogBytes / 1024).toFixed(1)} KB -> ${targetCatalogDir}`);

// ─── Smoke test ──────────────────────────────────────────────────
//
// Run `python3 engine/scripts/detect.py --list-rules` against the
// freshly-bundled engine. Catches three classes of build-time failure
// that would otherwise only surface at the user's first click:
//   1. Sibling-import miss — e.g. detect.py adds `from _mitre import …`
//      without anyone updating ENGINE_SIBLING_FILES above. Engine
//      crashes on every invocation inside the .vsix.
//   2. Catalogue YAML parse error introduced in this build. Engine
//      runs but `--list-rules` exits non-zero on strict-load.
//   3. Missing top-level Python dependency — though detect.py is
//      stdlib-only by contract, a regression here is silent in a
//      .vsix and triggers a runtime crash.
//
// A red CI / failed `npm run package` here is the right outcome —
// shipping a broken engine in a .vsix is the only failure that's
// invisible to regular tests.

// `--strict-catalog` turns every YAML parse error OR schema-validation
// failure in the bundled catalog into a non-zero engine exit, so the
// smoke test below catches them. Without this flag, `load_catalog`
// prints `ERROR:` lines to stderr but continues with N-1 entries, and
// the (still non-empty) rule list slipped through this check before
// R30.0.10 — defeating the "Catalogue YAML parse error introduced in
// this build" promise this script's docstring claims to enforce.
const python = process.env.PYTHON || 'python3';
const probe = spawnSync(python, [targetEngineFile, '--strict-catalog', '--list-rules'], {
  cwd: engineRoot,
  env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  encoding: 'utf8',
});

// Minimum rule count we accept from the bundled engine. Locked above
// 200 because the catalogue has been over 200 active rules since R27;
// a drop below this threshold means either a sibling-import miss
// silently filtered every entry, or someone gutted the catalogue by
// accident. Either way, fail the build.
const MIN_RULE_COUNT = 200;

if (probe.error) {
  if (probe.error.code === 'ENOENT') {
    console.warn(`[bundle-engine] WARN: ${python} not on PATH; skipping engine smoke test.`);
    console.warn('[bundle-engine] Set PYTHON env var to a real Python 3.10+ if this build is publication-bound.');
  } else {
    console.error(`[bundle-engine] FATAL: smoke test launcher errored: ${probe.error.message}`);
    process.exit(1);
  }
} else if (probe.status !== 0) {
  console.error(`[bundle-engine] FATAL: bundled engine smoke test failed (exit ${probe.status}).`);
  console.error('[bundle-engine] stderr from the bundled engine:');
  console.error((probe.stderr || '').replace(/^/gm, '  | '));
  // `--strict-catalog` makes detect.py exit 2 specifically on catalogue
  // parse / schema failures; surface that diagnosis when it's the cause.
  if (probe.status === 2 && /catalogue error/i.test(probe.stderr || '')) {
    console.error('[bundle-engine] CAUSE: catalogue YAML parse OR schema-validation error in this build.');
    console.error('[bundle-engine] Inspect the offending `catalog/*.yaml` file(s) listed above.');
  } else {
    console.error('[bundle-engine] This usually means a Python file detect.py imports as a sibling');
    console.error('[bundle-engine] is missing from ENGINE_SIBLING_FILES above. Add it.');
  }
  process.exit(1);
} else {
  // --list-rules emits lines like '  SEC-AWS-IAM-001       HIGH     <title>'.
  // Indented + starts with a rule-ID-shaped token. Headers (`# Section (N)`)
  // and the python-hcl2 stderr note are ignored.
  const ruleCount = (probe.stdout || '').split('\n')
    .filter(l => /^\s+[A-Z]+(?:-[A-Z0-9-]+)+\s/.test(l)).length;
  if (ruleCount < MIN_RULE_COUNT) {
    console.error(`[bundle-engine] FATAL: bundled engine listed only ${ruleCount} rules `
      + `(minimum ${MIN_RULE_COUNT}). The engine exited cleanly, but the catalogue is too thin.`);
    console.error('[bundle-engine] stderr from the bundled engine:');
    console.error((probe.stderr || '').replace(/^/gm, '  | '));
    console.error('[bundle-engine] Likely cause: silent drops in load_catalog (which `--strict-catalog`');
    console.error('[bundle-engine] should have promoted to a non-zero exit — investigate before shipping).');
    process.exit(1);
  }
  console.log(`[bundle-engine] smoke test OK (${python} listed ${ruleCount} rules from the bundled engine).`);
}
