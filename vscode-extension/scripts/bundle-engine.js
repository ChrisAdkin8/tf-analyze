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

const here = __dirname;                                            // vscode-extension/scripts/
const extensionRoot = path.dirname(here);                          // vscode-extension/
const repoRoot = path.dirname(extensionRoot);                      // tf-analyze/

// Mirror the source repo's layout inside `engine/` so detect.py's
// default `--catalog` resolution (Path(__file__).parent.parent /
// "catalog") finds the catalog automatically. With this layout:
//   engine/scripts/detect.py
//   engine/catalog/*.yaml
// the engine works with no extension-side flag bookkeeping.
const sourceEngineFile = path.join(repoRoot, 'scripts', 'detect.py');
const sourceCatalogDir = path.join(repoRoot, 'catalog');
const engineRoot = path.join(extensionRoot, 'engine');
const targetEngineFile = path.join(engineRoot, 'scripts', 'detect.py');
const targetCatalogDir = path.join(engineRoot, 'catalog');

function fail(msg) {
  console.error(`[bundle-engine] FATAL: ${msg}`);
  console.error('[bundle-engine] The extension must be built from inside the tf-analyze repo so the engine + catalog can be bundled.');
  process.exit(1);
}

if (!fs.existsSync(sourceEngineFile)) fail(`${sourceEngineFile} not found`);
if (!fs.existsSync(sourceCatalogDir)) fail(`${sourceCatalogDir} not found`);

// Reset engine/ on every run so deletions in the source repo don't
// leave orphaned files behind in the extension bundle.
if (fs.existsSync(engineRoot)) fs.rmSync(engineRoot, { recursive: true, force: true });
fs.mkdirSync(path.join(engineRoot, 'scripts'), { recursive: true });
fs.mkdirSync(targetCatalogDir, { recursive: true });

fs.copyFileSync(sourceEngineFile, targetEngineFile);

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

const engineSize = fs.statSync(targetEngineFile).size;
console.log(`[bundle-engine] engine: ${(engineSize / 1024).toFixed(1)} KB -> ${targetEngineFile}`);
console.log(`[bundle-engine] catalog: ${catalogCount} entries, ${(catalogBytes / 1024).toFixed(1)} KB -> ${targetCatalogDir}`);
