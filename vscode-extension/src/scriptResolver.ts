import * as fs from 'fs';
import * as path from 'path';
// Type-only import — the resolver only needs the
// WorkspaceConfiguration shape (a `.get<T>(key, default)` getter), so
// keeping this as `import type` lets the module be unit-tested with a
// hand-rolled stub config object outside VS Code.
import type * as vscode from 'vscode';

/** Path to the detect.py shipped inside the .vsix. The extension MUST
 * be self-contained — this path is the canonical engine location and
 * is checked first by `resolveScriptPath`, before any workspace
 * fallbacks or the user's `tf-analyze.scriptPath` setting.
 *
 * `__dirname` resolves to the runtime location of the compiled .js
 * (typically `<extensionRoot>/out/`). The bundled engine sits at
 * `<extensionRoot>/engine/detect.py`, populated by
 * `scripts/bundle-engine.js` at build time.
 *
 * Exported so callers (and tests) can verify the path without
 * re-deriving it. */
export const BUNDLED_ENGINE_PATH = path.resolve(__dirname, '..', 'engine', 'scripts', 'detect.py');

/** Resolve `detect.py` for the engine to run.
 *
 * Strategy (in order):
 *
 *  1. **Bundled engine inside the .vsix.** This is the default and
 *     covers every end-user install. Self-containment is a hard
 *     product requirement — users should never need to clone the
 *     tf-analyze repo, set `tf-analyze.scriptPath`, or open the
 *     engine source as part of their workspace.
 *  2. **`tf-analyze.scriptPath`** — explicit override, useful only
 *     for engine developers who want to point the extension at a
 *     local working copy. A configured *directory* is treated as
 *     "look for detect.py inside" (a common misconfiguration that
 *     produced `python3 <dir>` → `can't find '__main__' module`
 *     before 0.1.11).
 *  3. **Workspace-relative fallbacks** — `<ws>/scripts/detect.py`,
 *     `<ws>/detect.py`, and the sibling-clone case
 *     `<ws>/../tf-analyze/scripts/detect.py`.
 *  4. **Parent walk** — six levels up from the workspace looking for
 *     `scripts/detect.py`. Catches the case where the workspace is a
 *     fixture or submodule nested inside the tf-analyze repo.
 *
 * Returns an absolute file path, or null if no `detect.py` was found
 * (which should be unreachable in a properly-built .vsix). The
 * result is always a regular file.
 */
/** Optional knobs for `resolveScriptPath`, primarily so tests can
 * pin or disable the bundled-engine check independently of the
 * compiled module location. */
export interface ResolveOptions {
  /** Override the bundled-engine path. Pass `null` to disable the
   * check entirely (tests do this to exercise the fallback chain
   * without picking up the real bundled engine on disk). */
  bundledEnginePath?: string | null;
}

export function resolveScriptPath(
  cfg: vscode.WorkspaceConfiguration,
  wsFolder: string,
  options?: ResolveOptions,
): string | null {
  const isFile = (p: string): boolean => {
    try { return fs.statSync(p).isFile(); } catch { return false; }
  };
  const isDir = (p: string): boolean => {
    try { return fs.statSync(p).isDirectory(); } catch { return false; }
  };

  // 1. Bundled engine — checked first so the .vsix is self-contained
  //    and works on any workspace, regardless of layout. If this is
  //    missing, the extension was packaged incorrectly (the
  //    `bundle-engine` npm script didn't run before vsce package).
  const bundled = options?.bundledEnginePath === undefined
    ? BUNDLED_ENGINE_PATH
    : options.bundledEnginePath;
  if (bundled && isFile(bundled)) return bundled;

  // 2. Engine-developer override.
  const configured = cfg.get<string>('scriptPath', '').trim();
  if (configured) {
    const abs = path.isAbsolute(configured) ? configured : path.join(wsFolder, configured);
    if (isFile(abs)) return abs;
    if (isDir(abs)) {
      const inDir = path.join(abs, 'detect.py');
      if (isFile(inDir)) return inDir;
    }
  }

  // 3. Workspace-relative fallbacks. Mostly historical now that the
  //    .vsix bundles its own engine, but kept for engine devs who run
  //    the extension via F5 against a workspace that has its own copy.
  for (const cand of [
    path.join(wsFolder, 'scripts', 'detect.py'),
    path.join(wsFolder, 'detect.py'),
    path.join(wsFolder, '..', 'tf-analyze', 'scripts', 'detect.py'),
  ]) {
    if (isFile(cand)) return cand;
  }

  // 4. Parent walk for nested fixtures / submodules.
  let dir = wsFolder;
  for (let i = 0; i < 6; i++) {
    const parent = path.dirname(dir);
    if (parent === dir) break;
    const cand = path.join(parent, 'scripts', 'detect.py');
    if (isFile(cand)) return cand;
    dir = parent;
  }

  return null;
}

/** Resolve the Python interpreter to spawn the engine with.
 *
 * `tf-analyze.pythonPath` wins when set (absolute path or a name on PATH).
 * Otherwise default by platform: Windows installs almost always provide
 * `python` and frequently lack `python3`, so the previous hardcoded
 * `python3` made every scan/panel/LSP fail with ENOENT on Windows.
 * Takes `cfg` (rather than reading the config itself) so this module stays
 * value-import-free and unit-testable outside VS Code, like
 * `resolveScriptPath`. */
export function resolvePython(cfg: vscode.WorkspaceConfiguration): string {
  const configured = (cfg.get<string>('pythonPath', '') ?? '').trim();
  if (configured) return configured;
  return process.platform === 'win32' ? 'python' : 'python3';
}

/** A short list of representative paths checked, useful for surfacing
 * "we looked here" guidance in error panels. Not exhaustive — the
 * parent walk in resolveScriptPath checks more locations than this. */
export function defaultSearchPaths(wsFolder: string): string[] {
  return [
    path.join(wsFolder, 'scripts', 'detect.py'),
    path.join(wsFolder, 'detect.py'),
    path.join(wsFolder, '..', 'tf-analyze', 'scripts', 'detect.py'),
  ];
}
