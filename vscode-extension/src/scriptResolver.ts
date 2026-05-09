import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

/** Resolve `scripts/detect.py` from the workspace + user setting.
 *
 * Strategy (mirrored across every surface that shells out to the engine
 * so users hit the same lookup whether they invoke runScan, the attack
 * graph, or the HTML report):
 *
 *  1. Honour `tf-analyze.scriptPath` if set. A configured *directory*
 *     is treated as "look for detect.py inside" — a common
 *     misconfiguration that used to produce `python3 <dir>` →
 *     `can't find '__main__' module`.
 *  2. Workspace-relative fallbacks: `<ws>/scripts/detect.py`,
 *     `<ws>/detect.py`, and the sibling-clone case
 *     `<ws>/../tf-analyze/scripts/detect.py`.
 *  3. Walk up to six parent directories of the workspace looking for
 *     `scripts/detect.py`. Catches the case where the workspace is a
 *     fixture or submodule nested inside the tf-analyze repo.
 *
 * Returns an absolute file path, or null if no `detect.py` was found.
 * The result is always a regular file — `python3 <dir>` would
 * otherwise fail before emitting JSON.
 */
export function resolveScriptPath(
  cfg: vscode.WorkspaceConfiguration,
  wsFolder: string,
): string | null {
  const isFile = (p: string): boolean => {
    try { return fs.statSync(p).isFile(); } catch { return false; }
  };
  const isDir = (p: string): boolean => {
    try { return fs.statSync(p).isDirectory(); } catch { return false; }
  };

  const configured = cfg.get<string>('scriptPath', '').trim();
  if (configured) {
    const abs = path.isAbsolute(configured) ? configured : path.join(wsFolder, configured);
    if (isFile(abs)) return abs;
    if (isDir(abs)) {
      const inDir = path.join(abs, 'detect.py');
      if (isFile(inDir)) return inDir;
    }
  }

  for (const cand of [
    path.join(wsFolder, 'scripts', 'detect.py'),
    path.join(wsFolder, 'detect.py'),
    path.join(wsFolder, '..', 'tf-analyze', 'scripts', 'detect.py'),
  ]) {
    if (isFile(cand)) return cand;
  }

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
