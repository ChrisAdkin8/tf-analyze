import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/** Write `text` to `file` without following a symlink at that path.
 *
 * `fs.writeFileSync` writes through a symlink, so a repository that
 * commits `.tf-analyze-baseline.json -> ../../.bashrc` would have that
 * file overwritten when the user suppresses a finding. This refuses a
 * symlinked target outright, then writes a fresh sibling file (`wx`
 * fails if anything already sits at that name) and renames it into
 * place: a rename replaces the directory entry itself, so a symlink
 * swapped in between the check and the write is replaced, not followed.
 * Mirrors the engine's `--apply-fixes` guard. */
export function writeFileNoFollow(file: string, text: string): void {
  let st: fs.Stats | undefined;
  try { st = fs.lstatSync(file); } catch { st = undefined; }
  if (st && st.isSymbolicLink()) {
    throw new Error(`refusing to write ${file}: it is a symlink`);
  }
  if (st && !st.isFile()) {
    throw new Error(`refusing to write ${file}: not a regular file`);
  }
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  try {
    fs.writeFileSync(tmp, text, { encoding: 'utf8', flag: 'wx', mode: st ? st.mode & 0o777 : 0o644 });
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch { /* already renamed or never created */ }
    throw e;
  }
}

/** Write `text` to a new file in a private temp directory and return its
 * path. A fixed or guessable name in the shared temp dir could be a
 * symlink another local user planted; `mkdtemp` gives a fresh 0700
 * directory, so nothing else can be waiting at the name. */
export function writePrivateTempFile(name: string, text: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tf-analyze-'));
  const file = path.join(dir, name);
  fs.writeFileSync(file, text, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  return file;
}
