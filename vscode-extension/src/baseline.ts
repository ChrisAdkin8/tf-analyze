import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

/** Subset of the engine's finding shape that's needed to identify a
 * record in the baseline. The engine matches by (id, file, line,
 * resource), so any extra fields the user might paste in are ignored. */
export interface BaselineFinding {
  id: string;
  file: string;
  line: number;
  resource?: string;
}

/** On-disk baseline file format. The engine consumes this via
 * `--baseline PATH`. The shape mirrors `--format json` output minimally
 * — only the `findings` array is required, and only the four match
 * keys per record are required, but we preserve title/urgency for
 * human readability when someone opens the file in an editor. */
interface BaselineFile {
  findings: BaselineFinding[];
  // Free-form metadata — not consumed by the engine, useful for users.
  meta?: { last_updated?: string; created_by?: string };
}

/** Filename relative to the workspace root. Picked to be discoverable
 * by users (visible in the file tree, not hidden in `.vscode/`) but
 * obviously a config file (leading dot, kebab-case). */
export const BASELINE_FILENAME = '.tf-analyze-baseline.json';

export function baselinePath(wsFolder: string): string {
  return path.join(wsFolder, BASELINE_FILENAME);
}

export function baselineExists(wsFolder: string): boolean {
  try { return fs.statSync(baselinePath(wsFolder)).isFile(); } catch { return false; }
}

function read(wsFolder: string): BaselineFile {
  if (!baselineExists(wsFolder)) return { findings: [] };
  try {
    const raw = fs.readFileSync(baselinePath(wsFolder), 'utf8');
    const parsed = JSON.parse(raw) as BaselineFile;
    if (!Array.isArray(parsed.findings)) return { findings: [] };
    return parsed;
  } catch {
    return { findings: [] };
  }
}

function write(wsFolder: string, data: BaselineFile): void {
  data.meta = { ...(data.meta ?? {}), last_updated: new Date().toISOString(), created_by: 'tf-analyze (vscode-extension)' };
  fs.writeFileSync(baselinePath(wsFolder), JSON.stringify(data, null, 2) + '\n', 'utf8');
}

/** Match key compatible with the engine's (id, file, line, resource)
 * suppression criterion. Keep this in sync with detect.py — if the
 * engine ever loosens the criterion, remove fields from the key here
 * to mirror it. */
function key(f: BaselineFinding): string {
  return [f.id, f.file, f.line, f.resource ?? ''].join('|');
}

/** Add a finding to the baseline. Idempotent — re-suppressing the same
 * finding is a no-op. Returns true if the file changed. */
export function suppress(wsFolder: string, finding: BaselineFinding): boolean {
  const data = read(wsFolder);
  const existing = new Set(data.findings.map(key));
  if (existing.has(key(finding))) return false;
  data.findings.push({
    id: finding.id,
    file: finding.file,
    line: finding.line,
    ...(finding.resource ? { resource: finding.resource } : {}),
  });
  write(wsFolder, data);
  return true;
}

/** Remove a finding from the baseline. Returns true if a record was
 * actually removed. */
export function unsuppress(wsFolder: string, finding: BaselineFinding): boolean {
  if (!baselineExists(wsFolder)) return false;
  const data = read(wsFolder);
  const before = data.findings.length;
  const k = key(finding);
  data.findings = data.findings.filter(f => key(f) !== k);
  if (data.findings.length === before) return false;
  write(wsFolder, data);
  return true;
}

/** Open the baseline file in the active editor, creating an empty one
 * first if it doesn't exist. */
export async function openBaselineFile(wsFolder: string): Promise<void> {
  if (!baselineExists(wsFolder)) {
    write(wsFolder, { findings: [] });
  }
  const doc = await vscode.workspace.openTextDocument(baselinePath(wsFolder));
  await vscode.window.showTextDocument(doc);
}
