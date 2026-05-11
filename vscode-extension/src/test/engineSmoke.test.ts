import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/** End-to-end engine smoke tests for the remediation surface. These
 * spawn the real `python3 detect.py` so they catch upstream regressions
 * (the kind that broke compliance + apply-fixes earlier in this
 * release cycle) before users hit them through the panel.
 *
 * The test suite is skipped when python3 isn't on PATH or the engine
 * isn't located via the same parent-walk strategy the resolver uses —
 * keeping CI green on contributor laptops without the repo cloned.
 */

function findEngine(): string | null {
  // Walk up from this file's compiled location toward repo root looking
  // for scripts/detect.py. node:test runs from out/test, so the repo is
  // 4 levels up at most.
  let dir = __dirname;
  for (let i = 0; i < 8; i++) {
    const cand = path.join(dir, 'scripts', 'detect.py');
    if (fs.existsSync(cand) && fs.statSync(cand).isFile()) return cand;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function pythonAvailable(): boolean {
  try {
    execFileSync('python3', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function copyFixture(src: string): string {
  const dst = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-engine-'));
  for (const entry of fs.readdirSync(src)) {
    fs.copyFileSync(path.join(src, entry), path.join(dst, entry));
  }
  return dst;
}

const engine = findEngine();
const py = pythonAvailable();
const skip = !engine || !py;
const skipReason = !py ? 'python3 not on PATH' : !engine ? 'detect.py not located' : '';

test('engine: --apply-fixes dry-run produces a unified diff for the demo fixture', { skip: skip && skipReason }, () => {
  const repo = path.dirname(path.dirname(engine!));
  const fixture = path.join(repo, 'fixtures', 'attack_graph_demo');
  if (!fs.existsSync(fixture)) {
    // No fixture in this checkout — skip gracefully rather than fail
    return;
  }
  const target = copyFixture(fixture);
  try {
    let stdout = '';
    try {
      stdout = execFileSync('python3', [engine!, '--target', target, '--apply-fixes', 'dry-run'], {
        encoding: 'utf8',
        maxBuffer: 50 * 1024 * 1024,
      });
    } catch (e) {
      const err = e as { stdout?: string; status?: number };
      // exit 1 = findings present, expected for the demo
      stdout = err.stdout ?? '';
    }
    assert.ok(stdout.includes('--- '), 'dry-run should emit at least one unified-diff file header');
    assert.ok(stdout.includes('+++ '), 'dry-run should emit the +++ side of the unified diff');
    assert.ok(stdout.includes('@@'), 'dry-run should emit at least one hunk header');
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test('engine: --apply-fixes apply mutates source and writes a .bak alongside', { skip: skip && skipReason }, () => {
  const repo = path.dirname(path.dirname(engine!));
  const fixture = path.join(repo, 'fixtures', 'attack_graph_demo');
  if (!fs.existsSync(fixture)) return;
  const target = copyFixture(fixture);
  try {
    const sourceFile = path.join(target, 'main.tf');
    const backupFile = sourceFile + '.bak';
    const before = fs.readFileSync(sourceFile, 'utf8');
    assert.equal(fs.existsSync(backupFile), false, 'no .bak should exist before apply');

    try {
      execFileSync('python3', [engine!, '--target', target, '--apply-fixes', 'apply'], {
        encoding: 'utf8',
        maxBuffer: 50 * 1024 * 1024,
      });
    } catch (e) {
      // Engine exits 1 when findings remain — expected.
      const err = e as { status?: number };
      if (err.status !== undefined && err.status > 1) throw e;
    }

    assert.ok(fs.existsSync(backupFile), 'apply should leave a .bak alongside the patched file');
    const backupContent = fs.readFileSync(backupFile, 'utf8');
    const after = fs.readFileSync(sourceFile, 'utf8');
    assert.equal(backupContent, before, '.bak should be a verbatim copy of the original');
    assert.notEqual(after, before, 'patched file should differ from the original');

    // Spot-check: the demo fixture is missing aws_instance metadata_options;
    // the engine's fix_hcl should have inserted that block.
    assert.ok(after.includes('metadata_options'), 'patched main.tf should contain the metadata_options block the engine inserted');
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test('engine: --apply-fixes survives findings whose `file` is the target directory (regression for IsADirectoryError)', { skip: skip && skipReason }, () => {
  const repo = path.dirname(path.dirname(engine!));
  const fixture = path.join(repo, 'fixtures', 'attack_graph_demo');
  if (!fs.existsSync(fixture)) return;
  const target = copyFixture(fixture);
  try {
    // The demo fixture emits absent-resource findings (e.g.
    // ROB-AWS-BACKUP-001 with file=<target dir>:0). Pre-fix this
    // crashed _handle_apply_fixes with IsADirectoryError — the call
    // below should now exit cleanly with code 0 or 1 (findings).
    let exit = 0;
    try {
      execFileSync('python3', [engine!, '--target', target, '--apply-fixes', 'dry-run'], {
        encoding: 'utf8',
        maxBuffer: 50 * 1024 * 1024,
      });
    } catch (e) {
      const err = e as { status?: number; stderr?: string };
      exit = err.status ?? 0;
      // If we did crash, surface the traceback so the regression is obvious.
      if (exit > 1) throw new Error(`apply-fixes regressed (exit ${exit}): ${err.stderr ?? ''}`);
    }
    assert.ok(exit === 0 || exit === 1, `expected exit 0 or 1, got ${exit}`);
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
});

test('engine: --attack-graph populates a non-empty blast_radius block (regression for v0.1.42-43 empty panel)', { skip: skip && skipReason }, () => {
  const repo = path.dirname(path.dirname(engine!));
  const fixture = path.join(repo, 'fixtures', 'attack_graph_demo');
  if (!fs.existsSync(fixture)) return;
  let stdout = '';
  try {
    stdout = execFileSync('python3', [engine!, '--target', fixture, '--format', 'json', '--attack-graph'], {
      encoding: 'utf8',
      maxBuffer: 50 * 1024 * 1024,
    });
  } catch (e) {
    const err = e as { status?: number; stdout?: string; stderr?: string };
    if ((err.status ?? 0) > 1) throw new Error(`engine crashed (exit ${err.status}): ${err.stderr ?? ''}`);
    stdout = err.stdout ?? '';
  }
  const parsed = JSON.parse(stdout) as { blast_radius?: unknown[]; graph?: { nodes?: Array<{ blast_radius?: number }> } };
  assert.ok(Array.isArray(parsed.blast_radius) && parsed.blast_radius.length > 0,
    'JSON output should include a non-empty top-level blast_radius array when --attack-graph is passed');
  const nodes = parsed.graph?.nodes ?? [];
  assert.ok(nodes.length > 0, 'graph.nodes should be present');
  assert.ok(nodes.some(n => typeof n.blast_radius === 'number'),
    'at least one graph node should carry a numeric blast_radius field');
});

test('extension: buildArgs default includes --attack-graph (regression for v0.1.42-43 empty panel)', () => {
  // Static source check: if someone removes --attack-graph from the
  // default buildArgs the blast-radius panel/CodeLens/status-bar chip
  // all render empty silently — no diagnostic, no error, just nothing.
  // The engine roundtrip test above proves the engine still emits the
  // data; this one proves the extension still asks for it.
  const srcPath = path.join(__dirname, '..', '..', 'src', 'extension.ts');
  if (!fs.existsSync(srcPath)) return;
  const src = fs.readFileSync(srcPath, 'utf8');
  const m = src.match(/function buildArgs\([\s\S]*?\)\s*:\s*string\[\]\s*\{([\s\S]*?)\n\}/);
  assert.ok(m, 'buildArgs function should be discoverable in extension.ts');
  assert.ok(m![1].includes('"--attack-graph"'),
    'buildArgs must include "--attack-graph" in its default args — otherwise the blast-radius surfaces go dark');
});

test('engine: --format compliance runs without TypeError on str/int sort (regression for _ctrl_sort_key)', { skip: skip && skipReason }, () => {
  const repo = path.dirname(path.dirname(engine!));
  const target = path.join(repo, 'examples', 'terragoat', 'aws');
  if (!fs.existsSync(target)) return;
  let stdout = '';
  try {
    stdout = execFileSync('python3', [engine!, '--target', target, '--format', 'compliance', '--compliance-framework', 'cis'], {
      encoding: 'utf8',
      maxBuffer: 50 * 1024 * 1024,
    });
  } catch (e) {
    const err = e as { status?: number; stdout?: string; stderr?: string };
    // Exit 1 is fine (findings present); >1 indicates a crash.
    if ((err.status ?? 0) > 1) throw new Error(`compliance regressed: ${err.stderr ?? ''}`);
    stdout = err.stdout ?? '';
  }
  assert.ok(stdout.includes('Compliance Gap Report'), 'compliance output should include the gap-report heading');
  assert.ok(stdout.includes('CIS'), 'compliance output should mention the requested framework');
});
