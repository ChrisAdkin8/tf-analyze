import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { resolveScriptPath, defaultSearchPaths, BUNDLED_ENGINE_PATH } from '../scriptResolver';

// Every test in this file disables the bundled-engine check unless it
// specifically wants to exercise it. The bundled engine ships at
// `<extensionRoot>/engine/detect.py` after `npm run bundle-engine`,
// and would otherwise win over every workspace stub the tests build.
const NO_BUNDLE = { bundledEnginePath: null as null };

/** Stub for vscode.WorkspaceConfiguration. The resolver only calls
 * `cfg.get<string>('scriptPath', '')` so a minimal {get} object is
 * enough — typed loosely to match the shape without bringing the
 * vscode runtime in. */
function cfg(scriptPath: string): { get<T>(section: string, defaultValue: T): T } {
  return {
    get<T>(section: string, defaultValue: T): T {
      if (section === 'scriptPath') return (scriptPath as unknown) as T;
      return defaultValue;
    },
  };
}

function makeRepoLayout(): { repo: string; scriptFile: string } {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-resolver-'));
  fs.mkdirSync(path.join(repo, 'scripts'));
  const scriptFile = path.join(repo, 'scripts', 'detect.py');
  fs.writeFileSync(scriptFile, '#!/usr/bin/env python3\nprint("stub")\n');
  return { repo, scriptFile };
}

test('resolves a configured absolute file path verbatim', () => {
  const { repo, scriptFile } = makeRepoLayout();
  try {
    const resolved = resolveScriptPath(cfg(scriptFile) as never, repo, NO_BUNDLE);
    assert.equal(resolved, scriptFile);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('configured directory is treated as "look for detect.py inside"', () => {
  const { repo, scriptFile } = makeRepoLayout();
  try {
    // Point scriptPath at the directory, not the file — the
    // misconfiguration that produced `python3 <dir>` and the
    // "can't find '__main__' module" crash before 0.1.11.
    const dir = path.dirname(scriptFile);
    const resolved = resolveScriptPath(cfg(dir) as never, repo, NO_BUNDLE);
    assert.equal(resolved, scriptFile);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('falls back to <ws>/scripts/detect.py when the configured path is invalid', () => {
  const { repo, scriptFile } = makeRepoLayout();
  try {
    const resolved = resolveScriptPath(cfg('/nonexistent/path/detect.py') as never, repo, NO_BUNDLE);
    assert.equal(resolved, scriptFile);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('walks parent directories to find scripts/detect.py when workspace is a nested fixture', () => {
  const { repo, scriptFile } = makeRepoLayout();
  try {
    // Workspace is a fixture two levels deep — none of the workspace-
    // relative fallbacks match, only the parent walk does.
    const fixture = path.join(repo, 'fixtures', 'attack_graph_demo');
    fs.mkdirSync(fixture, { recursive: true });
    fs.writeFileSync(path.join(fixture, 'main.tf'), 'resource "aws_s3_bucket" "x" {}');

    const resolved = resolveScriptPath(cfg('') as never, fixture, NO_BUNDLE);
    assert.equal(resolved, scriptFile);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('returns null when no detect.py is reachable', () => {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-resolver-empty-'));
  try {
    const resolved = resolveScriptPath(cfg('') as never, ws, NO_BUNDLE);
    assert.equal(resolved, null);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('configured path that points at a non-script directory falls through to fallbacks', () => {
  const { repo, scriptFile } = makeRepoLayout();
  try {
    // Point scriptPath at a directory that has no detect.py inside —
    // resolver should fall through to the workspace fallback.
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-resolver-empty-cfg-'));
    try {
      const resolved = resolveScriptPath(cfg(empty) as never, repo, NO_BUNDLE);
      assert.equal(resolved, scriptFile);
    } finally {
      fs.rmSync(empty, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('defaultSearchPaths produces the workspace-relative trio', () => {
  const ws = '/tmp/some-ws';
  const paths = defaultSearchPaths(ws);
  assert.equal(paths.length, 3);
  assert.equal(paths[0], path.join(ws, 'scripts', 'detect.py'));
  assert.equal(paths[1], path.join(ws, 'detect.py'));
  // Sibling-clone case
  assert.ok(paths[2].endsWith(path.join('tf-analyze', 'scripts', 'detect.py')));
});

// ─── Bundled-engine path ────────────────────────────────────────────

test('BUNDLED_ENGINE_PATH points at <extensionRoot>/engine/scripts/detect.py', () => {
  // resolveScriptPath uses path.resolve(__dirname, '..', 'engine',
  // 'scripts', 'detect.py'). The engine/ subtree mirrors the source
  // repo's layout so detect.py's default `--catalog` lookup
  // (Path(__file__).parent.parent / "catalog") resolves to the
  // bundled catalog at engine/catalog/ without any extension-side
  // flag plumbing.
  assert.ok(BUNDLED_ENGINE_PATH.endsWith(path.join('engine', 'scripts', 'detect.py')),
    `expected bundled path to end with engine/scripts/detect.py, got ${BUNDLED_ENGINE_PATH}`);
});

test('resolver picks the bundled engine first when present', () => {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-resolver-bundled-'));
  try {
    // Even though a workspace-relative detect.py exists, the bundled
    // path should win — that's what makes the .vsix self-contained.
    fs.mkdirSync(path.join(ws, 'scripts'));
    fs.writeFileSync(path.join(ws, 'scripts', 'detect.py'), '#!/usr/bin/env python3\nprint("workspace")');

    const fakeBundled = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-bundled-'));
    const fakeBundledFile = path.join(fakeBundled, 'detect.py');
    fs.writeFileSync(fakeBundledFile, '#!/usr/bin/env python3\nprint("bundled")');

    try {
      const resolved = resolveScriptPath(cfg('') as never, ws, { bundledEnginePath: fakeBundledFile });
      assert.equal(resolved, fakeBundledFile, 'bundled engine should win over workspace fallback');
    } finally {
      fs.rmSync(fakeBundled, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('resolver falls back to workspace search when bundled engine is missing', () => {
  const { repo, scriptFile } = makeRepoLayout();
  try {
    const resolved = resolveScriptPath(cfg('') as never, repo, { bundledEnginePath: '/nonexistent/bundled/detect.py' });
    assert.equal(resolved, scriptFile);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});
