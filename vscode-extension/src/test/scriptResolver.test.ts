import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { resolveScriptPath, defaultSearchPaths } from '../scriptResolver';

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
    const resolved = resolveScriptPath(cfg(scriptFile) as never, repo);
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
    const resolved = resolveScriptPath(cfg(dir) as never, repo);
    assert.equal(resolved, scriptFile);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('falls back to <ws>/scripts/detect.py when the configured path is invalid', () => {
  const { repo, scriptFile } = makeRepoLayout();
  try {
    const resolved = resolveScriptPath(cfg('/nonexistent/path/detect.py') as never, repo);
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

    const resolved = resolveScriptPath(cfg('') as never, fixture);
    assert.equal(resolved, scriptFile);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('returns null when no detect.py is reachable', () => {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-resolver-empty-'));
  try {
    const resolved = resolveScriptPath(cfg('') as never, ws);
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
      const resolved = resolveScriptPath(cfg(empty) as never, repo);
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
