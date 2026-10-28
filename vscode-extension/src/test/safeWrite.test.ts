import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { writeFileNoFollow, writePrivateTempFile } from '../safeWrite';
import { BASELINE_FILENAME, ensureBaselineFile, suppress } from '../baseline';

function fresh(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-safewrite-'));
}

test('a symlinked baseline is refused and its target left alone', () => {
  const root = fresh();
  try {
    const ws = path.join(root, 'ws');
    fs.mkdirSync(ws);
    const victim = path.join(root, 'victim');
    fs.writeFileSync(victim, 'keep me\n');
    // A cloned repo can commit this link.
    fs.symlinkSync(victim, path.join(ws, BASELINE_FILENAME));
    assert.throws(
      () => suppress(ws, { id: 'SEC-AWS-SG-001', file: 'main.tf', line: 1 }),
      /symlink/,
    );
    assert.equal(fs.readFileSync(victim, 'utf8'), 'keep me\n');
    assert.equal(fs.readdirSync(ws).length, 1, 'no temp file left behind');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a symlinked .tf-analyze.yaml is refused', () => {
  const root = fresh();
  try {
    const victim = path.join(root, 'victim');
    fs.writeFileSync(victim, 'keep me\n');
    const link = path.join(root, '.tf-analyze.yaml');
    fs.symlinkSync(victim, link);
    assert.throws(() => writeFileNoFollow(link, 'ignore_rules:\n  - X\n'), /symlink/);
    assert.equal(fs.readFileSync(victim, 'utf8'), 'keep me\n');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a directory at the path is refused', () => {
  const root = fresh();
  try {
    const dir = path.join(root, BASELINE_FILENAME);
    fs.mkdirSync(dir);
    assert.throws(() => writeFileNoFollow(dir, '{}'), /not a regular file/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('a regular file is replaced and keeps its mode', () => {
  const ws = fresh();
  try {
    const file = ensureBaselineFile(ws);
    fs.chmodSync(file, 0o640);
    assert.equal(suppress(ws, { id: 'SEC-AWS-SG-001', file: 'main.tf', line: 1 }), true);
    assert.match(fs.readFileSync(file, 'utf8'), /SEC-AWS-SG-001/);
    assert.equal(fs.statSync(file).mode & 0o777, 0o640);
    assert.deepEqual(fs.readdirSync(ws), [BASELINE_FILENAME]);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('report temp files go in a fresh private directory', () => {
  const a = writePrivateTempFile('tf-analyze-ws.html', '<p>a</p>');
  const b = writePrivateTempFile('tf-analyze-ws.html', '<p>b</p>');
  try {
    assert.notEqual(path.dirname(a), path.dirname(b));
    assert.equal(fs.readFileSync(a, 'utf8'), '<p>a</p>');
    assert.equal(fs.statSync(path.dirname(a)).mode & 0o077, 0);
    assert.equal(fs.statSync(a).mode & 0o077, 0);
  } finally {
    fs.rmSync(path.dirname(a), { recursive: true, force: true });
    fs.rmSync(path.dirname(b), { recursive: true, force: true });
  }
});
