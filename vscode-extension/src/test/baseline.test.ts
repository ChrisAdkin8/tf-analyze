import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  BASELINE_FILENAME,
  baselinePath,
  baselineExists,
  ensureBaselineFile,
  suppress,
  unsuppress,
} from '../baseline';

/** Create a fresh temp workspace dir for each test. Returned dir is
 * cleaned up by the caller — node:test doesn't have a built-in
 * teardown the way mocha does, so we do it inline at the end of each
 * test. */
function freshWs(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'tfa-baseline-'));
}

function read(ws: string): { findings: { id: string; file: string; line: number; resource?: string }[]; meta?: unknown } {
  const raw = fs.readFileSync(baselinePath(ws), 'utf8');
  return JSON.parse(raw);
}

test('baselinePath joins workspace + filename', () => {
  const ws = '/tmp/whatever';
  assert.equal(baselinePath(ws), path.join(ws, BASELINE_FILENAME));
});

test('baselineExists returns false on a fresh workspace', () => {
  const ws = freshWs();
  try {
    assert.equal(baselineExists(ws), false);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('ensureBaselineFile creates an empty findings array when missing', () => {
  const ws = freshWs();
  try {
    const p = ensureBaselineFile(ws);
    assert.equal(p, baselinePath(ws));
    assert.equal(baselineExists(ws), true);
    const parsed = read(ws);
    assert.deepEqual(parsed.findings, []);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('ensureBaselineFile is non-destructive when the file already exists', () => {
  const ws = freshWs();
  try {
    fs.writeFileSync(baselinePath(ws), JSON.stringify({ findings: [{ id: 'PRE', file: 'a.tf', line: 1 }] }));
    ensureBaselineFile(ws);
    const parsed = read(ws);
    assert.equal(parsed.findings.length, 1);
    assert.equal(parsed.findings[0].id, 'PRE');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('suppress adds a finding and returns true; second call is a no-op returning false', () => {
  const ws = freshWs();
  try {
    const f = { id: 'SEC-AWS-S3-001', file: 'main.tf', line: 17, resource: 'aws_s3_bucket.x' };
    assert.equal(suppress(ws, f), true);
    assert.equal(suppress(ws, f), false, 'second suppress for same key should be a no-op');

    const parsed = read(ws);
    assert.equal(parsed.findings.length, 1);
    assert.equal(parsed.findings[0].id, 'SEC-AWS-S3-001');
    assert.equal(parsed.findings[0].file, 'main.tf');
    assert.equal(parsed.findings[0].line, 17);
    assert.equal(parsed.findings[0].resource, 'aws_s3_bucket.x');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('suppress preserves multiple findings with distinct keys', () => {
  const ws = freshWs();
  try {
    suppress(ws, { id: 'A', file: 'x.tf', line: 1 });
    suppress(ws, { id: 'A', file: 'x.tf', line: 2 });               // same id, different line
    suppress(ws, { id: 'B', file: 'x.tf', line: 1 });               // same line, different id
    suppress(ws, { id: 'A', file: 'y.tf', line: 1 });               // same id+line, different file
    suppress(ws, { id: 'A', file: 'x.tf', line: 1, resource: 'r' }); // same id+file+line, different resource

    const parsed = read(ws);
    assert.equal(parsed.findings.length, 5, 'each distinct (id, file, line, resource) should produce a record');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('unsuppress removes the matching finding and returns true; missing keys return false', () => {
  const ws = freshWs();
  try {
    suppress(ws, { id: 'A', file: 'x.tf', line: 1 });
    suppress(ws, { id: 'B', file: 'x.tf', line: 2 });
    assert.equal(unsuppress(ws, { id: 'A', file: 'x.tf', line: 1 }), true);
    assert.equal(unsuppress(ws, { id: 'A', file: 'x.tf', line: 1 }), false, 'already removed key should return false');
    assert.equal(unsuppress(ws, { id: 'NOPE', file: 'x.tf', line: 99 }), false);

    const parsed = read(ws);
    assert.equal(parsed.findings.length, 1);
    assert.equal(parsed.findings[0].id, 'B');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('unsuppress on a non-existent baseline file is a safe no-op', () => {
  const ws = freshWs();
  try {
    assert.equal(baselineExists(ws), false);
    assert.equal(unsuppress(ws, { id: 'A', file: 'x.tf', line: 1 }), false);
    assert.equal(baselineExists(ws), false, 'unsuppress should not create the file just to remove nothing');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('write injects meta.last_updated timestamp', () => {
  const ws = freshWs();
  try {
    suppress(ws, { id: 'A', file: 'x.tf', line: 1 });
    const parsed = read(ws);
    const meta = parsed.meta as { last_updated?: string; created_by?: string } | undefined;
    assert.ok(meta?.last_updated, 'meta.last_updated should be present');
    assert.ok(meta?.created_by?.includes('vscode-extension'), 'meta.created_by should identify the writer');
    // Timestamp should be a valid ISO string
    assert.ok(!isNaN(Date.parse(meta?.last_updated ?? '')), 'meta.last_updated should be parseable as ISO 8601');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('a corrupted baseline file is treated as empty rather than crashing', () => {
  const ws = freshWs();
  try {
    fs.writeFileSync(baselinePath(ws), 'this is not JSON {{{', 'utf8');
    // suppress should still succeed — read() returns {findings: []} on parse error
    const added = suppress(ws, { id: 'A', file: 'x.tf', line: 1 });
    assert.equal(added, true);
    const parsed = read(ws);
    assert.equal(parsed.findings.length, 1, 'corrupted file should be replaced with one containing only the new finding');
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test('a baseline file without a findings array is treated as empty', () => {
  const ws = freshWs();
  try {
    fs.writeFileSync(baselinePath(ws), JSON.stringify({ meta: { foo: 1 } }));
    const added = suppress(ws, { id: 'A', file: 'x.tf', line: 1 });
    assert.equal(added, true);
    const parsed = read(ws);
    assert.equal(parsed.findings.length, 1);
  } finally {
    fs.rmSync(ws, { recursive: true, force: true });
  }
});
