// ESM and CommonJS must expose the same API and produce byte identical results.
// The committed cjs/index.cjs is generated from src/*.mjs by scripts/build-cjs.mjs
// and this file is the guard that keeps both entry points honest.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import * as esm from '../src/index.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const require = createRequire(import.meta.url);
const cjs = require('../cjs/index.cjs');

const CORPUS = [
  '(a+)+$',
  '(a*)*$',
  '^(a|aa)+$',
  '.*.*.*$',
  '\\d+\\d+$',
  '(?:(\\w)\\1)+$',
  '(?:(?=a+)\\w)+$',
  '.+',
  '^[a-z0-9]+(?:-[a-z0-9]+)*$',
  '^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$',
  '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$',
  '(?:[A-Za-z0-9+/]{4})*'
];

test('the package root resolves to the CommonJS build', () => {
  const fromRoot = require('..');
  assert.equal(typeof fromRoot.analyzeRegex, 'function');
  assert.deepEqual(Object.keys(fromRoot).sort(), Object.keys(esm).sort());
});

test('ESM and CJS export the same names', () => {
  assert.deepEqual(Object.keys(esm).sort(), Object.keys(cjs).sort());
});

test('ESM and CJS agree on version, rules and CWE metadata', () => {
  assert.equal(esm.VERSION, cjs.VERSION);
  assert.equal(esm.CWE_ID, cjs.CWE_ID);
  assert.equal(esm.CWE_URL, cjs.CWE_URL);
  assert.deepEqual(esm.RULES, cjs.RULES);
});

for (const pattern of CORPUS) {
  test(`parity for /${pattern}/`, () => {
    const left = esm.analyzeRegex(pattern);
    const right = cjs.analyzeRegex(pattern);
    assert.deepEqual(right, left);
  });
}

test('both entry points reject invalid patterns the same way', () => {
  assert.throws(() => esm.analyzeRegex('(a'), /Unterminated group/);
  assert.throws(() => cjs.analyzeRegex('(a'), /Unterminated group/);
});

test('both entry points throw an UnsafeRegexError with the same surface', () => {
  const left = esm.assertSafeRegex;
  const right = cjs.assertSafeRegex;
  let leftError;
  let rightError;
  try {
    left('(a+)+$');
  } catch (error) {
    leftError = error;
  }
  try {
    right('(a+)+$');
  } catch (error) {
    rightError = error;
  }
  assert.equal(leftError.name, rightError.name);
  assert.deepEqual(leftError.analysis, rightError.analysis);
});

test('both entry points expose the parser', () => {
  assert.equal(esm.parseRegex('(a)').captureCount, 1);
  assert.equal(cjs.parseRegex('(a)').captureCount, 1);
});

test('the committed CJS artifact matches the ESM sources', () => {
  const result = spawnSync(process.execPath, [join(ROOT, 'scripts', 'build-cjs.mjs'), '--check'], {
    cwd: ROOT,
    encoding: 'utf8'
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /up to date/);
});

test('the CJS build is strict mode and dependency free', () => {
  const { readFileSync } = require('node:fs');
  const source = readFileSync(join(ROOT, 'cjs', 'index.cjs'), 'utf8');
  assert.match(source, /^'use strict';/);
  assert.equal(/\brequire\(/.test(source), false);
});
