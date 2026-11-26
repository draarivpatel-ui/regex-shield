import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const CLI = join(ROOT, 'bin', 'regex-shield.mjs');

function run(args, input) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    input,
    timeout: 20000
  });
}

test('--help prints usage and exits zero', () => {
  const result = run(['--help']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Usage:/);
  assert.match(result.stdout, /Exit codes:/);
});

test('--version prints the package version', () => {
  const result = run(['--version']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), '1.0.0');
});

test('no arguments is a usage error', () => {
  const result = run([]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /no patterns/);
});

test('a safe pattern exits zero', () => {
  const result = run(['^[a-z]+$']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /risk: safe/);
  assert.match(result.stdout, /1 pattern checked/);
});

test('a dangerous pattern exits one and prints the rule', () => {
  const result = run(['(a+)+$']);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /risk: critical/);
  assert.match(result.stdout, /RS001/);
});

test('--json emits parseable deterministic JSON', () => {
  const first = run(['--json', '(a+)+$']);
  const second = run(['--json', '(a+)+$']);
  assert.equal(first.status, 1);
  const payload = JSON.parse(first.stdout);
  assert.equal(payload.tool, 'regex-shield');
  assert.equal(payload.version, '1.0.0');
  assert.equal(payload.threshold, 'medium');
  assert.equal(payload.safe, false);
  assert.equal(payload.results[0].risk, 'critical');
  assert.equal(payload.results[0].findings[0].code, 'RS001');
  assert.equal(first.stdout, second.stdout);
});

test('--json marks safe runs as safe', () => {
  const result = run(['--json', '^[a-z]+$']);
  assert.equal(result.status, 0);
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.safe, true);
  assert.equal(payload.results[0].risk, 'safe');
});

test('--flags is applied to pattern strings', () => {
  const result = run(['--json', '--flags', 'i', '^[a-z]+$']);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).results[0].flags, 'i');
});

test('--flags=value form is accepted', () => {
  const result = run(['--json', '--flags=i', '^(A+)+$']);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).results[0].flags, 'i');
});

test('--threshold raises the failure bar', () => {
  const result = run(['--threshold', 'critical', '.*.*$']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /all below "critical"/);
});

test('--threshold lowers the failure bar', () => {
  const result = run(['--threshold', 'low', '.+']);
  assert.equal(result.status, 1);
});

test('an invalid threshold is rejected', () => {
  const result = run(['--threshold', 'extreme', 'a']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /invalid threshold/);
});

test('an invalid pattern exits with a parse error', () => {
  const result = run(['(a']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unterminated group/);
});

test('invalid flags exit with a parse error', () => {
  const result = run(['--flags', 'z', 'a']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Invalid regular expression flag/);
});

test('an unknown option is rejected', () => {
  const result = run(['--wat', 'a']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unknown option/);
});

test('--stdin reads a single pattern', () => {
  const result = run(['--stdin'], '(a+)+$\n');
  assert.equal(result.status, 1);
  assert.match(result.stdout, /RS001/);
});

test('--stdin cannot be combined with positional patterns', () => {
  const result = run(['--stdin', '(a+)+$'], 'a\n');
  assert.equal(result.status, 2);
  assert.match(result.stderr, /either --stdin or positional/);
});

test('multiple patterns are checked and summarised', () => {
  const result = run(['^[a-z]+$', '(a+)+$']);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /2 patterns checked/);
  assert.match(result.stdout, /at least one at or above "medium"/);
});

test('--no-witness removes witness hints', () => {
  const result = run(['--no-witness', '(a+)+$']);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.includes('witness hint'), false);
});

test('--no-broad removes the informational broad rule', () => {
  const result = run(['--no-broad', '.+']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /no findings/);
});

test('--json reports parse errors alongside valid results', () => {
  const result = run(['--json', '^a$', '(a']);
  assert.equal(result.status, 2);
  const payload = JSON.parse(result.stdout);
  assert.equal(payload.results.length, 1);
  assert.equal(payload.parseErrors.length, 1);
  assert.match(payload.parseErrors[0].message, /Unterminated group/);
});

test('a pattern that starts with a dash can follow --', () => {
  const result = run(['--', '-foo']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /risk: safe/);
});
