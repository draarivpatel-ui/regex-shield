import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
const EM_DASH = String.fromCharCode(0x2014);
const EN_DASH = String.fromCharCode(0x2013);
const HOME_PREFIX = `/${'Users'}/`;

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.git') continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

test('package metadata is complete', () => {
  assert.equal(pkg.name, '@aarivbuildz/regex-shield');
  assert.match(pkg.version, /^\d+\.\d+\.\d+$/);
  assert.equal(pkg.license, 'MIT');
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.sideEffects, false);
  assert.equal(pkg.engines.node, '>=18.0.0');
});

test('runtime dependencies are zero and fuzz tooling stays development-only', () => {
  assert.deepEqual(pkg.dependencies, {});
  assert.ok(Object.keys(pkg.devDependencies || {}).includes('fast-check'));
  for (const name of Object.keys(pkg.devDependencies || {})) {
    assert.equal(pkg.dependencies[name], undefined, `${name} must stay development-only`);
  }
});

test('the entry points exist and are wired in exports', () => {
  for (const file of ['src/index.mjs', 'cjs/index.cjs', 'types/index.d.ts', 'bin/regex-shield.mjs']) {
    assert.equal(existsSync(join(ROOT, file)), true, file);
  }
  assert.equal(pkg.main, './cjs/index.cjs');
  assert.equal(pkg.module, './src/index.mjs');
  assert.equal(pkg.types, './types/index.d.ts');
  assert.equal(pkg.exports['.'].import, './src/index.mjs');
  assert.equal(pkg.exports['.'].require, './cjs/index.cjs');
  assert.equal(pkg.exports['.'].types, './types/index.d.ts');
});

test('the CLI entry has a shebang and the bin mapping', () => {
  const source = readFileSync(join(ROOT, 'bin', 'regex-shield.mjs'), 'utf8');
  assert.match(source, /^#!\/usr\/bin\/env node\n/);
  assert.equal(pkg.bin['regex-shield'], './bin/regex-shield.mjs');
});

test('published files are present', () => {
  for (const file of [
    'README.md',
    'LICENSE',
    'SECURITY.md',
    'CONTRIBUTING.md',
    '.github/workflows/ci.yml',
    'benchmarks/bench.mjs'
  ]) {
    assert.equal(existsSync(join(ROOT, file)), true, file);
  }
  for (const dir of ['src', 'cjs', 'types', 'bin']) {
    assert.ok(pkg.files.includes(dir), dir);
  }
});

test('README documents the API, rules and test count', () => {
  const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
  for (const name of ['analyzeRegex', 'assertSafeRegex', 'isSafeRegex', 'CWE-1333']) {
    assert.ok(readme.includes(name), name);
  }
  assert.match(readme, /\d+ deterministic tests/);
  assert.match(readme, /zero dependencies/i);
  assert.equal(readme.includes(EM_DASH), false);
  assert.equal(readme.includes(EN_DASH), false);
});

test('security policy explains private reporting', () => {
  const policy = readFileSync(join(ROOT, 'SECURITY.md'), 'utf8');
  assert.match(policy, /Reporting/i);
  assert.match(policy, /security\/advisories/);
  assert.match(policy, /Supported/i);
});

test('contributing guide names the test command', () => {
  const guide = readFileSync(join(ROOT, 'CONTRIBUTING.md'), 'utf8');
  assert.match(guide, /npm test/);
  assert.match(guide, /build:cjs/);
});

test('the license is MIT for the project contributors', () => {
  const license = readFileSync(join(ROOT, 'LICENSE'), 'utf8');
  assert.match(license, /MIT License/);
  assert.match(license, /regex-shield contributors/);
});

test('CI runs the test suite and the CJS parity check', () => {
  const workflow = readFileSync(join(ROOT, '.github/workflows/ci.yml'), 'utf8');
  assert.match(workflow, /npm test/);
  assert.match(workflow, /build-cjs\.mjs --check/);
  assert.match(workflow, /node-version/);
  assert.match(workflow, /18/);
});

test('type definitions cover the public API', () => {
  const types = readFileSync(join(ROOT, 'types/index.d.ts'), 'utf8');
  for (const name of [
    'analyzeRegex',
    'assertSafeRegex',
    'isSafeRegex',
    'parseRegex',
    'scan',
    'CharSet',
    'UnsafeRegexError',
    'RegexParseError',
    'Analysis',
    'Finding',
    'Witness',
    'RiskLevel'
  ]) {
    assert.ok(types.includes(name), name);
  }
});

test('no shipped text file contains internal paths or em dashes', () => {
  const files = walk(ROOT).filter((file) =>
    /\.(mjs|cjs|js|ts|json|md|yml|yaml)$/.test(file)
  );
  assert.ok(files.length > 20);
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    assert.equal(text.includes(HOME_PREFIX), false, `internal path in ${file}`);
    assert.equal(text.includes(EM_DASH), false, `em dash in ${file}`);
    assert.equal(text.includes(EN_DASH), false, `en dash in ${file}`);
  }
});

test('gitignore excludes local artifacts', () => {
  const ignore = readFileSync(join(ROOT, '.gitignore'), 'utf8');
  assert.match(ignore, /node_modules\//);
  assert.match(ignore, /coverage\//);
  assert.match(ignore, /\.DS_Store/);
});
