// Production regex regression corpus.
//
// These are the patterns maintainers actually put in validators, routers and
// parsers. The analyser must leave them alone. Each case is paired with the
// input shape it is designed for, although the analyser never runs the regex.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeRegex, isSafeRegex } from '../src/index.mjs';

const BENIGN = [
  { name: 'email', pattern: '^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$' },
  { name: 'email strict', pattern: '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$' },
  { name: 'url', pattern: '^(https?):\\/\\/([^:\\/\\s]+)(?::(\\d+))?(\\/[^\\s]*)?$' },
  { name: 'url short', pattern: '^https?://[^\\s/]+(?:/[^\\s]*)?$' },
  { name: 'uuid', pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' },
  { name: 'iso datetime', pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,3})?(Z|[+-]\\d{2}:\\d{2})$' },
  { name: 'ipv4', pattern: '^(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)$' },
  { name: 'ipv6', pattern: '^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1)$' },
  { name: 'semver', pattern: '^v?(\\d+)\\.(\\d+)\\.(\\d+)(?:-([0-9A-Za-z.-]+))?(?:\\+[0-9A-Za-z.-]+)?$' },
  { name: 'domain', pattern: '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$' },
  { name: 'slug', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' },
  { name: 'hex color', pattern: '^#?([a-f0-9]{6}|[a-f0-9]{3})$' },
  { name: 'jwt', pattern: '^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$' },
  { name: 'number', pattern: '^[-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?$' },
  { name: 'date', pattern: '^\\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])$' },
  { name: 'time', pattern: '^([01]\\d|2[0-3]):[0-5]\\d(:[0-5]\\d)?$' },
  { name: 'username', pattern: '^[a-zA-Z0-9_]{3,16}$' },
  { name: 'filename', pattern: '^[\\w\\-. ]+\\.(js|mjs|cjs|json|md)$' },
  { name: 'path segments', pattern: '^[\\w.~-]+(?:/[\\w.~-]+)*$' },
  { name: 'timestamp', pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z$' },
  { name: 'css custom property', pattern: '^--[a-z][a-z0-9-]*$' },
  { name: 'hex literal', pattern: '^0x[0-9a-fA-F]+$' },
  { name: 'query pair', pattern: '^[?&][^=&#]+=[^&#]*$' },
  { name: 'phone', pattern: '^\\+?[1-9]\\d{1,14}$' },
  { name: 'currency', pattern: '^\\$?(\\d{1,3}(,\\d{3})*|\\d+)(\\.\\d{2})?$' },
  { name: 'css color', pattern: '^rgba?\\(\\s*(\\d{1,3})\\s*,\\s*(\\d{1,3})\\s*,\\s*(\\d{1,3})\\s*(?:,\\s*(0|1|0?\\.\\d+)\\s*)?\\)$' },
  { name: 'markdown link', pattern: '^\\[([^\\]]+)\\]\\(([^\\)]+)\\)$' },
  { name: 'quoted string', pattern: '^"(?:[^"\\\\]|\\\\.)*"$' },
  { name: 'json key', pattern: '^"(?:[^"\\\\]|\\\\.)*"\\s*:\\s*' },
  { name: 'base64', pattern: '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$' },
  { name: 'empty line', pattern: '^\\s*$' },
  { name: 'word boundary', pattern: '\\b\\w+\\b' },
  { name: 'iso date only', pattern: '^\\d{4}-\\d{2}-\\d{2}$' },
  { name: 'camel case', pattern: '^[a-z][a-zA-Z0-9]*$' },
  { name: 'duplicate word', pattern: '\\b(\\w+)\\s+\\1\\b' },
  { name: 'size unit', pattern: '^\\d+(?:\\.\\d+)?(?:px|rem|em|%)$' },
  { name: 'version range', pattern: '^[~^]?\\d+(?:\\.\\d+){0,2}$' },
  { name: 'windows drive', pattern: '^[A-Za-z]:\\\\[^\\\\]+(?:\\\\[^\\\\]+)*$' }
];

for (const entry of BENIGN) {
  test(`benign ${entry.name} regex stays safe`, () => {
    const result = analyzeRegex(entry.pattern);
    assert.equal(result.safe, true, `${entry.name}: ${result.findings.map((finding) => finding.code).join(',')}`);
    assert.equal(isSafeRegex(entry.pattern), true);
  });
}

test('a broad informational note can appear on an otherwise safe pattern', () => {
  const result = analyzeRegex('[^<]+');
  assert.equal(result.risk, 'low');
  assert.equal(result.safe, true);
  assert.deepEqual(result.findings.map((finding) => finding.code), ['RS008']);
});

test('the classic HTML tag regex is flagged as risky', () => {
  const result = analyzeRegex('^<([a-z]+)([^<]+)*(?:>(.*)<\\/\\1>|\\s+\\/>)$');
  assert.equal(result.risk, 'critical');
  assert.ok(result.findings.some((finding) => finding.rule === 'nested-quantifier'));
});

test('an unanchored HTML tag scan is at least low risk', () => {
  const result = analyzeRegex('<([a-z][a-z0-9]*)\\b[^>]*>(.*?)<\\/\\1>');
  assert.equal(result.safe, true);
  assert.ok(result.findings.some((finding) => finding.code === 'RS008'));
});

test('flags do not change the structural verdict', () => {
  assert.equal(analyzeRegex('^[a-z]+$', { flags: 'i' }).risk, 'safe');
  assert.equal(analyzeRegex('^(a+)+$', { flags: 'i' }).risk, 'critical');
});
