// Red-team regressions: flags that change the language, Annex B class escapes,
// polynomial backtracking across separators, parser resource limits, and
// fail-open option values.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  analyzeRegex,
  isSafeRegex,
  assertSafeRegex,
  RegexParseError,
  UnsafeRegexError
} from '../src/index.mjs';

const codes = (result) => result.findings.map((finding) => finding.code);

test('/i makes alternate case branches ambiguous', () => {
  const result = analyzeRegex('(a|A)+', { flags: 'i' });
  assert.equal(result.risk, 'critical');
  assert.ok(codes(result).includes('RS003'));
  // Without the flag the branches are disjoint and the pattern is safe.
  assert.equal(analyzeRegex('(a|A)+').risk, 'safe');
});

test('/i makes case-folded character classes overlap', () => {
  const result = analyzeRegex('[a-z]+[A-Z]+', { flags: 'i' });
  assert.equal(result.risk, 'high');
  assert.ok(codes(result).includes('RS002'));
  assert.equal(analyzeRegex('[a-z]+[A-Z]+').risk, 'safe');
});

test('/i folds non-ASCII case pairs', () => {
  const result = analyzeRegex('(é|É)+', { flags: 'i' });
  assert.equal(result.risk, 'critical');
  assert.ok(codes(result).includes('RS003'));
});

test('/i folds a negated class before complementing it', () => {
  // [^a] under /i excludes both "a" and "A", so it cannot overlap /a+/.
  assert.equal(codes(analyzeRegex('[^a]+a+', { flags: 'i' })).includes('RS002'), false);
  assert.equal(codes(analyzeRegex('[^a-z]+[A-Z]+', { flags: 'i' })).includes('RS002'), false);
});

test('/s makes the dot overlap line terminators', () => {
  const dotted = analyzeRegex('.*\\n*', { flags: 's' });
  assert.equal(dotted.risk, 'high');
  assert.ok(codes(dotted).includes('RS002'));
  const strict = analyzeRegex('.*\\n*');
  assert.equal(codes(strict).includes('RS002'), false);
});

test('the dot excludes U+2028 and U+2029 without the s flag', () => {
  for (const pattern of ['.*\\u2028*', '.*\\u2029*']) {
    const result = analyzeRegex(pattern);
    assert.equal(codes(result).includes('RS002'), false, pattern);
  }
});

test('class octal escapes for 8 and 9 are identity escapes, not NUL', () => {
  // /[\8]/ matches "8" in Annex B, so /[\8]+8+/ is 8+8+ and quadratic.
  for (const pattern of ['[\\8]+8+', '[\\9]+9+']) {
    const result = analyzeRegex(pattern);
    assert.equal(result.risk, 'high', pattern);
    assert.ok(codes(result).includes('RS002'), pattern);
  }
});

test('a one character separator both scans accept still creates quadratic backtracking', () => {
  const result = analyzeRegex('.*a.*');
  assert.equal(result.risk, 'high');
  assert.ok(codes(result).includes('RS002'));
});

test('a class separator that shares a character with both scans is a bridge', () => {
  const result = analyzeRegex('[a-z]+[a-z0-9-][a-z0-9]+');
  assert.ok(codes(result).includes('RS002'));
});

test('a separator the dot cannot consume does not create an overlap', () => {
  // Without /s the dot excludes U+2028, so it cannot slide across the separator.
  assert.equal(codes(analyzeRegex('.*\\u2028.*')).includes('RS002'), false);
  assert.ok(codes(analyzeRegex('.*\\u2028.*', { flags: 's' })).includes('RS002'));
});

test('literal separated wildcard runs are reported as a cubic chain', () => {
  const result = analyzeRegex('.*a.*b.*c');
  assert.equal(result.risk, 'high');
  assert.equal(result.complexity.worstCase, 'cubic');
  const finding = result.findings.find((entry) => entry.code === 'RS007');
  assert.ok(finding);
  assert.equal(finding.detail.chainLength, 3);
});

test('delimiters outside both scans still keep chains apart', () => {
  assert.equal(analyzeRegex('\\w+@\\w+\\.\\w+').risk === 'safe', true);
  assert.equal(analyzeRegex('[a-z0-9]+(?:-[a-z0-9]+)*').risk, 'safe');
});

test('deeply nested groups fail with a parse error instead of a stack overflow', () => {
  const pattern = '('.repeat(3000) + 'a' + ')'.repeat(3000);
  assert.throws(() => analyzeRegex(pattern), (error) => {
    assert.equal(error instanceof RegexParseError, true);
    assert.match(error.message, /nested too deeply/);
    return true;
  });
  // Below the limit the parser still works.
  const shallow = '('.repeat(400) + 'a' + ')'.repeat(400);
  assert.equal(analyzeRegex(shallow).risk, 'safe');
});

test('v-mode class set operations fail closed instead of being misread', () => {
  for (const pattern of ['[[a-z]--[aeiou]]', '[a--b]', '[\\q{ab}]']) {
    assert.throws(() => analyzeRegex(pattern, { flags: 'v' }), RegexParseError, pattern);
  }
  // Simple v-mode classes still analyze.
  assert.equal(analyzeRegex('[a-z]+', { flags: 'v' }).risk, 'safe');
});

test('an unknown threshold throws instead of silently passing critical patterns', () => {
  assert.throws(() => assertSafeRegex('(a+)+$', { threshold: 'extreme' }), TypeError);
  assert.throws(() => isSafeRegex('(a+)+$', { threshold: 'extreme' }), TypeError);
  assert.throws(() => assertSafeRegex('(a+)+$', { threshold: 'critical' }), UnsafeRegexError);
});

test('an invalid maxFindings throws instead of hiding every finding', () => {
  assert.throws(() => analyzeRegex('(a+)+$', { maxFindings: -1 }), TypeError);
  assert.throws(() => analyzeRegex('(a+)+$', { maxFindings: '1' }), TypeError);
  assert.throws(() => analyzeRegex('(a+)+$', { maxFindings: 1.5 }), TypeError);
});

test('inherited option properties cannot weaken the gate', () => {
  const polluted = Object.create({
    threshold: 'safe',
    maxFindings: 0,
    includeBroad: false,
    witnesses: false
  });
  assert.equal(isSafeRegex('(a+)+$', polluted), false);
  assert.throws(() => assertSafeRegex('(a+)+$', polluted), UnsafeRegexError);
  const result = analyzeRegex('(a+)+$', polluted);
  assert.equal(result.risk, 'critical');
  assert.ok(result.findings.length > 0);
  assert.throws(() => analyzeRegex(Object.create({ pattern: '(a+)+$' })), TypeError);
});
