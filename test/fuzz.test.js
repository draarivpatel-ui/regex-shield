import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import {
  RegexParseError,
  UnsafeRegexError,
  analyzeRegex,
  assertSafeRegex,
  isSafeRegex,
  scan
} from '../src/index.mjs';

const LITERAL_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.split('');

function literalText(minLength, maxLength) {
  return fc.array(fc.constantFrom(...LITERAL_CHARS), { minLength, maxLength }).map((items) => items.join(''));
}

test('positive: bounded literal patterns are accepted as safe', () => {
  fc.assert(fc.property(literalText(1, 24), (text) => {
    const pattern = '^' + text + '$';
    const result = analyzeRegex(pattern);
    assert.equal(result.safe, true);
    assert.equal(result.risk, 'safe');
    assert.equal(result.score, 0);
    assert.deepEqual(result.findings, []);
    assert.equal(isSafeRegex(pattern), true);
    assert.equal(scan([pattern])[0].safe, true);
    assert.doesNotThrow(() => assertSafeRegex(pattern));
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: nested quantifiers are rejected as catastrophic-backtracking risks', () => {
  fc.assert(fc.property(fc.constantFrom(...LITERAL_CHARS), (char) => {
    const pattern = '(' + char + '+)+$';
    const result = analyzeRegex(pattern);
    assert.equal(result.safe, false);
    assert.equal(result.risk, 'critical');
    assert.ok(result.findings.some((finding) => finding.code === 'RS001'));
    assert.equal(isSafeRegex(pattern), false);
    assert.throws(() => assertSafeRegex(pattern), UnsafeRegexError);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: overlapping adjacent quantifiers are never reported safe', () => {
  fc.assert(fc.property(fc.constantFrom('a', '0', '_'), fc.constantFrom('+', '*'), (char, quantifier) => {
    const pattern = char + quantifier + char + '+$';
    const result = analyzeRegex(pattern);
    assert.equal(result.safe, false);
    assert.ok(result.findings.some((finding) => finding.code === 'RS002' || finding.code === 'RS001'));
    assert.equal(isSafeRegex(pattern), false);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: malformed patterns are rejected instead of analyzed as safe', () => {
  fc.assert(fc.property(literalText(0, 18), (text) => {
    const pattern = '(' + text;
    assert.throws(() => analyzeRegex(pattern), RegexParseError);
    assert.throws(() => scan([pattern]), RegexParseError);
  }), { seed: 20261127, numRuns: 100 });
});
