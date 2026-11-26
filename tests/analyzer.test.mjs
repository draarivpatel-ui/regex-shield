import test from 'node:test';
import assert from 'node:assert/strict';

import {
  analyzeRegex,
  isSafeRegex,
  assertSafeRegex,
  scan,
  UnsafeRegexError,
  RegexParseError,
  RULES,
  CWE_ID,
  CWE_URL,
  VERSION
} from '../src/index.mjs';

const codes = (result) => result.findings.map((finding) => finding.code);

test('analyzeRegex returns the documented result shape', () => {
  const result = analyzeRegex('(a+)+$');
  assert.equal(result.pattern, '(a+)+$');
  assert.equal(result.flags, '');
  assert.equal(result.safe, false);
  assert.equal(result.risk, 'critical');
  assert.equal(result.score, 70);
  assert.equal(Array.isArray(result.findings), true);
  assert.equal(Array.isArray(result.witnesses), true);
  assert.equal(typeof result.witnessHint, 'string');
  assert.equal(typeof result.starHeight, 'number');
  assert.equal(typeof result.complexity, 'object');
  assert.deepEqual(result.parsed, { captureCount: 1, groupNames: [] });
});

test('a literal pattern is safe with no findings', () => {
  const result = analyzeRegex('^hello world$');
  assert.equal(result.safe, true);
  assert.equal(result.risk, 'safe');
  assert.equal(result.score, 0);
  assert.deepEqual(result.findings, []);
  assert.equal(result.witnessHint, '');
});

test('RegExp input keeps source and flags', () => {
  const result = analyzeRegex(/^(a+)+$/im);
  assert.equal(result.pattern, '^(a+)+$');
  assert.equal(result.flags, 'im');
  assert.equal(result.risk, 'critical');
});

test('pattern object input is accepted', () => {
  const result = analyzeRegex({ pattern: '^(a+)+$', flags: 'g' });
  assert.equal(result.flags, 'g');
  assert.equal(result.risk, 'critical');
});

test('invalid input types are rejected', () => {
  assert.throws(() => analyzeRegex(null), TypeError);
  assert.throws(() => analyzeRegex(42), TypeError);
  assert.throws(() => analyzeRegex({ flags: 'g' }), TypeError);
});

test('invalid patterns surface as RegexParseError', () => {
  assert.throws(() => analyzeRegex('(a'), RegexParseError);
});

test('findings carry CWE metadata and stable identifiers', () => {
  const [finding] = analyzeRegex('(a+)+$').findings;
  assert.equal(finding.id, 'RS001');
  assert.equal(finding.code, 'RS001');
  assert.equal(finding.cwe, CWE_ID);
  assert.equal(finding.cwe, 'CWE-1333');
  assert.match(CWE_URL, /^https:\/\/cwe\.mitre\.org\//);
  assert.equal(finding.rule, RULES.NESTED_QUANTIFIER);
});

test('RULES exposes every rule identifier', () => {
  assert.deepEqual(Object.keys(RULES).sort(), [
    'BACKREFERENCE_IN_QUANTIFIER',
    'BROAD_UNBOUNDED',
    'LOOKAROUND_IN_QUANTIFIER',
    'MULTIPLE_WILDCARDS',
    'NESTED_QUANTIFIER',
    'NULLABLE_QUANTIFIER_BODY',
    'OVERLAPPING_ADJACENT',
    'OVERLAPPING_ALTERNATION'
  ]);
  assert.equal(VERSION, '1.0.0');
});

// ---------------------------------------------------------------------------
// Nested quantifiers
// ---------------------------------------------------------------------------

test('nested plus inside plus is critical', () => {
  const result = analyzeRegex('(a+)+$');
  assert.deepEqual(codes(result), ['RS001']);
  assert.equal(result.findings[0].severity, 'critical');
  assert.equal(result.findings[0].complexity, 'exponential');
  assert.equal(result.complexity.worstCase, 'exponential');
});

test('nested digits inside a capture group are critical', () => {
  const result = analyzeRegex('^(\\d+)+$');
  assert.deepEqual(codes(result), ['RS001']);
  assert.equal(result.risk, 'critical');
});

test('a nullable inner star also reports the empty body rule', () => {
  const result = analyzeRegex('(a*)*$');
  assert.deepEqual(codes(result), ['RS001', 'RS006']);
  assert.equal(result.score, 82);
});

test('the classic OWASP evil regex is detected', () => {
  const result = analyzeRegex('^(([a-z])+.)+[A-Z]([a-z])+$');
  assert.equal(result.risk, 'critical');
  assert.ok(codes(result).includes('RS001'));
});

test('nested quantifier with a bare overlapping neighbour is detected', () => {
  const result = analyzeRegex('(a+a)+');
  assert.deepEqual(codes(result), ['RS001']);
  assert.equal(result.risk, 'critical');
});

test('a bounded outer quantifier lowers the nested severity', () => {
  const result = analyzeRegex('(?:(?:a+)){2}$');
  assert.deepEqual(codes(result), ['RS001']);
  assert.equal(result.findings[0].severity, 'high');
  assert.equal(result.findings[0].complexity, 'quadratic');
});

test('a required separator makes a repeated group deterministic', () => {
  assert.equal(analyzeRegex('(ab+)+$').risk, 'safe');
  assert.equal(analyzeRegex('(a+x)+$').risk, 'safe');
});

test('a fixed stride repetition is not exponential', () => {
  assert.equal(analyzeRegex('(a{2})+$').risk, 'safe');
  assert.equal(analyzeRegex('(?:[A-Za-z0-9+/]{4})*').risk, 'safe');
});

test('nested finding details include bounds and a witness character', () => {
  const [finding] = analyzeRegex('(a+)+$').findings;
  assert.equal(finding.detail.bounds, '+ over +');
  assert.equal(finding.detail.sampleChar, 'a');
  assert.equal(finding.detail.terminator, '!');
  assert.deepEqual(finding.detail.ranges, [[0x61, 0x61]]);
});

// ---------------------------------------------------------------------------
// Adjacent overlapping quantifiers
// ---------------------------------------------------------------------------

test('adjacent digit quantifiers are quadratic', () => {
  const result = analyzeRegex('\\d+\\d+$');
  assert.deepEqual(codes(result), ['RS002']);
  assert.equal(result.findings[0].severity, 'high');
  assert.equal(result.findings[0].complexity, 'quadratic');
  assert.equal(result.complexity.worstCase, 'quadratic');
});

test('adjacent capture groups with the same class are quadratic', () => {
  const result = analyzeRegex('(a+)(a+)$');
  assert.deepEqual(codes(result), ['RS002']);
});

test('adjacent wildcards are quadratic', () => {
  const result = analyzeRegex('.*.*$');
  assert.deepEqual(codes(result), ['RS002']);
  assert.equal(result.risk, 'high');
});

test('disjoint adjacent classes are not reported', () => {
  assert.equal(analyzeRegex('[a-z]+[0-9]+$').risk, 'safe');
  assert.equal(analyzeRegex('\\w+\\s+\\w+').risk, 'safe');
});

test('bounded adjacent quantifiers are not reported', () => {
  assert.equal(analyzeRegex('\\d{2}\\d{3}$').risk, 'safe');
});

test('the ambiguous boundary is described in the finding', () => {
  const [finding] = analyzeRegex('\\d+\\d+$').findings;
  assert.equal(finding.detail.leftBounds, '+');
  assert.equal(finding.detail.rightBounds, '+');
  assert.equal(finding.detail.sampleChar, '0');
});

// ---------------------------------------------------------------------------
// Overlapping alternation branches
// ---------------------------------------------------------------------------

test('a prefix overlapping alternation is critical', () => {
  const result = analyzeRegex('(a|aa)+$');
  assert.deepEqual(codes(result), ['RS003']);
  assert.equal(result.findings[0].severity, 'critical');
  assert.equal(result.findings[0].detail.repeatUnit, 'a');
});

test('identical alternation branches are critical', () => {
  assert.equal(analyzeRegex('(a|a)*$').risk, 'critical');
});

test('a branch contained in another is critical', () => {
  assert.equal(analyzeRegex('^(\\w|_)+$').risk, 'critical');
});

test('an empty branch inside a loop is critical', () => {
  const result = analyzeRegex('(a|)+$');
  assert.ok(codes(result).includes('RS003'));
  assert.equal(result.risk, 'critical');
});

test('a nullable empty branch is reported from either side', () => {
  assert.equal(analyzeRegex('(?:|a)+$').risk, 'critical');
  assert.equal(analyzeRegex('(?:a|)*').risk, 'critical');
});

test('a prefix related branch is critical', () => {
  assert.equal(analyzeRegex('(?:a|ab)+$').risk, 'critical');
});

test('disjoint literal branches stay safe', () => {
  assert.equal(analyzeRegex('(?:foo|bar)+$').risk, 'safe');
  assert.equal(analyzeRegex('^(?:cat|dog)$').risk, 'safe');
});

// ---------------------------------------------------------------------------
// Unbounded wildcard chains
// ---------------------------------------------------------------------------

test('three overlapping unbounded quantifiers form a cubic chain', () => {
  const result = analyzeRegex('.*.*.*$');
  assert.deepEqual(codes(result), ['RS007']);
  assert.equal(result.findings[0].complexity, 'cubic');
  assert.equal(result.findings[0].detail.chainLength, 3);
});

test('a wildcard chain with digits is detected', () => {
  const result = analyzeRegex('.+\\d+.+$');
  assert.deepEqual(codes(result), ['RS007']);
});

test('a chain separated by a literal is not a chain', () => {
  const result = analyzeRegex('.*\\n.*.*');
  assert.equal(codes(result).includes('RS007'), false);
});

test('a chain finding suppresses pairwise duplicates for its elements', () => {
  const result = analyzeRegex('.*.*.*$');
  assert.equal(result.findings.filter((finding) => finding.code === 'RS002').length, 0);
});

// ---------------------------------------------------------------------------
// Nullable bodies
// ---------------------------------------------------------------------------

test('an optional body in an unbounded loop reports the nullable rule', () => {
  const result = analyzeRegex('(?:a?)*$');
  assert.deepEqual(codes(result), ['RS006']);
  assert.equal(result.findings[0].severity, 'medium');
  assert.equal(result.risk, 'medium');
});

test('a star body in a plus loop reports both rules', () => {
  const result = analyzeRegex('(?:a*)+$');
  assert.deepEqual(codes(result), ['RS001', 'RS006']);
});

test('a non nullable single character body is not reported', () => {
  assert.equal(analyzeRegex('(?:a)+$').risk, 'safe');
});

// ---------------------------------------------------------------------------
// Backreferences and lookarounds
// ---------------------------------------------------------------------------

test('a backreference inside an unbounded loop is critical', () => {
  const result = analyzeRegex('(?:(\\w)\\1)+$');
  assert.deepEqual(codes(result), ['RS004']);
  assert.equal(result.findings[0].severity, 'critical');
  assert.equal(result.findings[0].complexity, 'exponential');
});

test('a backreference inside a bounded loop is high', () => {
  const result = analyzeRegex('(?:(\\w)\\1){2}$');
  assert.deepEqual(codes(result), ['RS004']);
  assert.equal(result.findings[0].severity, 'high');
});

test('a backreference outside a loop is not reported', () => {
  assert.equal(analyzeRegex('(\\w+)\\s+\\1').risk, 'safe');
});

test('an unbounded lookahead inside a loop is high', () => {
  const result = analyzeRegex('(?:(?=a+)\\w)+$');
  assert.deepEqual(codes(result), ['RS005']);
  assert.equal(result.findings[0].severity, 'high');
});

test('a negative lookahead inside a loop is high', () => {
  assert.equal(analyzeRegex('(?:(?!\\d+)\\w)+$').risk, 'high');
});

test('a lookbehind inside a loop is high', () => {
  assert.equal(analyzeRegex('(?:(?<=a+)\\w)+$').risk, 'high');
});

test('a bounded lookaround inside a loop is only medium', () => {
  const result = analyzeRegex('(?:(?=a{2})\\w)+$');
  assert.deepEqual(result.findings, []);
});

test('a quantified lookaround is reported when it scans unbounded text', () => {
  const result = analyzeRegex('(?:(?=a+)\\w){2}$');
  assert.deepEqual(codes(result), ['RS005']);
  assert.equal(result.findings[0].severity, 'medium');
});

// ---------------------------------------------------------------------------
// Broad unbounded scans
// ---------------------------------------------------------------------------

test('an unanchored dot repetition is a low informational finding', () => {
  const result = analyzeRegex('.+');
  assert.deepEqual(codes(result), ['RS008']);
  assert.equal(result.risk, 'low');
  assert.equal(result.safe, true);
  assert.equal(result.score, 4);
});

test('a large unanchored negated class is broad', () => {
  assert.deepEqual(codes(analyzeRegex('[^a]+')), ['RS008']);
});

test('anchoring suppresses the broad rule', () => {
  assert.equal(analyzeRegex('^.+').risk, 'safe');
  assert.equal(analyzeRegex('^[^a]+$').risk, 'safe');
});

test('small unanchored classes are not broad', () => {
  assert.equal(analyzeRegex('\\d+').risk, 'safe');
  assert.equal(analyzeRegex('\\w+').risk, 'safe');
});

test('includeBroad false removes the informational rule', () => {
  const result = analyzeRegex('.+', { includeBroad: false });
  assert.deepEqual(result.findings, []);
  assert.equal(result.risk, 'safe');
});

test('maxFindings caps the returned list', () => {
  const result = analyzeRegex('(a*)*$', { maxFindings: 1 });
  assert.equal(result.findings.length, 1);
  assert.equal(result.risk, 'critical');
});

test('witnesses can be disabled', () => {
  const result = analyzeRegex('(a+)+$', { witnesses: false });
  assert.deepEqual(result.witnesses, []);
  assert.equal(result.witnessHint, '');
});

test('the score never exceeds one hundred', () => {
  const result = analyzeRegex('^(a+)(a+)(a+)(a+)(a+)+$');
  assert.ok(result.score <= 100);
  assert.ok(result.score >= 70);
});

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

test('isSafeRegex uses a medium threshold by default', () => {
  assert.equal(isSafeRegex('(a+)+$'), false);
  assert.equal(isSafeRegex('.+'), true);
  assert.equal(isSafeRegex('.+', { threshold: 'low' }), false);
});

test('isSafeRegex respects a custom threshold', () => {
  assert.equal(isSafeRegex('.*.*$', { threshold: 'critical' }), true);
  assert.equal(isSafeRegex('.*.*$', { threshold: 'high' }), false);
});

test('assertSafeRegex returns the analysis for a safe pattern', () => {
  const result = assertSafeRegex('^[a-z]+$');
  assert.equal(result.risk, 'safe');
});

test('assertSafeRegex throws an UnsafeRegexError with context', () => {
  try {
    assertSafeRegex('(a+)+$');
    assert.fail('expected an unsafe regex error');
  } catch (error) {
    assert.ok(error instanceof UnsafeRegexError);
    assert.equal(error.name, 'UnsafeRegexError');
    assert.equal(error.pattern, '(a+)+$');
    assert.equal(error.risk, 'critical');
    assert.equal(error.findings[0].code, 'RS001');
    assert.equal(error.analysis.pattern, '(a+)+$');
  }
});

test('assertSafeRegex honours a higher threshold', () => {
  assert.equal(assertSafeRegex('.*.*$', { threshold: 'critical' }).risk, 'high');
  assert.throws(() => assertSafeRegex('.*.*$', { threshold: 'high' }), UnsafeRegexError);
});

test('scan returns one indexed result per pattern', () => {
  const results = scan(['^a$', '(a+)+$', /^(b*)*$/]);
  assert.equal(results.length, 3);
  assert.deepEqual(results.map((result) => result.index), [0, 1, 2]);
  assert.equal(results[0].risk, 'safe');
  assert.equal(results[1].risk, 'critical');
  assert.equal(results[2].risk, 'critical');
});

test('scan rejects non array input', () => {
  assert.throws(() => scan('(a+)+$'), TypeError);
});

test('analysis is deterministic across repeated calls', () => {
  const first = analyzeRegex('^(\\w+\\s?)*$');
  const second = analyzeRegex('^(\\w+\\s?)*$');
  assert.deepEqual(first, second);
});
