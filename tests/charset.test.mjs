import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CharSet,
  csNormalize,
  csComplement,
  csUnion,
  csIntersect,
  csIsSubset,
  csSize,
  csIntersects,
  csContainsCodePoint,
  csSampleCodePoint,
  csRenderCodePoint,
  csDescribe,
  CS_MAX_CODE_POINT
} from '../src/charset.mjs';

test('csNormalize sorts, merges and clips ranges', () => {
  assert.deepEqual(csNormalize([[5, 9], [1, 3], [4, 4]]), [[1, 9]]);
  assert.deepEqual(csNormalize([[10, 12], [1, 2]]), [[1, 2], [10, 12]]);
  assert.deepEqual(csNormalize([[-5, 2]]), [[0, 2]]);
  assert.deepEqual(csNormalize([[5, 1]]), [[1, 5]]);
  assert.deepEqual(csNormalize([[0, CS_MAX_CODE_POINT + 50]]), [[0, CS_MAX_CODE_POINT]]);
});

test('csNormalize returns an empty array for empty or malformed input', () => {
  assert.deepEqual(csNormalize([]), []);
  assert.deepEqual(csNormalize(null), []);
  assert.deepEqual(csNormalize('nope'), []);
});

test('csComplement covers the gaps and both edges', () => {
  assert.deepEqual(csComplement([[0x30, 0x39]]), [[0, 0x2f], [0x3a, CS_MAX_CODE_POINT]]);
  assert.deepEqual(csComplement([]), [[0, CS_MAX_CODE_POINT]]);
  assert.deepEqual(csComplement([[0, CS_MAX_CODE_POINT]]), []);
  assert.deepEqual(csComplement([[1, 2], [4, 5]]), [[0, 0], [3, 3], [6, CS_MAX_CODE_POINT]]);
});

test('double complement is the normalized original', () => {
  const original = [[1, 3], [7, 9]];
  assert.deepEqual(csComplement(csComplement(original)), csNormalize(original));
});

test('csUnion merges multiple range lists', () => {
  assert.deepEqual(csUnion([[1, 2]], [[2, 4]], [[10, 11]]), [[1, 4], [10, 11]]);
  assert.deepEqual(csUnion([], []), []);
});

test('csIntersect finds shared spans', () => {
  assert.deepEqual(csIntersect([[1, 10]], [[5, 20]]), [[5, 10]]);
  assert.deepEqual(csIntersect([[1, 2]], [[3, 4]]), []);
  assert.deepEqual(csIntersect([[1, 4], [8, 10]], [[3, 9]]), [[3, 4], [8, 9]]);
});

test('csIsSubset is true only when every code point is contained', () => {
  assert.equal(csIsSubset([[3, 4]], [[1, 5]]), true);
  assert.equal(csIsSubset([[1, 5]], [[3, 4]]), false);
  assert.equal(csIsSubset([], [[1, 2]]), true);
  assert.equal(csIsSubset([[1, 2]], []), false);
});

test('csSize counts code points, not ranges', () => {
  assert.equal(csSize([[1, 3]]), 3);
  assert.equal(csSize([[1, 3], [10, 10]]), 4);
  assert.equal(csSize([]), 0);
});

test('csIntersects and csContainsCodePoint agree with the algebra', () => {
  assert.equal(csIntersects([[1, 3]], [[3, 5]]), true);
  assert.equal(csIntersects([[1, 3]], [[4, 5]]), false);
  assert.equal(csContainsCodePoint([[0x41, 0x5a]], 0x4d), true);
  assert.equal(csContainsCodePoint([[0x41, 0x5a]], 0x61), false);
});

test('csSampleCodePoint prefers printable characters', () => {
  assert.equal(csSampleCodePoint([[0, 0x10]]), 0);
  assert.equal(csSampleCodePoint([[0, 0x10], [0x41, 0x5a]]), 0x41);
  assert.equal(csSampleCodePoint([[0x30, 0x39]]), 0x30);
  assert.equal(csSampleCodePoint([[0x0a, 0x0b]]), 0x0a);
});

test('csSampleCodePoint honours exclusions', () => {
  assert.equal(csSampleCodePoint([[0x61, 0x63]], ['a']), 0x62);
  assert.equal(csSampleCodePoint([[0x61, 0x61]], ['a']), null);
});

test('csRenderCodePoint renders printable and escaped forms', () => {
  assert.equal(csRenderCodePoint(0x41), 'A');
  assert.equal(csRenderCodePoint(0x0a), '\\x0a');
  assert.equal(csRenderCodePoint(0x2603), '\\u2603');
  assert.equal(csRenderCodePoint(null), '');
});

test('csDescribe summarizes simple and huge sets', () => {
  assert.equal(csDescribe([[0x61, 0x63]]), 'a-c');
  assert.equal(csDescribe([[0, CS_MAX_CODE_POINT]]), 'any character');
  assert.equal(csDescribe([]), 'nothing');
  assert.match(csDescribe([[0x100, 0x200]]), /^U\+100-U\+200$/);
});

test('csDescribe truncates long range lists', () => {
  const ranges = [];
  for (let index = 0; index < 10; index += 1) ranges.push([index * 10, index * 10 + 1]);
  assert.match(csDescribe(ranges, 3), /and 7 more ranges$/);
});

test('CharSet.literal wraps exactly one code point', () => {
  const set = CharSet.literal(0x41);
  assert.equal(set.size, 1);
  assert.equal(set.contains(0x41), true);
  assert.equal(set.contains(0x42), false);
});

test('CharSet.category models digit, word and space classes', () => {
  assert.equal(CharSet.category('d', false).size, 10);
  assert.equal(CharSet.category('w', false).contains(0x5f), true);
  assert.equal(CharSet.category('s', false).contains(0x20), true);
  assert.equal(CharSet.category('d', true).contains(0x41), true);
  assert.equal(CharSet.category('d', true).contains(0x30), false);
});

test('CharSet.dot excludes line terminators', () => {
  const dot = CharSet.dot();
  assert.equal(dot.contains(0x0a), false);
  assert.equal(dot.contains(0x0d), false);
  assert.equal(dot.contains(0x41), true);
});

test('CharSet.universe contains every code point', () => {
  const universe = CharSet.universe();
  assert.equal(universe.size, CS_MAX_CODE_POINT + 1);
  assert.equal(universe.contains(0), true);
  assert.equal(universe.contains(CS_MAX_CODE_POINT), true);
});

test('CharSet algebra methods return new sets', () => {
  const letters = new CharSet([[0x61, 0x7a]]);
  const digits = new CharSet([[0x30, 0x39]]);
  const both = letters.union(digits);
  assert.equal(letters.size, 26);
  assert.equal(both.size, 36);
  assert.equal(letters.intersects(digits), false);
  assert.equal(both.intersect(letters).size, 26);
  assert.equal(letters.subsetOf(both), true);
  assert.equal(both.subsetOf(letters), false);
});

test('CharSet emptiness and sampling', () => {
  const empty = new CharSet([]);
  assert.equal(empty.isEmpty, true);
  assert.equal(empty.sampleCodePoint(), null);
  assert.equal(new CharSet([[0x61, 0x62]]).sampleCodePoint(), 0x61);
  assert.equal(new CharSet([[0x61, 0x62]]).sampleCodePoint(['a', 'b']), null);
});

test('CharSet.describe uses its own ranges', () => {
  assert.equal(new CharSet([[0x61, 0x63]]).describe(), 'a-c');
  assert.equal(new CharSet([]).describe(), 'nothing');
});
