import test from 'node:test';
import assert from 'node:assert/strict';

import { parseRegex, RegexParseError } from '../src/parser.mjs';

test('parseRegex returns a root node with pattern metadata', () => {
  const ast = parseRegex('ab', 'gi');
  assert.equal(ast.type, 'root');
  assert.equal(ast.pattern, 'ab');
  assert.equal(ast.flags, 'gi');
  assert.equal(ast.captureCount, 0);
  assert.deepEqual(ast.groupNames, []);
});

test('an empty pattern parses to an empty sequence', () => {
  const ast = parseRegex('');
  assert.equal(ast.body.type, 'sequence');
  assert.deepEqual(ast.body.elements, []);
});

test('a single character records its index span', () => {
  const ast = parseRegex('a');
  const char = ast.body.elements[0];
  assert.equal(char.type, 'char');
  assert.equal(char.codePoint, 0x61);
  assert.equal(char.index, 0);
  assert.equal(char.end, 1);
});

test('an astral character is one code point and two code units', () => {
  const ast = parseRegex('\u{1f600}', 'u');
  const char = ast.body.elements[0];
  assert.equal(char.type, 'char');
  assert.equal(char.codePoint, 0x1f600);
  assert.equal(char.end, 2);
});

test('alternation splits into branch sequences', () => {
  const ast = parseRegex('a|b|c');
  assert.equal(ast.body.type, 'alternation');
  assert.equal(ast.body.options.length, 3);
  assert.equal(ast.body.options[0].elements[0].codePoint, 0x61);
});

test('an empty alternation branch is preserved', () => {
  const ast = parseRegex('a|');
  assert.equal(ast.body.type, 'alternation');
  assert.equal(ast.body.options.length, 2);
  assert.deepEqual(ast.body.options[1].elements, []);
});

test('capture groups are numbered', () => {
  const ast = parseRegex('(a)(b)');
  const [first, second] = ast.body.elements;
  assert.equal(first.type, 'group');
  assert.equal(first.kind, 'capture');
  assert.equal(first.captureIndex, 1);
  assert.equal(second.captureIndex, 2);
  assert.equal(ast.captureCount, 2);
});

test('non capturing groups keep a null capture index', () => {
  const ast = parseRegex('(?:a)');
  assert.equal(ast.body.elements[0].kind, 'noncapture');
  assert.equal(ast.body.elements[0].captureIndex, null);
});

test('named groups record their name', () => {
  const ast = parseRegex('(?<word>a)');
  const group = ast.body.elements[0];
  assert.equal(group.kind, 'named');
  assert.equal(group.name, 'word');
  assert.equal(group.captureIndex, 1);
  assert.deepEqual(ast.groupNames, ['word']);
});

test('duplicate group names are rejected', () => {
  assert.throws(() => parseRegex('(?<a>x)(?<a>y)'), RegexParseError);
});

test('invalid group names are rejected', () => {
  assert.throws(() => parseRegex('(?<1a>x)'), RegexParseError);
  assert.throws(() => parseRegex('(?<>x)'), RegexParseError);
});

test('lookaround groups expose their kind', () => {
  assert.equal(parseRegex('(?=a)').body.elements[0].lookKind, 'ahead');
  assert.equal(parseRegex('(?!a)').body.elements[0].lookKind, 'ahead-negative');
  assert.equal(parseRegex('(?<=a)').body.elements[0].lookKind, 'behind');
  assert.equal(parseRegex('(?<!a)').body.elements[0].lookKind, 'behind-negative');
});

test('anchors are parsed separately from characters', () => {
  const ast = parseRegex('^a$');
  assert.equal(ast.body.elements[0].type, 'anchor');
  assert.equal(ast.body.elements[0].kind, 'start');
  assert.equal(ast.body.elements[2].kind, 'end');
});

test('word boundary anchors are recognised outside classes', () => {
  assert.equal(parseRegex('\\b').body.elements[0].kind, 'word-boundary');
  assert.equal(parseRegex('\\B').body.elements[0].kind, 'non-word-boundary');
});

test('backspace is a character inside a class', () => {
  const ast = parseRegex('[\\b]');
  const item = ast.body.elements[0];
  assert.equal(item.type, 'class');
  assert.deepEqual(item.ranges, [[0x08, 0x08]]);
});

test('dot carries the line terminator aware set', () => {
  const dot = parseRegex('.').body.elements[0];
  assert.equal(dot.type, 'dot');
  assert.equal(dot.set.contains(0x0a), false);
  assert.equal(dot.set.contains(0x41), true);
});

test('character classes expose ranges', () => {
  const item = parseRegex('[a-cx]').body.elements[0];
  assert.equal(item.type, 'class');
  assert.deepEqual(item.ranges, [[0x61, 0x63], [0x78, 0x78]]);
  assert.equal(item.raw, '[a-cx]');
});

test('negated classes expose the effective set', () => {
  const item = parseRegex('[^a]').body.elements[0];
  assert.equal(item.negated, true);
  assert.equal(item.set.contains(0x61), false);
  assert.equal(item.set.contains(0x62), true);
});

test('class escapes contribute their whole category', () => {
  const item = parseRegex('[\\d\\s]').body.elements[0];
  assert.equal(item.set.contains(0x30), true);
  assert.equal(item.set.contains(0x20), true);
  assert.equal(item.set.contains(0x41), false);
});

test('a hyphen beside a class escape is a literal under Annex B', () => {
  const left = parseRegex('[a-\\d]').body.elements[0];
  assert.equal(left.set.contains(0x2d), true);
  assert.equal(left.set.contains(0x61), true);
  assert.equal(left.set.contains(0x35), true);
  const right = parseRegex('[\\d-a]').body.elements[0];
  assert.equal(right.set.contains(0x2d), true);
  assert.equal(right.set.contains(0x61), true);
});

test('range boundaries are validated', () => {
  assert.throws(() => parseRegex('[z-a]'), RegexParseError);
  assert.throws(() => parseRegex('[a-z'), RegexParseError);
});

test('a trailing hyphen is a literal', () => {
  const item = parseRegex('[a-]').body.elements[0];
  assert.equal(item.set.contains(0x2d), true);
});

test('quantifiers record bounds and greediness', () => {
  const star = parseRegex('a*').body.elements[0];
  assert.equal(star.type, 'quantifier');
  assert.equal(star.min, 0);
  assert.equal(star.max, Infinity);
  assert.equal(star.greedy, true);
  const lazy = parseRegex('a+?').body.elements[0];
  assert.equal(lazy.min, 1);
  assert.equal(lazy.greedy, false);
});

test('braced quantifiers parse all three forms', () => {
  assert.deepEqual(
    [parseRegex('a{2}').body.elements[0].min, parseRegex('a{2}').body.elements[0].max],
    [2, 2]
  );
  assert.deepEqual(
    [parseRegex('a{2,5}').body.elements[0].min, parseRegex('a{2,5}').body.elements[0].max],
    [2, 5]
  );
  assert.deepEqual(
    [parseRegex('a{2,}').body.elements[0].min, parseRegex('a{2,}').body.elements[0].max],
    [2, Infinity]
  );
});

test('out of order quantifier bounds are rejected', () => {
  assert.throws(() => parseRegex('a{5,2}'), RegexParseError);
});

test('an incomplete brace is a literal outside unicode mode', () => {
  const ast = parseRegex('a{2');
  assert.equal(ast.body.elements.length, 3);
  assert.equal(ast.body.elements[1].codePoint, 0x7b);
  assert.equal(ast.body.elements[2].codePoint, 0x32);
});

test('an incomplete brace is an error in unicode mode', () => {
  assert.throws(() => parseRegex('a{2', 'u'), RegexParseError);
});

test('a quantified group carries the group as its body', () => {
  const quantifier = parseRegex('(ab)+').body.elements[0];
  assert.equal(quantifier.type, 'quantifier');
  assert.equal(quantifier.body.type, 'group');
});

test('numeric backreferences resolve to their capture', () => {
  const ast = parseRegex('(a)\\1');
  const backref = ast.body.elements[1];
  assert.equal(backref.type, 'backref');
  assert.equal(backref.ref, 1);
});

test('forward backreferences still resolve', () => {
  const ast = parseRegex('\\1(a)');
  assert.equal(ast.body.elements[0].type, 'backref');
  assert.equal(ast.body.elements[0].ref, 1);
});

test('named backreferences keep their name', () => {
  const ast = parseRegex('(?<x>a)\\k<x>');
  const backref = ast.body.elements[1];
  assert.equal(backref.type, 'backref');
  assert.equal(backref.ref, 'x');
});

test('decimal escapes above the capture count become legacy escapes', () => {
  const ast = parseRegex('\\12');
  const node = ast.body.elements[0];
  assert.equal(node.type, 'char');
  assert.equal(node.codePoint, 10);
  assert.equal(node.legacyEscape, true);
});

test('a lone \\8 is a literal digit without captures', () => {
  const node = parseRegex('\\8').body.elements[0];
  assert.equal(node.type, 'char');
  assert.equal(node.codePoint, 0x38);
});

test('escape sequences decode to code points', () => {
  assert.equal(parseRegex('\\n').body.elements[0].codePoint, 0x0a);
  assert.equal(parseRegex('\\t').body.elements[0].codePoint, 0x09);
  assert.equal(parseRegex('\\x41').body.elements[0].codePoint, 0x41);
  assert.equal(parseRegex('\\u0041').body.elements[0].codePoint, 0x41);
  assert.equal(parseRegex('\\u{41}', 'u').body.elements[0].codePoint, 0x41);
  assert.equal(parseRegex('\\cA').body.elements[0].codePoint, 0x01);
  assert.equal(parseRegex('\\0').body.elements[0].codePoint, 0x00);
});

test('unicode property escapes are sets in unicode mode', () => {
  const node = parseRegex('\\p{L}', 'u').body.elements[0];
  assert.equal(node.type, 'class');
  assert.equal(node.set.contains(0x41), true);
});

test('unicode property escapes are literals outside unicode mode', () => {
  const ast = parseRegex('\\p{L}');
  assert.equal(ast.body.elements.length, 4);
  assert.equal(ast.body.elements[0].codePoint, 0x70);
});

test('flags are validated', () => {
  assert.throws(() => parseRegex('a', 'z'), RegexParseError);
  assert.throws(() => parseRegex('a', 'gg'), RegexParseError);
  assert.throws(() => parseRegex('a', 'uv'), RegexParseError);
  assert.equal(parseRegex('a', 'dgimsy').flags, 'dgimsy');
});

test('structural syntax errors are reported with an index', () => {
  assert.throws(() => parseRegex('('), RegexParseError);
  assert.throws(() => parseRegex(')'), RegexParseError);
  assert.throws(() => parseRegex('['), RegexParseError);
  assert.throws(() => parseRegex('*'), RegexParseError);
  assert.throws(() => parseRegex('^*'), RegexParseError);
});

test('parse errors expose pattern and index fields', () => {
  try {
    parseRegex('a{5,2}');
    assert.fail('expected a parse error');
  } catch (error) {
    assert.equal(error.name, 'RegexParseError');
    assert.equal(error.pattern, 'a{5,2}');
    assert.equal(typeof error.index, 'number');
  }
});

test('parseRegex rejects non string patterns', () => {
  assert.throws(() => parseRegex(null), TypeError);
  assert.throws(() => parseRegex(42), TypeError);
});
