import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeRegex, RULES } from '../src/index.mjs';
import { WT_RATIONALE } from '../src/witness.mjs';

test('witnesses have the documented shape', () => {
  const [witness] = analyzeRegex('(a+)+$').witnesses;
  assert.equal(witness.code, 'RS001');
  assert.equal(witness.rule, RULES.NESTED_QUANTIFIER);
  assert.equal(witness.severity, 'critical');
  assert.equal(typeof witness.input, 'string');
  assert.equal(witness.length, witness.input.length);
  assert.equal(typeof witness.rationale, 'string');
  assert.ok(witness.rationale.length > 20);
});

test('the witness hint is the first witness input', () => {
  const result = analyzeRegex('(a+)+$');
  assert.equal(result.witnessHint, result.witnesses[0].input);
});

test('critical witnesses use the forty character base run', () => {
  const result = analyzeRegex('(a+)+$');
  assert.equal(result.witnessHint, `${'a'.repeat(40)}!`);
});

test('high witnesses use the twenty eight character base run', () => {
  const result = analyzeRegex('\\d+\\d+$');
  assert.equal(result.witnessHint, `${'0'.repeat(28)}!`);
});

test('medium and low witnesses use shorter runs', () => {
  assert.equal(analyzeRegex('(?:a?)*$').witnessHint, `${'a'.repeat(20)}!`);
  assert.equal(analyzeRegex('.+').witnessHint, `${'!'.repeat(12)}\n`);
});

test('a wildcard finding uses a newline terminator', () => {
  const [witness] = analyzeRegex('.*.*$').witnesses;
  assert.equal(witness.input.at(-1), '\n');
  assert.equal(witness.input.slice(0, -1), '!'.repeat(28));
});

test('an alternation witness repeats the shortest branch prefix', () => {
  const result = analyzeRegex('(?:ab|abc)+$');
  const witness = result.witnesses.find((entry) => entry.code === 'RS003');
  assert.equal(witness.input, `${'ab'.repeat(20)}!`);
});

test('witnesses are deterministic and bounded', () => {
  const first = analyzeRegex('^(\\w+\\s?)*$');
  const second = analyzeRegex('^(\\w+\\s?)*$');
  assert.deepEqual(first.witnesses, second.witnesses);
  for (const witness of first.witnesses) {
    assert.ok(witness.length <= 64);
    assert.equal(witness.input.length, witness.length);
  }
});

test('there is one witness per finding', () => {
  const result = analyzeRegex('(a*)*$');
  assert.equal(result.witnesses.length, result.findings.length);
  assert.deepEqual(
    result.witnesses.map((witness) => witness.code),
    result.findings.map((finding) => finding.code)
  );
});

test('every rule has a rationale', () => {
  const rules = Object.values(RULES).sort();
  assert.deepEqual(Object.keys(WT_RATIONALE).sort(), rules);
});
