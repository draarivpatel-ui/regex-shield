// regex-shield: deterministic attack string hints.
//
// A witness hint is not a proof of exploitability. It is a short, reproducible
// input shape that concentrates the ambiguity a finding describes, so a
// maintainer can confirm the issue with a bounded timing test before fixing the
// pattern. The generator never executes the regex itself.

const WT_REPEAT_BASE = { critical: 40, high: 28, medium: 20, low: 12 };
const WT_MAX_LENGTH = 64;

const WT_RATIONALE = {
  'nested-quantifier':
    'A long run of the repeated character with no trailing match forces the engine to split the run ' +
    'between the inner and outer loops at every boundary.',
  'overlapping-adjacent-quantifiers':
    'One run of a character both quantifiers accept, followed by a character neither accepts, makes ' +
    'every split point fail only after rescanning the suffix.',
  'overlapping-alternation-quantifier':
    'Repeating the shortest overlapping branch builds a string that every repetition can read in more ' +
    'than one way, then a non matching terminator forces full backtracking.',
  'backreference-in-quantifier':
    'Repeating a short unit feeds the backreference many candidate lengths inside each loop iteration.',
  'lookaround-in-quantifier':
    'Repeating a unit that the lookaround rescans at every position multiplies the two scan costs.',
  'nullable-quantifier-body':
    'A run that the nullable body cannot consume forces an empty iteration check at every position.',
  'multiple-unbounded-wildcards':
    'A long run with no delimiter makes each unbounded scan retry the entire tail at every split point.',
  'broad-unbounded-quantifier':
    'A long run over the broad set shows the per-position cost of the unanchored scan.'
};

function wtCountFor(severity, unitLength) {
  const base = WT_REPEAT_BASE[severity] || 16;
  if (unitLength <= 1) return base;
  const reps = Math.max(3, Math.floor(base / unitLength));
  return reps;
}

export function generateWitnesses(ast, findings) {
  const witnesses = [];
  for (const finding of findings) {
    const detail = finding.detail || {};
    const unitRaw = typeof detail.repeatUnit === 'string' && detail.repeatUnit.length > 0
      ? detail.repeatUnit
      : (typeof detail.sampleChar === 'string' && detail.sampleChar.length > 0 ? detail.sampleChar : 'a');
    const terminator = typeof detail.terminator === 'string' && detail.terminator.length > 0
      ? detail.terminator
      : '!';
    const count = wtCountFor(finding.severity, unitRaw.length);
    let input = unitRaw.repeat(count) + terminator;
    if (input.length > WT_MAX_LENGTH) input = input.slice(0, WT_MAX_LENGTH - 1) + terminator;
    witnesses.push({
      code: finding.code,
      rule: finding.rule,
      severity: finding.severity,
      input,
      length: input.length,
      rationale: WT_RATIONALE[finding.rule] || 'Repeated input followed by a non matching terminator.'
    });
  }
  return witnesses;
}

export { WT_RATIONALE };
