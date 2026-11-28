// regex-shield: static ReDoS analysis over the parsed regex AST.
//
// Every rule reasons about the languages the subexpressions match, using code
// point sets computed by src/charset.mjs. The output is deterministic: the same
// pattern and flags always produce the same findings, in the same order, with
// the same scores and witness hints.

import { CharSet, csComplement, csSampleCodePoint } from './charset.mjs';
import { parseRegex, RegexParseError } from './parser.mjs';
import { generateWitnesses } from './witness.mjs';

export const CWE_ID = 'CWE-1333';
export const CWE_URL = 'https://cwe.mitre.org/data/definitions/1333.html';

export const RULES = Object.freeze({
  NESTED_QUANTIFIER: 'nested-quantifier',
  OVERLAPPING_ADJACENT: 'overlapping-adjacent-quantifiers',
  OVERLAPPING_ALTERNATION: 'overlapping-alternation-quantifier',
  BACKREFERENCE_IN_QUANTIFIER: 'backreference-in-quantifier',
  LOOKAROUND_IN_QUANTIFIER: 'lookaround-in-quantifier',
  NULLABLE_QUANTIFIER_BODY: 'nullable-quantifier-body',
  MULTIPLE_WILDCARDS: 'multiple-unbounded-wildcards',
  BROAD_UNBOUNDED: 'broad-unbounded-quantifier'
});

const AN_SEVERITY_WEIGHT = { critical: 70, high: 40, medium: 12, low: 4 };
const AN_RISK_ORDER = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
const AN_RULE_META = {
  [RULES.NESTED_QUANTIFIER]: {
    code: 'RS001',
    title: 'Nested quantifiers over an overlapping body'
  },
  [RULES.OVERLAPPING_ADJACENT]: {
    code: 'RS002',
    title: 'Adjacent quantified atoms match overlapping characters'
  },
  [RULES.OVERLAPPING_ALTERNATION]: {
    code: 'RS003',
    title: 'Quantified alternation with overlapping branches'
  },
  [RULES.BACKREFERENCE_IN_QUANTIFIER]: {
    code: 'RS004',
    title: 'Backreference inside a quantified loop'
  },
  [RULES.LOOKAROUND_IN_QUANTIFIER]: {
    code: 'RS005',
    title: 'Lookaround with unbounded matching inside a quantified loop'
  },
  [RULES.NULLABLE_QUANTIFIER_BODY]: {
    code: 'RS006',
    title: 'Quantifier body can match the empty string'
  },
  [RULES.MULTIPLE_WILDCARDS]: {
    code: 'RS007',
    title: 'Chain of unbounded wildcards'
  },
  [RULES.BROAD_UNBOUNDED]: {
    code: 'RS008',
    title: 'Unanchored unbounded quantifier over a broad character class'
  }
};

export class UnsafeRegexError extends Error {
  constructor(analysis) {
    const worst = analysis.findings[0];
    super(
      `Unsafe regular expression /${analysis.pattern}/${analysis.flags} flagged as ${analysis.risk}` +
        (worst ? ` (${worst.code} ${worst.title})` : '')
    );
    this.name = 'UnsafeRegexError';
    this.pattern = analysis.pattern;
    this.flags = analysis.flags;
    this.risk = analysis.risk;
    this.score = analysis.score;
    this.analysis = analysis;
    this.findings = analysis.findings;
  }
}

// ---------------------------------------------------------------------------
// AST helpers
// ---------------------------------------------------------------------------

function anUnwrap(node) {
  let current = node;
  for (let guard = 0; guard < 64; guard += 1) {
    if (!current) return current;
    if (current.type === 'group' && current.kind !== 'lookaround') {
      current = current.body;
      continue;
    }
    if (current.type === 'sequence') {
      const meaningful = current.elements.filter((element) => element.type !== 'anchor');
      if (meaningful.length === 1) {
        current = meaningful[0];
        continue;
      }
    }
    return current;
  }
  return current;
}

function anIsZeroWidth(node) {
  return node.type === 'anchor' || (node.type === 'group' && node.kind === 'lookaround');
}

// A literal carries every code point the /i flag lets it match.
function anCharSet(node) {
  if (node.codePoints && node.codePoints.length > 0) return CharSet.fromCodePoints(node.codePoints);
  return CharSet.literal(node.codePoint);
}

// The set a single character sequence element consumes, or null when the
// element is not a plain one character atom. Used to see through separators
// such as ".*a.*" where both scans can also consume the "a".
function anBridgeSet(node) {
  const inner = anUnwrap(node);
  if (!inner) return null;
  if (inner.type === 'char') return anCharSet(inner);
  if (inner.type === 'class' || inner.type === 'dot') return inner.set;
  return null;
}

function anStartInfo(node) {
  if (!node) return { nullable: true, set: null };
  switch (node.type) {
    case 'char':
      return { nullable: false, set: anCharSet(node) };
    case 'class':
    case 'dot':
      return { nullable: false, set: node.set };
    case 'anchor':
      return { nullable: true, set: null };
    case 'backref':
      return { nullable: true, set: null, unknown: true };
    case 'quantifier': {
      const inner = anStartInfo(node.body);
      return { nullable: node.min === 0 || inner.nullable, set: inner.set };
    }
    case 'group': {
      if (node.kind === 'lookaround') return { nullable: true, set: null };
      return anStartInfo(node.body);
    }
    case 'sequence': {
      let set = null;
      let nullable = true;
      for (const element of node.elements) {
        const info = anStartInfo(element);
        if (info.set) set = set ? set.union(info.set) : info.set;
        if (!info.nullable) {
          nullable = false;
          break;
        }
      }
      return { nullable, set };
    }
    case 'alternation': {
      let set = null;
      let nullable = false;
      for (const option of node.options) {
        const info = anStartInfo(option);
        if (info.set) set = set ? set.union(info.set) : info.set;
        if (info.nullable) nullable = true;
      }
      return { nullable, set };
    }
    default:
      return { nullable: true, set: null };
  }
}

function anLastInfo(node) {
  if (!node) return { nullable: true, set: null };
  switch (node.type) {
    case 'char':
      return { nullable: false, set: anCharSet(node) };
    case 'class':
    case 'dot':
      return { nullable: false, set: node.set };
    case 'anchor':
      return { nullable: true, set: null };
    case 'backref':
      return { nullable: true, set: null, unknown: true };
    case 'quantifier': {
      const inner = anLastInfo(node.body);
      return { nullable: node.min === 0 || inner.nullable, set: inner.set };
    }
    case 'group': {
      if (node.kind === 'lookaround') return { nullable: true, set: null };
      return anLastInfo(node.body);
    }
    case 'sequence': {
      let set = null;
      let nullable = true;
      for (let index = node.elements.length - 1; index >= 0; index -= 1) {
        const info = anLastInfo(node.elements[index]);
        if (info.set) set = set ? set.union(info.set) : info.set;
        if (!info.nullable) {
          nullable = false;
          break;
        }
      }
      return { nullable, set };
    }
    case 'alternation': {
      let set = null;
      let nullable = false;
      for (const option of node.options) {
        const info = anLastInfo(option);
        if (info.set) set = set ? set.union(info.set) : info.set;
        if (info.nullable) nullable = true;
      }
      return { nullable, set };
    }
    default:
      return { nullable: true, set: null };
  }
}

function anConsumedSet(node) {
  if (!node) return null;
  switch (node.type) {
    case 'char':
      return anCharSet(node);
    case 'class':
    case 'dot':
      return node.set;
    case 'backref':
    case 'anchor':
      return null;
    case 'quantifier':
      return anConsumedSet(node.body);
    case 'group':
      if (node.kind === 'lookaround') return null;
      return anConsumedSet(node.body);
    case 'sequence': {
      let set = null;
      for (const element of node.elements) {
        const inner = anConsumedSet(element);
        if (inner) set = set ? set.union(inner) : inner;
      }
      return set;
    }
    case 'alternation': {
      let set = null;
      for (const option of node.options) {
        const inner = anConsumedSet(option);
        if (inner) set = set ? set.union(inner) : inner;
      }
      return set;
    }
    default:
      return null;
  }
}

function anStarHeight(node) {  if (!node) return 0;
  switch (node.type) {
    case 'quantifier': {
      const inner = anStarHeight(node.body);
      return node.max === Infinity ? inner + 1 : inner;
    }
    case 'group':
      return anStarHeight(node.body);
    case 'sequence': {
      let max = 0;
      for (const element of node.elements) max = Math.max(max, anStarHeight(element));
      return max;
    }
    case 'alternation': {
      let max = 0;
      for (const option of node.options) max = Math.max(max, anStarHeight(option));
      return max;
    }
    default:
      return 0;
  }
}

// Exact length in code units when the subexpression matches one fixed length,
// otherwise null. A repeated fixed length unit has a deterministic stride, so
// patterns such as the base64 "(?:[A-Za-z0-9+/]{4})*" cannot backtrack
// exponentially even though the syntax nests two quantifiers.
function anFixedLength(node) {
  if (!node) return 0;
  switch (node.type) {
    case 'char':
      return node.codePoint > 0xffff ? 2 : 1;
    case 'class':
    case 'dot':
      return 1;
    case 'anchor':
      return 0;
    case 'group':
      return node.kind === 'lookaround' ? 0 : anFixedLength(node.body);
    case 'sequence': {
      let total = 0;
      for (const element of node.elements) {
        const length = anFixedLength(element);
        if (length === null) return null;
        total += length;
      }
      return total;
    }
    case 'alternation': {
      let common = null;
      for (const option of node.options) {
        const length = anFixedLength(option);
        if (length === null) return null;
        if (common === null) common = length;
        else if (common !== length) return null;
      }
      return common === null ? 0 : common;
    }
    case 'quantifier': {
      if (node.min !== node.max) return null;
      const inner = anFixedLength(node.body);
      if (inner === null) return null;
      return inner * node.min;
    }
    default:
      return null;
  }
}

function anQuantifierDepth(node, depth) {
  if (!node) return depth;
  const next = node.type === 'quantifier' && node.max >= 2 ? depth + 1 : depth;
  switch (node.type) {
    case 'quantifier':
      return Math.max(next, anQuantifierDepth(node.body, next));
    case 'group':
      return node.kind === 'lookaround' ? depth : anQuantifierDepth(node.body, next);
    case 'sequence': {
      let max = next;
      for (const element of node.elements) max = Math.max(max, anQuantifierDepth(element, next));
      return max;
    }
    case 'alternation': {
      let max = next;
      for (const option of node.options) max = Math.max(max, anQuantifierDepth(option, next));
      return max;
    }
    default:
      return next;
  }
}

function anCount(node, predicate) {
  let total = 0;
  const visit = (current) => {
    if (!current) return;
    if (predicate(current)) total += 1;
    if (current.type === 'group') visit(current.body);
    else if (current.type === 'quantifier') visit(current.body);
    else if (current.type === 'sequence') current.elements.forEach(visit);
    else if (current.type === 'alternation') current.options.forEach(visit);
  };
  visit(node);
  return total;
}

function anContainsUnbounded(node) {
  if (!node) return false;
  let found = false;
  const visit = (current) => {
    if (!current || found) return;
    if (current.type === 'quantifier' && current.max === Infinity) {
      found = true;
      return;
    }
    if (current.type === 'group' || current.type === 'quantifier') visit(current.body);
    else if (current.type === 'sequence') current.elements.forEach(visit);
    else if (current.type === 'alternation') current.options.forEach(visit);
  };
  visit(node);
  return found;
}

function anSoleQuantifier(node) {
  if (!node) return null;
  if (node.type === 'quantifier') return node;
  if (node.type === 'group' && node.kind !== 'lookaround') return anSoleQuantifier(node.body);
  if (node.type === 'sequence') {
    const meaningful = node.elements.filter((element) => element.type !== 'anchor');
    if (meaningful.length === 1) return anSoleQuantifier(meaningful[0]);
  }
  return null;
}

// Elements of a repeated body that must consume something. A body whose only
// required part is the inner repetition behaves exactly like a pure nested
// quantifier even when optional elements such as "\s?" sit beside it.
function anBodyElements(node) {
  let current = node;
  for (let guard = 0; guard < 64; guard += 1) {
    if (!current) return [];
    if (current.type === 'group' && current.kind !== 'lookaround') {
      current = current.body;
      continue;
    }
    if (current.type === 'sequence') return current.elements;
    return [current];
  }
  return [current];
}

function anIsEffectivelyPure(body, inner) {
  const elements = anBodyElements(body);
  const required = elements.filter((element) => !anStartInfo(element).nullable);
  const consuming = elements.filter((element) => !anIsZeroWidth(element));
  if (required.length === 1 && anSoleQuantifier(required[0]) === inner) return true;
  // A body such as (a*)* has no required element at all. It is still a pure
  // repetition when the only consuming element is the inner quantifier.
  if (required.length === 0 && consuming.length === 1 && anSoleQuantifier(consuming[0]) === inner) return true;
  return false;
}

// The quantified atom a sequence element stands for, looking through grouping
// wrappers. Used to compare neighbours such as "(a+)(a+)".
function anQuantifiedForm(node) {
  const inner = anUnwrap(node);
  if (inner && inner.type === 'quantifier' && inner.max >= 2) return inner;
  return null;
}

// Quantifiers that can begin at the current position of an element, looking
// through groups, alternations and nullable prefixes. A following element does
// not have to start with a quantifier itself: in the ANSI escape shape
// "[...]* (?:(?:letters*(?:;chars*)*)? BEL ...)" the semicolon loop can start
// where the preceding class loop ends, and the two compete for the same run.
function anFirstQuantifiers(node, out) {
  if (!node) return out;
  switch (node.type) {
    case 'quantifier':
      if (node.max >= 2) out.push(node);
      if (node.min === 0) anFirstQuantifiers(node.body, out);
      return out;
    case 'group':
      if (node.kind === 'lookaround') return out;
      return anFirstQuantifiers(node.body, out);
    case 'sequence':
      for (const element of node.elements) {
        if (element.type === 'anchor') continue;
        anFirstQuantifiers(element, out);
        if (!anStartInfo(element).nullable) break;
      }
      return out;
    case 'alternation':
      for (const option of node.options) anFirstQuantifiers(option, out);
      return out;
    default:
      return out;
  }
}

function anDescribeBounds(quantifier) {
  if (quantifier.max === Infinity) {
    if (quantifier.min === 0) return '*';
    if (quantifier.min === 1) return '+';
    return `{${quantifier.min},}`;
  }
  if (quantifier.min === quantifier.max) return `{${quantifier.min}}`;
  return `{${quantifier.min},${quantifier.max}}`;
}

function anLiteralPrefix(node) {
  if (!node) return '';
  if (node.type === 'char') return String.fromCodePoint(node.codePoint);
  if (node.type === 'quantifier') {
    if (node.min < 1) return '';
    return anLiteralPrefix(node.body).repeat(Math.min(node.min, 8));
  }
  if (node.type === 'group') {
    if (node.kind === 'lookaround') return '';
    return anLiteralPrefix(node.body);
  }
  if (node.type === 'sequence') {
    let text = '';
    for (const element of node.elements) {
      const part = anLiteralPrefix(element);
      if (part.length === 0) break;
      text += part;
      if (text.length >= 16) break;
    }
    return text.slice(0, 16);
  }
  if (node.type === 'alternation') {
    return node.options.map(anLiteralPrefix).sort((a, b) => a.length - b.length)[0] || '';
  }
  return '';
}

function anPickTerminator(sets) {
  // The witness only forces backtracking when the final character cannot be
  // consumed by any of the competing sets. Pick the first printable code point
  // outside their union, then fall back to the lowest outside code point. For a
  // dot based finding that is a newline, and for a negated class it is the one
  // excluded character.
  let union = null;
  for (const set of sets) {
    if (!set) continue;
    union = union ? union.union(set) : set;
  }
  if (!union) return '!';
  const codePoint = csSampleCodePoint(csComplement(union.ranges));
  if (codePoint === null) return '\u0000';
  return String.fromCodePoint(codePoint);
}

function anRanges(set) {
  return set ? set.ranges : [];
}

// Set difference a minus b, expressed through the range algebra.
function anDifference(a, b) {
  const out = [];
  for (const [lo, hi] of a.ranges) {
    let cursor = lo;
    for (const [otherLo, otherHi] of b.ranges) {
      if (otherHi < cursor) continue;
      if (otherLo > hi) break;
      if (otherLo > cursor) out.push([cursor, Math.min(hi, otherLo - 1)]);
      cursor = Math.max(cursor, otherHi + 1);
      if (cursor > hi) break;
    }
    if (cursor <= hi) out.push([cursor, hi]);
  }
  return new CharSet(out, { source: 'difference' });
}

// Every adjacent pair of quantified atoms in a sequence whose character sets
// overlap. This is the single source of truth for the adjacent overlap rule and
// for the "ambiguous body" test used by the nested quantifier rule.
function anOverlapPairs(sequence) {
  const items = sequence.elements.filter((element) => !anIsZeroWidth(element));
  const pairs = [];
  for (let index = 0; index + 1 < items.length; index += 1) {
    const leftForm = anQuantifiedForm(items[index]);
    if (!leftForm || leftForm.max !== Infinity) continue;
    // The junction is what matters: the characters the left atom can end on and
    // the characters the right atom can start with. Comparing whole consumed
    // sets would flag patterns such as "([\w-]+\.)+[a-z]{2,}", where the dot
    // makes the boundary unambiguous.
    const leftSet = anLastInfo(leftForm.body).set;
    if (!leftSet) continue;
    // A one character separator does not make the boundary unambiguous when
    // both neighbouring scans can consume that same character. ".*a.*" and
    // "[^@\s]+@[^@\s]+\.[^@\s]+" backtrack quadratically exactly because the
    // separator can slide between the two runs.
    for (const offset of [1, 2]) {
      const rightElement = items[index + offset];
      if (!rightElement) break;
      let bridgeSet = null;
      if (offset === 2) {
        bridgeSet = anBridgeSet(items[index + 1]);
        if (!bridgeSet) continue;
      }
      const candidates = anFirstQuantifiers(rightElement, []);
      const seen = new Set();
      for (const rightForm of candidates) {
        if (rightForm.max !== Infinity) continue;
        if (seen.has(rightForm.index)) continue;
        seen.add(rightForm.index);
        const rightSet = anStartInfo(rightForm.body).set;
        if (!rightSet || !leftSet.intersects(rightSet)) continue;
        const shared = leftSet.intersect(rightSet);
        if (shared.isEmpty) continue;
        // The separator must be able to be the same character that both scans
        // accept; otherwise one of them cannot slide across it.
        if (bridgeSet && !bridgeSet.intersects(shared)) continue;
        pairs.push({
          leftElement: items[index],
          rightElement,
          left: leftForm,
          right: rightForm,
          leftSet,
          rightSet,
          shared,
          bridge: bridgeSet
        });
      }
    }
  }
  return pairs;
}

// A repeated body can also be ambiguous when one unbounded atom hands the same
// characters to the next atom, even if that next atom consumes a single
// character. "(a+a)+" and the classic "(([a-z])+.)+" both split a failing run
// between the inner loop and the following atom inside every outer iteration.
function anHasPrefixOverlap(sequence) {
  const items = sequence.elements.filter((element) => !anIsZeroWidth(element));
  for (let index = 0; index + 1 < items.length; index += 1) {
    const form = anQuantifiedForm(items[index]);
    if (!form || form.max !== Infinity) continue;
    const leftSet = anLastInfo(form.body).set;
    const rightSet = anStartInfo(items[index + 1]).set;
    if (leftSet && rightSet && leftSet.intersects(rightSet)) return true;
  }
  return false;
}

function anContainsAdjacentOverlap(node) {
  let found = false;
  const visit = (current) => {
    if (!current || found) return;
    if (current.type === 'sequence') {
      if (anOverlapPairs(current).length > 0 || anHasPrefixOverlap(current)) {
        found = true;
        return;
      }
      current.elements.forEach(visit);
    } else if (current.type === 'group' || current.type === 'quantifier') {
      visit(current.body);
    } else if (current.type === 'alternation') {
      current.options.forEach(visit);
    }
  };
  visit(node);
  return found;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

function anCollectInnerQuantifiers(node, out) {
  if (!node) return out;
  switch (node.type) {
    case 'quantifier':
      out.push(node);
      // Stop at an unbounded inner quantifier: the outer/inner pair is reported
      // here, deeper pairs are reported when that quantifier is visited as an
      // outer quantifier itself.
      if (node.max !== Infinity) anCollectInnerQuantifiers(node.body, out);
      return out;
    case 'group':
      if (node.kind === 'lookaround') return out;
      return anCollectInnerQuantifiers(node.body, out);
    case 'sequence':
      for (const element of node.elements) anCollectInnerQuantifiers(element, out);
      return out;
    case 'alternation':
      for (const option of node.options) anCollectInnerQuantifiers(option, out);
      return out;
    default:
      return out;
  }
}

function anCheckNestedQuantifier(quantifier, add) {
  if (quantifier.max < 2) return;
  const candidates = anCollectInnerQuantifiers(quantifier.body, []);
  const ambiguousBody = anContainsAdjacentOverlap(quantifier.body);
  for (const inner of candidates) {
    if (inner.max < 2) continue;
    // A fixed count over a fixed length body repeats with a stride, for example
    // (?:[A-Za-z0-9+/]{4})* used by base64 validators. There is only one way to
    // partition a run, so this nesting does not multiply backtracking paths.
    if (inner.min === inner.max && anFixedLength(inner.body) !== null) continue;
    const innerSet = anConsumedSet(inner.body);
    // A "pure" nested quantifier repeats nothing required except the inner
    // repetition, so every character boundary can be assigned to either loop.
    // Optional elements beside it do not change that. When the body is not pure,
    // the risk only holds if the body itself has an ambiguous adjacent pair for
    // the outer loop to redistribute.
    const pure = anIsEffectivelyPure(quantifier.body, inner);
    if (!pure && !ambiguousBody) continue;

    const unboundedOuter = quantifier.max === Infinity;
    const severity = unboundedOuter ? 'critical' : 'high';
    const sample = innerSet ? innerSet.sampleCodePoint() : null;
    const terminator = anPickTerminator([innerSet]);
    const bounds = `${anDescribeBounds(quantifier)} over ${anDescribeBounds(inner)}`;

    add({
      rule: RULES.NESTED_QUANTIFIER,
      severity,
      complexity: severity === 'critical' ? 'exponential' : 'quadratic',
      index: inner.index,
      title: AN_RULE_META[RULES.NESTED_QUANTIFIER].title,
      message:
        `A quantified subexpression ("${anDescribeBounds(inner)}") sits inside another quantifier ` +
        `("${anDescribeBounds(quantifier)}") whose repeated unit can consume the same characters.`,
      explanation: pure
        ? 'The outer loop repeats a group whose only job is the inner repetition, so every character ' +
          'boundary inside a run can be assigned to the outer iteration or to the inner one. Each extra ' +
          'character multiplies the number of partitions, which makes matching time exponential in the ' +
          'length of the attack string.'
        : 'The outer loop contains an adjacent pair that can absorb the same characters, so the engine ' +
          'cannot pin a single split point per repetition. Repeating the group multiplies the number of ' +
          'readings the engine has to retry.',
      remediation:
        'Make one repetition own the characters. Either collapse the two loops into a single bounded ' +
        'quantifier, add a required delimiter inside the outer loop, or validate the run length before ' +
        'applying an anchored pattern.',
      detail: {
        bounds,
        starHeight: 2,
        sampleChar: sample === null ? null : String.fromCodePoint(sample),
        terminator,
        ranges: anRanges(innerSet)
      }
    });
  }
}

function anCheckAdjacentQuantifiers(sequence, add, suppressed) {
  for (const pair of anOverlapPairs(sequence)) {
    if (suppressed.has(pair.leftElement) || suppressed.has(pair.rightElement)) continue;
    const sample = pair.shared.sampleCodePoint();
    const terminator = anPickTerminator([pair.leftSet, pair.rightSet]);
    // Both sides are unbounded by construction (see anOverlapPairs). Bounded
    // neighbours can only split a run a fixed number of ways and are not
    // reported, which keeps validators such as base64 patterns quiet.
    add({
      rule: RULES.OVERLAPPING_ADJACENT,
      severity: 'high',
      complexity: 'quadratic',
      index: pair.right.index,
      title: AN_RULE_META[RULES.OVERLAPPING_ADJACENT].title,
      message: pair.bridge
        ? `"${anDescribeBounds(pair.left)}" and "${anDescribeBounds(pair.right)}" both match ` +
          `${pair.shared.describe()} and the character between them is one both can consume.`
        : `"${anDescribeBounds(pair.left)}" and "${anDescribeBounds(pair.right)}" are adjacent and both match ` +
          `${pair.shared.describe()}.`,
      explanation:
        'An adjacent pair of quantified atoms that accept the same characters leaves the engine no single ' +
        'boundary between them. For every possible split point the remaining suffix is retried, which is ' +
        'quadratic in the length of the input and becomes a denial of service at a few thousand characters.',
      remediation:
        'Separate the two quantifiers with a character that only one of them accepts, or merge them into a ' +
        'single quantified class. When the split is intentional, cap the total length before matching.',
      detail: {
        sampleChar: sample === null ? null : String.fromCodePoint(sample),
        terminator,
        ranges: pair.shared.ranges,
        leftBounds: anDescribeBounds(pair.left),
        rightBounds: anDescribeBounds(pair.right)
      }
    });
  }
}

function anCheckAlternationQuantifier(quantifier, add) {
  if (quantifier.max < 2) return;
  const body = anUnwrap(quantifier.body);
  if (!body || body.type !== 'alternation' || body.options.length < 2) return;
  for (let leftIndex = 0; leftIndex < body.options.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < body.options.length; rightIndex += 1) {
      const left = body.options[leftIndex];
      const right = body.options[rightIndex];
      const leftStart = anStartInfo(left);
      const rightStart = anStartInfo(right);
      // An empty branch has no start set but still makes the loop ambiguous, so
      // the nullable test must run before any set based filter.
      const nullableBranch = leftStart.nullable || rightStart.nullable;
      const shared =
        leftStart.set && rightStart.set ? leftStart.set.intersect(rightStart.set) : null;

      const leftConsumed = anConsumedSet(left);
      const rightConsumed = anConsumedSet(right);
      const subset =
        leftConsumed && rightConsumed
          ? leftConsumed.subsetOf(rightConsumed) || rightConsumed.subsetOf(leftConsumed)
          : false;
      const leftPrefix = anLiteralPrefix(left);
      const rightPrefix = anLiteralPrefix(right);
      const prefixRelation =
        leftPrefix.length > 0 && rightPrefix.length > 0
          ? leftPrefix.startsWith(rightPrefix) || rightPrefix.startsWith(leftPrefix)
          : false;
      // Sharing a first character alone is deterministic for literal branches
      // such as (bar|baz) and must not be reported. The ambiguity is real only
      // when one branch can match a prefix of another, when one branch's
      // character language contains the other, or when a branch can match the
      // empty string and let the loop spin.
      const ambiguous =
        prefixRelation || nullableBranch || (subset && Boolean(shared) && !shared.isEmpty);
      if (!ambiguous) continue;

      const unitSource = leftPrefix.length > 0 && rightPrefix.length > 0
        ? (leftPrefix.length <= rightPrefix.length ? leftPrefix : rightPrefix)
        : null;
      const sample = unitSource && unitSource.length > 0 ? null : (shared ? shared.sampleCodePoint() : null);
      const terminator = anPickTerminator([leftConsumed, rightConsumed]);

      add({
        rule: RULES.OVERLAPPING_ALTERNATION,
        severity: 'critical',
        complexity: 'exponential',
        index: quantifier.index,
        title: AN_RULE_META[RULES.OVERLAPPING_ALTERNATION].title,
        message:
          `Alternation branches "${leftPrefix || '(set)'}" and "${rightPrefix || '(set)'}" both match ` +
          `${shared && !shared.isEmpty ? shared.describe() : 'the empty string'}, and the whole group is quantified ` +
          `with "${anDescribeBounds(quantifier)}".`,
        explanation:
          'When one branch can match text that is a prefix of what another branch matches, or when a ' +
          'branch can match nothing at all, the engine cannot tell where one repetition ends without ' +
          'trying every reading. Under an unbounded quantifier the number of readings doubles with every ' +
          'repetition, which is the classic exponential ReDoS shape.',
        remediation:
          'Order the branches longest first and make them start with distinct characters where possible. ' +
          'For literal sets, replace the alternation with a character class. Never allow an empty branch ' +
          'inside a repeated group.',
        detail: {
          sampleChar: sample === null ? null : String.fromCodePoint(sample),
          repeatUnit: unitSource || undefined,
          terminator,
          ranges: anRanges(shared),
          branches: [leftPrefix, rightPrefix]
        }
      });
    }
  }
}

function anCheckBackreference(node, ctx, add) {
  if (ctx.quantifiers.length === 0) return;
  const owner = ctx.quantifiers[ctx.quantifiers.length - 1];
  const unbounded = owner.max === Infinity;
  add({
    rule: RULES.BACKREFERENCE_IN_QUANTIFIER,
    severity: unbounded ? 'critical' : 'high',
    complexity: unbounded ? 'exponential' : 'quadratic',
    index: node.index,
    title: AN_RULE_META[RULES.BACKREFERENCE_IN_QUANTIFIER].title,
    message:
      `Backreference "${String(node.ref)}" is evaluated inside a loop quantified with ` +
      `"${anDescribeBounds(owner)}".`,
    explanation:
      'A backreference matches text whose length was decided by an earlier submatch, so the engine cannot ' +
      'use a fixed stride. Inside a repeated group every candidate split must be re-matched, and the ' +
      'search space grows super-linearly with the input.',
    remediation:
      'Avoid variable length backreferences inside quantified groups. Capture the repeated text once and ' +
      'compare it in code, or bound the repetition count.',
    detail: { sampleChar: 'a', terminator: '!' }
  });
}

function anCheckLookaround(node, ctx, add) {
  if (ctx.quantifiers.length === 0) return;
  if (!anContainsUnbounded(node.body)) return;
  const owner = ctx.quantifiers[ctx.quantifiers.length - 1];
  const unbounded = owner.max === Infinity;
  add({
    rule: RULES.LOOKAROUND_IN_QUANTIFIER,
    severity: unbounded ? 'high' : 'medium',
    complexity: unbounded ? 'quadratic' : 'linear',
    index: node.index,
    title: AN_RULE_META[RULES.LOOKAROUND_IN_QUANTIFIER].title,
    message:
      `A ${node.lookKind} lookaround with unbounded matching runs inside a loop quantified with ` +
      `"${anDescribeBounds(owner)}".`,
    explanation:
      'Lookarounds are re-evaluated at every position reached by the surrounding loop. When the ' +
      'lookaround itself scans unbounded text, the combined cost is the product of both scans, and ' +
      'negative lookarounds can force the engine to retry entire tails.',
    remediation:
      'Hoist the lookaround outside the loop, or make the lookaround body bounded. Anchoring the outer ' +
      'pattern and validating the lookaround target separately is usually cheaper.',
    detail: { sampleChar: 'a', terminator: '!' }
  });
}

function anCheckNullable(quantifier, add) {
  if (quantifier.max < 2) return;
  if (!anStartInfo(quantifier.body).nullable) return;
  if (quantifier.body.type === 'char' || quantifier.body.type === 'class' || quantifier.body.type === 'dot') return;
  add({
    rule: RULES.NULLABLE_QUANTIFIER_BODY,
    severity: 'medium',
    complexity: 'quadratic',
    index: quantifier.index,
    title: AN_RULE_META[RULES.NULLABLE_QUANTIFIER_BODY].title,
    message:
      `The body of "${anDescribeBounds(quantifier)}" can match the empty string, so the loop can spin ` +
      'without consuming input.',
    explanation:
      'A repeated subexpression that can match nothing forces the engine to detect and break the empty ' +
      'iteration at every position. Combined with other ambiguity it multiplies the backtracking cost, ' +
      'and some engines still degrade sharply on these patterns.',
    remediation:
      'Make the repeated body consume at least one character, for example by changing an optional ' +
      'quantifier inside the group into a required one, or by using a negative lookahead guard.',
    detail: { sampleChar: 'a', terminator: '!' }
  });
}

function anCheckWildcardChain(sequence, add, suppressed) {
  // Every consuming element, classified as an unbounded quantifier, a one
  // character bridge, or a barrier. A literal only breaks a chain when at
  // least one neighbouring scan cannot consume it; ".*a.*b.*c" is a cubic
  // chain precisely because both scans around "a" and "b" match every
  // separator character.
  const items = [];
  for (const element of sequence.elements) {
    if (anIsZeroWidth(element)) continue;
    const form = anQuantifiedForm(element);
    if (form && form.max === Infinity) {
      items.push({ element, form, set: anConsumedSet(form.body), bridge: false });
      continue;
    }
    const bridgeSet = anBridgeSet(element);
    items.push({ element, form: null, set: bridgeSet, bridge: bridgeSet !== null });
  }
  const runs = [];
  let index = 0;
  while (index < items.length) {
    if (!items[index].form) {
      index += 1;
      continue;
    }
    const run = [index];
    let cursor = index;
    for (;;) {
      const next = items[cursor + 1];
      const after = items[cursor + 2];
      if (next && next.form) {
        const currentSet = items[cursor].set;
        const nextSet = next.set;
        if (currentSet && nextSet && !currentSet.intersects(nextSet)) break;
        run.push(cursor + 1);
        cursor += 1;
        continue;
      }
      if (next && next.bridge && after && after.form) {
        const bridgeSet = next.set;
        const currentSet = items[cursor].set;
        const nextSet = after.set;
        const overlap = !currentSet || !nextSet || currentSet.intersects(nextSet);
        const shared = currentSet && nextSet ? currentSet.intersect(nextSet) : (currentSet || nextSet);
        const bridgeFits = !shared || bridgeSet.intersects(shared);
        if (overlap && bridgeFits) {
          run.push(cursor + 1, cursor + 2);
          cursor += 2;
          continue;
        }
      }
      break;
    }
    runs.push(run);
    index = cursor + 1;
  }
  for (const run of runs) {
    const quantifierItems = run.map((entry) => items[entry]).filter((item) => item.form);
    const length = quantifierItems.length;
    if (length < 3) continue;
    const first = quantifierItems[0];
    const last = quantifierItems[length - 1];
    const headSet = first.set;
    const secondSet = quantifierItems[1].set;
    let sampleSource = headSet;
    let sample = null;
    if (headSet && secondSet) {
      const difference = anDifference(headSet, secondSet);
      if (!difference.isEmpty) {
        sampleSource = difference;
        sample = difference.sampleCodePoint();
      } else {
        sample = headSet.intersect(secondSet).sampleCodePoint();
      }
    } else if (headSet) {
      sample = headSet.sampleCodePoint();
    }
    const terminator = anPickTerminator(quantifierItems.map((item) => item.set));
    for (const entry of run) suppressed.add(items[entry].element);
    add({
      rule: RULES.MULTIPLE_WILDCARDS,
      severity: 'high',
      complexity: 'cubic',
      index: first.form.index,
      title: AN_RULE_META[RULES.MULTIPLE_WILDCARDS].title,
      message:
        `${length} unbounded quantifiers in a row ("${anDescribeBounds(first.form)}" ... ` +
        `"${anDescribeBounds(last.form)}") all match overlapping characters.`,
      explanation:
        'Each unbounded quantifier in the chain can scan an arbitrary suffix. When their character ' +
        'sets overlap, a failing suffix makes the engine retry the tail once per split point, giving ' +
        'polynomial backtracking of degree ' + (length - 1) + ' (cubic or worse for three or more).',
      remediation:
        'Replace the greedy scans with a single bounded parse, make the delimiters explicit, or anchor ' +
        'the pattern and cap the input length before matching.',
      detail: {
        sampleChar: sample === null ? 'a' : String.fromCodePoint(sample),
        terminator,
        ranges: anRanges(sampleSource),
        chainLength: length
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

// Read options as own properties only. A polluted Object.prototype must not be
// able to supply a threshold, a cap, or a pattern the caller never passed.
function anOwn(options, name) {
  if (!options || typeof options !== 'object') return undefined;
  return Object.prototype.hasOwnProperty.call(options, name) ? options[name] : undefined;
}

function anNormalizeInput(input, options) {
  if (input instanceof RegExp) return { pattern: input.source, flags: input.flags };
  if (typeof input === 'string') {
    const flags = anOwn(options, 'flags');
    return { pattern: input, flags: flags === undefined ? '' : flags };
  }
  const pattern = anOwn(input, 'pattern');
  if (input && typeof input === 'object' && typeof pattern === 'string') {
    const flags = anOwn(input, 'flags');
    return { pattern, flags: flags === undefined ? '' : flags };
  }
  throw new TypeError('analyzeRegex expects a pattern string or a RegExp');
}

function anScore(findings) {
  let score = 0;
  for (const finding of findings) score += AN_SEVERITY_WEIGHT[finding.severity] || 0;
  return Math.min(100, score);
}

function anRisk(findings) {
  let risk = 'safe';
  for (const finding of findings) {
    if (AN_RISK_ORDER[finding.severity] > AN_RISK_ORDER[risk]) risk = finding.severity;
  }
  return risk;
}

function anWorstCase(findings) {
  const order = ['linear', 'quadratic', 'cubic', 'exponential'];
  let worst = 'linear';
  for (const finding of findings) {
    if (order.indexOf(finding.complexity) > order.indexOf(worst)) worst = finding.complexity;
  }
  return worst;
}

function anSort(findings) {
  return findings.slice().sort((left, right) => {
    const delta = AN_RISK_ORDER[right.severity] - AN_RISK_ORDER[left.severity];
    if (delta !== 0) return delta;
    return left.index - right.index;
  });
}

export function analyzeRegex(input, options) {
  const opts = options || {};
  const normalized = anNormalizeInput(input, opts);
  const ast = parseRegex(normalized.pattern, normalized.flags);
  const findings = [];
  const suppressed = new Set();
  const add = (finding) => {
    const meta = AN_RULE_META[finding.rule];
    findings.push({
      id: meta.code,
      code: meta.code,
      rule: finding.rule,
      title: finding.title,
      severity: finding.severity,
      complexity: finding.complexity,
      cwe: CWE_ID,
      index: finding.index,
      message: finding.message,
      explanation: finding.explanation,
      remediation: finding.remediation,
      detail: finding.detail || {}
    });
  };

  const visit = (node, ctx) => {
    if (!node) return;
    switch (node.type) {
      case 'quantifier':
        anCheckNestedQuantifier(node, add);
        anCheckAlternationQuantifier(node, add);
        anCheckNullable(node, add);
        visit(node.body, { quantifiers: ctx.quantifiers.concat(node), lookarounds: ctx.lookarounds });
        return;
      case 'sequence':
        // The chain rule runs first so that its wider finding takes precedence
        // over the pairwise rule for the same elements.
        anCheckWildcardChain(node, add, suppressed);
        anCheckAdjacentQuantifiers(node, add, suppressed);
        for (const element of node.elements) visit(element, ctx);
        return;
      case 'alternation':
        for (const option of node.options) visit(option, ctx);
        return;
      case 'group':
        if (node.kind === 'lookaround') {
          anCheckLookaround(node, ctx, add);
          visit(node.body, { quantifiers: ctx.quantifiers, lookarounds: ctx.lookarounds + 1 });
        } else {
          visit(node.body, ctx);
        }
        return;
      case 'backref':
        anCheckBackreference(node, ctx, add);
        return;
      default:
        return;
    }
  };

  visit(ast.body, { quantifiers: [], lookarounds: 0 });

  if (anOwn(opts, 'includeBroad') !== false) {
    const broad = [];
    const collectBroad = (node) => {
      if (!node) return;
      if (node.type === 'quantifier' && node.max === Infinity) {
        const set = anConsumedSet(node.body);
        if (set && (node.body.type === 'dot' || set.size >= 512)) {
          const anchored = anIsAnchored(ast.body);
          if (!anchored) broad.push({ node, set });
        }
      }
      if (node.type === 'group' || node.type === 'quantifier') collectBroad(node.body);
      else if (node.type === 'sequence') node.elements.forEach(collectBroad);
      else if (node.type === 'alternation') node.options.forEach(collectBroad);
    };
    collectBroad(ast.body);
    if (findings.length === 0) {
      for (const entry of broad.slice(0, 1)) {
        const sample = entry.set.sampleCodePoint();
        add({
          rule: RULES.BROAD_UNBOUNDED,
          severity: 'low',
          complexity: 'linear',
          index: entry.node.index,
          title: AN_RULE_META[RULES.BROAD_UNBOUNDED].title,
          message:
            `An unanchored "${anDescribeBounds(entry.node)}" scans a broad character set ` +
            `(${entry.set.describe(3)}).`,
          explanation:
            'This is linear, not catastrophic, but an unanchored scan over a huge set touches every ' +
            'position of the input. On very large inputs the constant factor is worth knowing about.',
          remediation:
            'Anchor the pattern, or narrow the class and bound the repetition when the input is untrusted.',
          detail: {
            sampleChar: sample === null ? 'a' : String.fromCodePoint(sample),
            terminator: anPickTerminator([entry.set]),
            ranges: anRanges(entry.set)
          }
        });
      }
    }
  }

  const ordered = anSort(findings);
  const maxFindingsOption = anOwn(opts, 'maxFindings');
  const maxFindings = maxFindingsOption === undefined ? 100 : maxFindingsOption;
  if (!Number.isInteger(maxFindings) || maxFindings < 0) {
    // A negative or non-numeric cap used to slice away every finding and
    // report the pattern as safe, which turned a typo into a silent bypass.
    throw new TypeError('maxFindings must be a non-negative integer');
  }
  const limited = ordered.slice(0, maxFindings);
  const witnesses = anOwn(opts, 'witnesses') === false ? [] : generateWitnesses(ast, limited);
  const risk = anRisk(ordered);
  const complexity = {
    starHeight: anStarHeight(ast.body),
    quantifierDepth: anQuantifierDepth(ast.body, 0),
    unboundedQuantifiers: anCount(ast.body, (node) => node.type === 'quantifier' && node.max === Infinity),
    alternations: anCount(ast.body, (node) => node.type === 'alternation'),
    backreferences: anCount(ast.body, (node) => node.type === 'backref'),
    lookarounds: anCount(ast.body, (node) => node.type === 'group' && node.kind === 'lookaround'),
    worstCase: anWorstCase(ordered)
  };
  const safe = risk === 'safe' || risk === 'low';

  return {
    pattern: normalized.pattern,
    flags: normalized.flags,
    safe,
    risk,
    score: anScore(ordered),
    findings: limited,
    witnessHint: witnesses.length > 0 ? witnesses[0].input : '',
    witnesses,
    starHeight: complexity.starHeight,
    complexity,
    parsed: {
      captureCount: ast.captureCount,
      groupNames: ast.groupNames.slice()
    }
  };
}

function anIsAnchored(body) {
  if (!body) return false;
  const first = body.type === 'sequence' ? body.elements[0] : body;
  return Boolean(first && first.type === 'anchor' && first.kind === 'start');
}

function anThreshold(options) {
  const supplied = anOwn(options, 'threshold');
  const value = supplied === undefined ? 'medium' : supplied;
  if (typeof value !== 'string' || !Object.prototype.hasOwnProperty.call(AN_RISK_ORDER, value)) {
    // An unknown threshold used to make every comparison false, so
    // assertSafeRegex silently accepted critical patterns.
    throw new TypeError('threshold must be one of safe, low, medium, high, critical');
  }
  return value;
}

export function isSafeRegex(input, options) {
  const opts = options || {};
  const threshold = anThreshold(opts);
  const analysis = analyzeRegex(input, opts);
  return AN_RISK_ORDER[analysis.risk] < AN_RISK_ORDER[threshold];
}

export function assertSafeRegex(input, options) {
  const threshold = anThreshold(options);
  const analysis = analyzeRegex(input, options);
  if (AN_RISK_ORDER[analysis.risk] >= AN_RISK_ORDER[threshold]) {
    throw new UnsafeRegexError(analysis);
  }
  return analysis;
}

export { RegexParseError };
