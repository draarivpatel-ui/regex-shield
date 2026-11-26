// regex-shield: character set algebra.
//
// A regex atom consumes a set of code points. Every ReDoS rule in this package
// reasons about those sets, so they are modelled explicitly instead of being
// reduced to "this atom is a wildcard" heuristics. Ranges are inclusive pairs
// and are always normalised: sorted, merged, and clipped to the code space.

export const CS_MAX_CODE_POINT = 0x10ffff;

// Escape class ranges for the ASCII plus common Unicode whitespace that
// JavaScript's \s covers. Sticky details such as lone surrogates are
// deliberately out of scope: the analyzer never executes the pattern.
const CS_CATEGORIES = {
  d: [[0x30, 0x39]],
  w: [[0x30, 0x39], [0x41, 0x5a], [0x5f, 0x5f], [0x61, 0x7a]],
  s: [
    [0x09, 0x0d],
    [0x20, 0x20],
    [0xa0, 0xa0],
    [0x1680, 0x1680],
    [0x2000, 0x200a],
    [0x2028, 0x2029],
    [0x202f, 0x202f],
    [0x205f, 0x205f],
    [0x3000, 0x3000],
    [0xfeff, 0xfeff]
  ]
};

// JavaScript's dot excludes every LineTerminator: LF, CR, LS and PS. The
// analyzer previously forgot U+2028 and U+2029, which made overlap tests treat
// a dot as able to consume them.
const CS_DOT_RANGES = [
  [0x00, 0x09],
  [0x0b, 0x0c],
  [0x0e, 0x2027],
  [0x202a, 0x10ffff]
];

export function csNormalize(ranges) {
  if (!Array.isArray(ranges) || ranges.length === 0) return [];
  const clipped = [];
  for (const range of ranges) {
    if (!range || range.length !== 2) continue;
    let lo = Math.max(0, Math.min(CS_MAX_CODE_POINT, range[0] | 0));
    let hi = Math.max(0, Math.min(CS_MAX_CODE_POINT, range[1] | 0));
    if (hi < lo) {
      const swap = lo;
      lo = hi;
      hi = swap;
    }
    clipped.push([lo, hi]);
  }
  clipped.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const merged = [];
  for (const range of clipped) {
    const last = merged[merged.length - 1];
    if (last && range[0] <= last[1] + 1) {
      if (range[1] > last[1]) last[1] = range[1];
    } else {
      merged.push([range[0], range[1]]);
    }
  }
  return merged;
}

export function csComplement(ranges) {
  const normalized = csNormalize(ranges);
  const result = [];
  let cursor = 0;
  for (const [lo, hi] of normalized) {
    if (lo > cursor) result.push([cursor, lo - 1]);
    cursor = Math.max(cursor, hi + 1);
  }
  if (cursor <= CS_MAX_CODE_POINT) result.push([cursor, CS_MAX_CODE_POINT]);
  return result;
}

function foldCodePoint(codePoint, out) {
  out.add(codePoint);
  if (!Number.isInteger(codePoint) || codePoint < 0 || codePoint > CS_MAX_CODE_POINT) return;
  try {
    const text = String.fromCodePoint(codePoint);
    const lower = text.toLowerCase();
    const upper = text.toUpperCase();
    if ([...lower].length === 1) out.add(lower.codePointAt(0));
    if ([...upper].length === 1) out.add(upper.codePointAt(0));
  } catch (_) {
    // Lone surrogates and engines without String.fromCodePoint keep the literal.
  }
}

/** Code points that case-fold to (or from) ``codePoint`` under the /i flag. */
export function csCaseVariants(codePoint) {
  const points = new Set();
  foldCodePoint(codePoint, points);
  return Array.from(points).sort((left, right) => left - right);
}

/**
 * Case-insensitive closure of a set. ASCII letters are folded exactly by
 * shifting the A-Z and a-z slices. Other cased code points are folded one by
 * one for bounded ranges; a huge range such as \p{L} is already an
 * over-approximation, so folding it would only add cost.
 */
export function csCaseFold(ranges) {
  const out = [];
  for (const [lo, hi] of csNormalize(ranges)) {
    out.push([lo, hi]);
    const upperLo = Math.max(lo, 0x41);
    const upperHi = Math.min(hi, 0x5a);
    if (upperLo <= upperHi) out.push([upperLo + 0x20, upperHi + 0x20]);
    const lowerLo = Math.max(lo, 0x61);
    const lowerHi = Math.min(hi, 0x7a);
    if (lowerLo <= lowerHi) out.push([lowerLo - 0x20, lowerHi - 0x20]);
    if (hi - lo <= 512) {
      const points = new Set();
      for (let codePoint = lo; codePoint <= hi; codePoint += 1) foldCodePoint(codePoint, points);
      for (const codePoint of points) {
        if (codePoint < lo || codePoint > hi) out.push([codePoint, codePoint]);
      }
    }
  }
  return csNormalize(out);
}

export function csUnion() {
  const all = [];
  for (const ranges of arguments) {
    for (const range of ranges) all.push(range);
  }
  return csNormalize(all);
}

export function csIntersect(a, b) {
  const left = csNormalize(a);
  const right = csNormalize(b);
  const out = [];
  let i = 0;
  let j = 0;
  while (i < left.length && j < right.length) {
    const lo = Math.max(left[i][0], right[j][0]);
    const hi = Math.min(left[i][1], right[j][1]);
    if (lo <= hi) out.push([lo, hi]);
    if (left[i][1] < right[j][1]) i += 1;
    else j += 1;
  }
  return out;
}

// True when every code point of a is contained in b.
export function csIsSubset(a, b) {
  const left = csNormalize(a);
  const right = csNormalize(b);
  let j = 0;
  for (const [lo, hi] of left) {
    while (j < right.length && right[j][1] < lo) j += 1;
    if (j >= right.length) return false;
    if (right[j][0] > lo || right[j][1] < hi) return false;
  }
  return true;
}

export function csSize(ranges) {
  let total = 0;
  for (const [lo, hi] of csNormalize(ranges)) total += hi - lo + 1;
  return total;
}

export function csIntersects(a, b) {
  return csIntersect(a, b).length > 0;
}

export function csContainsCodePoint(ranges, codePoint) {
  const cp = codePoint | 0;
  for (const [lo, hi] of csNormalize(ranges)) {
    if (cp >= lo && cp <= hi) return true;
  }
  return false;
}

// A printable representative for a set, used by the witness generator so the
// attack hint is readable. Falls back to the lowest code point.
export function csSampleCodePoint(ranges, exclude) {
  const excluded = new Set();
  for (const value of exclude || []) {
    if (typeof value === 'string' && value.length > 0) excluded.add(value.codePointAt(0));
    else if (typeof value === 'number') excluded.add(value);
  }
  const normalized = csNormalize(ranges);
  const printable = (cp) => cp >= 0x21 && cp <= 0x7e;
  for (const [lo, hi] of normalized) {
    const end = Math.min(hi, lo + 256);
    for (let cp = Math.max(lo, 0x21); cp <= end; cp += 1) {
      if (!printable(cp) || excluded.has(cp)) continue;
      return cp;
    }
  }
  for (const [lo, hi] of normalized) {
    for (let cp = lo; cp <= Math.min(hi, lo + 256); cp += 1) {
      if (!excluded.has(cp)) return cp;
    }
  }
  return null;
}

export function csRenderCodePoint(codePoint) {
  if (codePoint === null || codePoint === undefined) return '';
  if (codePoint >= 0x20 && codePoint <= 0x7e) return String.fromCodePoint(codePoint);
  if (codePoint <= 0xff) return `\\x${codePoint.toString(16).padStart(2, '0')}`;
  return `\\u${codePoint.toString(16).padStart(4, '0')}`;
}

// Human readable set summary, bounded so reports stay readable for huge sets.
export function csDescribe(ranges, limit = 6) {
  const normalized = csNormalize(ranges);
  if (normalized.length === 0) return 'nothing';
  const parts = [];
  for (const [lo, hi] of normalized.slice(0, limit)) {
    if (lo === 0 && hi === CS_MAX_CODE_POINT) {
      parts.push('any character');
      continue;
    }
    if (lo === hi) parts.push(csRenderCodePoint(lo));
    else if (hi - lo <= 64) parts.push(`${csRenderCodePoint(lo)}-${csRenderCodePoint(hi)}`);
    else parts.push(`U+${lo.toString(16).toUpperCase()}-U+${hi.toString(16).toUpperCase()}`);
  }
  if (normalized.length > limit) parts.push(`and ${normalized.length - limit} more ranges`);
  return parts.join(', ');
}

// Immutable set wrapper. `negated` is display metadata only; `ranges` is always
// the effective set after negation so callers never branch on the flag.
export class CharSet {
  constructor(ranges, meta) {
    this.ranges = csNormalize(ranges);
    this.meta = meta || {};
  }

  static literal(codePoint) {
    return new CharSet([[codePoint, codePoint]], { source: 'literal' });
  }

  static fromCodePoints(codePoints) {
    const ranges = [];
    for (const codePoint of codePoints || []) {
      if (Number.isInteger(codePoint)) ranges.push([codePoint, codePoint]);
    }
    return new CharSet(ranges, { source: 'literal' });
  }

  static category(letter, negated) {
    const ranges = CS_CATEGORIES[letter.toLowerCase()] || [];
    return new CharSet(negated ? csComplement(ranges) : ranges, {
      source: 'category',
      letter,
      negated: Boolean(negated)
    });
  }

  static dot() {
    return new CharSet(CS_DOT_RANGES, { source: 'dot' });
  }

  static universe() {
    return new CharSet([[0, CS_MAX_CODE_POINT]], { source: 'universe' });
  }

  static property(raw, negated) {
    return new CharSet([[0, CS_MAX_CODE_POINT]], {
      source: 'property',
      raw,
      negated: Boolean(negated)
    });
  }

  get isEmpty() {
    return this.ranges.length === 0;
  }

  get size() {
    return csSize(this.ranges);
  }

  intersects(other) {
    return csIntersects(this.ranges, other.ranges);
  }

  intersect(other) {
    return new CharSet(csIntersect(this.ranges, other.ranges), { source: 'intersection' });
  }

  union(other) {
    return new CharSet(csUnion(this.ranges, other.ranges), { source: 'union' });
  }

  subsetOf(other) {
    return csIsSubset(this.ranges, other.ranges);
  }

  contains(codePoint) {
    return csContainsCodePoint(this.ranges, codePoint);
  }

  sampleCodePoint(exclude) {
    return csSampleCodePoint(this.ranges, exclude);
  }

  describe(limit) {
    return csDescribe(this.ranges, limit);
  }
}
