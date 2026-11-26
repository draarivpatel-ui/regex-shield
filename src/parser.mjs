// regex-shield: a self contained parser for JavaScript regular expressions.
//
// The parser does not execute patterns. It produces a small AST that keeps the
// structure the analyzer needs: alternations, sequences, groups (including
// lookarounds), character classes with real code point ranges, quantifiers with
// their bounds and greediness, anchors, backreferences, and capture metadata.
//
// Syntax validation is deliberately faithful to the JavaScript grammar for the
// constructs that matter to ReDoS analysis. Annex B leniencies are reproduced
// where they change how a pattern is read (for example a stray "{" is a literal
// outside unicode mode, and decimal escapes above the capture count fall back to
// legacy octal).

import { CharSet, csComplement } from './charset.mjs';

const PN_ALLOWED_FLAGS = 'dgimsuvy';

// JavaScript identifiers allow the zero width non joiner and joiner, written here
// as escapes so the source stays readable.
const PN_GROUP_NAME = /^[$_\p{ID_Start}][$\u200c\u200d\p{ID_Continue}]*$/u;

export class RegexParseError extends Error {
  constructor(message, pattern, index) {
    const safeIndex = Number.isInteger(index) ? index : 0;
    super(`${message} at index ${safeIndex} in /${pattern}/`);
    this.name = 'RegexParseError';
    this.pattern = pattern;
    this.index = safeIndex;
  }
}

function pnIsAssertion(node) {
  return node.type === 'anchor' || (node.type === 'group' && node.kind === 'lookaround');
}

function pnIsHexDigit(ch) {
  return ch !== undefined && /[0-9a-fA-F]/.test(ch);
}

class RegexParser {
  constructor(source, flags) {
    this.source = source;
    this.flags = flags;
    this.pos = 0;
    this.captureCount = 0;
    this.groupNames = [];
    this.backrefs = [];
    this.unicode = flags.includes('u') || flags.includes('v');
  }

  error(message, index) {
    throw new RegexParseError(message, this.source, index === undefined ? this.pos : index);
  }

  eof() {
    return this.pos >= this.source.length;
  }

  peek(offset) {
    return this.source[this.pos + (offset || 0)];
  }

  eat(ch) {
    if (this.peek() === ch) {
      this.pos += 1;
      return true;
    }
    return false;
  }

  parse() {
    const body = this.parseDisjunction();
    if (!this.eof()) this.error('Unmatched closing parenthesis');
    this.resolveBackreferences(body);
    return {
      type: 'root',
      pattern: this.source,
      flags: this.flags,
      body,
      captureCount: this.captureCount,
      groupNames: this.groupNames.slice()
    };
  }

  parseDisjunction() {
    const start = this.pos;
    const options = [this.parseAlternative()];
    while (this.eat('|')) options.push(this.parseAlternative());
    if (options.length === 1) return options[0];
    return { type: 'alternation', options, index: start, end: this.pos };
  }

  parseAlternative() {
    const start = this.pos;
    const elements = [];
    while (!this.eof() && this.peek() !== '|' && this.peek() !== ')') {
      elements.push(this.parseTerm());
    }
    return { type: 'sequence', elements, index: start, end: this.pos };
  }

  parseTerm() {
    const start = this.pos;
    const atom = this.parseAtom();
    const quantified = this.parseQuantifier(atom, start);
    return quantified || atom;
  }

  parseQuantifier(atom, start) {
    if (this.eof()) return null;
    const ch = this.peek();
    let min;
    let max;
    let quantStart = this.pos;
    if (ch === '*') {
      min = 0;
      max = Infinity;
      this.pos += 1;
    } else if (ch === '+') {
      min = 1;
      max = Infinity;
      this.pos += 1;
    } else if (ch === '?') {
      min = 0;
      max = 1;
      this.pos += 1;
    } else if (ch === '{') {
      const bounds = this.tryParseBraces();
      if (!bounds) {
        if (this.unicode) this.error('Incomplete quantifier', start === this.pos ? this.pos : quantStart);
        return null;
      }
      min = bounds.min;
      max = bounds.max;
    } else {
      return null;
    }
    let greedy = true;
    if (this.peek() === '?') {
      greedy = false;
      this.pos += 1;
    }
    if (pnIsAssertion(atom)) {
      if (atom.type === 'anchor' || this.unicode) {
        this.error('Nothing to repeat', quantStart);
      }
    }
    return {
      type: 'quantifier',
      min,
      max,
      greedy,
      body: atom,
      index: start,
      end: this.pos
    };
  }

  // Returns { min, max } when the text at the cursor is a well formed bound,
  // otherwise restores the cursor and returns null.
  tryParseBraces() {
    const saved = this.pos;
    this.pos += 1;
    let minText = '';
    while (!this.eof() && /[0-9]/.test(this.peek())) {
      minText += this.peek();
      this.pos += 1;
    }
    if (minText.length === 0) {
      this.pos = saved;
      return null;
    }
    let maxText = null;
    if (this.peek() === ',') {
      this.pos += 1;
      maxText = '';
      while (!this.eof() && /[0-9]/.test(this.peek())) {
        maxText += this.peek();
        this.pos += 1;
      }
    }
    if (this.peek() !== '}') {
      this.pos = saved;
      return null;
    }
    this.pos += 1;
    const min = Number(minText);
    let max;
    if (maxText === null) max = min;
    else if (maxText === '') max = Infinity;
    else max = Number(maxText);
    if (max !== Infinity && max < min) this.error('Numbers out of order in quantifier');
    if (min > 0xffffffff) this.error('Quantifier value is too large');
    return { min, max };
  }

  parseAtom() {
    const start = this.pos;
    const ch = this.peek();
    if (ch === '(') return this.parseGroup();
    if (ch === '[') return this.parseClass();
    if (ch === '.') {
      this.pos += 1;
      return { type: 'dot', index: start, end: this.pos, set: CharSet.dot() };
    }
    if (ch === '^') {
      this.pos += 1;
      return { type: 'anchor', kind: 'start', index: start, end: this.pos };
    }
    if (ch === '$') {
      this.pos += 1;
      return { type: 'anchor', kind: 'end', index: start, end: this.pos };
    }
    if (ch === '\\') return this.parseEscape(false);
    if (ch === '*' || ch === '+' || ch === '?') this.error('Nothing to repeat', start);
    if (ch === ')' || ch === '|') this.error('Unexpected token', start);
    this.pos += 1;
    let codePoint = this.source.codePointAt(start);
    if (codePoint !== undefined && codePoint > 0xffff) this.pos = start + 2;
    return {
      type: 'char',
      codePoint,
      raw: this.source.slice(start, this.pos),
      index: start,
      end: this.pos
    };
  }

  parseGroup() {
    const start = this.pos;
    this.pos += 1;
    let kind = 'capture';
    let lookKind = null;
    let name = null;
    let captureIndex = null;
    if (this.eat('?')) {
      if (this.eat(':')) {
        kind = 'noncapture';
      } else if (this.eat('=')) {
        kind = 'lookaround';
        lookKind = 'ahead';
      } else if (this.eat('!')) {
        kind = 'lookaround';
        lookKind = 'ahead-negative';
      } else if (this.eat('<')) {
        if (this.eat('=')) {
          kind = 'lookaround';
          lookKind = 'behind';
        } else if (this.eat('!')) {
          kind = 'lookaround';
          lookKind = 'behind-negative';
        } else {
          let nameText = '';
          while (!this.eof() && this.peek() !== '>') {
            nameText += this.peek();
            this.pos += 1;
          }
          if (!this.eat('>')) this.error('Unterminated group name', start);
          if (!PN_GROUP_NAME.test(nameText)) {
            this.error('Invalid capture group name', start);
          }
          if (this.groupNames.includes(nameText)) {
            this.error('Duplicate capture group name', start);
          }
          kind = 'named';
          name = nameText;
          this.groupNames.push(nameText);
        }
      } else {
        this.error('Invalid group', start);
      }
    }
    if (kind === 'capture' || kind === 'named') {
      this.captureCount += 1;
      captureIndex = this.captureCount;
    }
    const body = this.parseDisjunction();
    if (!this.eat(')')) this.error('Unterminated group', start);
    return {
      type: 'group',
      kind,
      lookKind,
      name,
      captureIndex,
      body,
      index: start,
      end: this.pos
    };
  }

  parseClass() {
    const start = this.pos;
    this.pos += 1;
    const negated = this.eat('^');
    const items = [];
    while (!this.eof() && this.peek() !== ']') {
      const first = this.parseClassAtom();
      if (this.peek() === '-' && this.peek(1) !== ']' && this.peek(1) !== undefined) {
        const dashPos = this.pos;
        this.pos += 1;
        const second = this.parseClassAtom();
        if (first.kind !== 'char' || second.kind !== 'char') {
          // Annex B: outside unicode mode a "-" that touches a set valued escape
          // is a literal hyphen between two class atoms, so "[a-\\d]" is legal and
          // means "a", "-" or a digit. Unicode mode keeps the strict grammar.
          if (this.unicode) this.error('Invalid character class range', dashPos);
          items.push(first, { kind: 'char', codePoint: 0x2d }, second);
          continue;
        }
        if (second.codePoint < first.codePoint) this.error('Range out of order in character class', dashPos);
        items.push({ kind: 'range', lo: first.codePoint, hi: second.codePoint });
      } else {
        items.push(first);
      }
    }
    if (!this.eat(']')) this.error('Unterminated character class', start);
    const ranges = [];
    for (const item of items) {
      if (item.kind === 'char') ranges.push([item.codePoint, item.codePoint]);
      else if (item.kind === 'range') ranges.push([item.lo, item.hi]);
      else for (const range of item.set.ranges) ranges.push(range);
    }
    const set = new CharSet(negated ? csComplement(ranges) : ranges, {
      source: 'class',
      negated,
      raw: this.source.slice(start, this.pos)
    });
    return {
      type: 'class',
      negated,
      set,
      ranges: set.ranges,
      raw: this.source.slice(start, this.pos),
      index: start,
      end: this.pos
    };
  }

  // A class atom is either a single code point or a set valued escape such as
  // \d. Ranges may only be formed from two single code points.
  parseClassAtom() {
    if (this.peek() === '\\') {
      const escape = this.parseEscape(true);
      if (escape.type === 'char') return { kind: 'char', codePoint: escape.codePoint };
      return { kind: 'set', set: escape.set };
    }
    const start = this.pos;
    this.pos += 1;
    let codePoint = this.source.codePointAt(start);
    if (codePoint !== undefined && codePoint > 0xffff) this.pos = start + 2;
    return { kind: 'char', codePoint };
  }

  parseEscape(inClass) {
    const start = this.pos;
    this.pos += 1;
    if (this.eof()) this.error('Trailing backslash', start);
    const ch = this.peek();
    this.pos += 1;
    const charNode = (codePoint) => ({
      type: 'char',
      codePoint,
      raw: this.source.slice(start, this.pos),
      index: start,
      end: this.pos
    });
    const setNode = (set, raw) => ({
      type: 'class',
      negated: false,
      set,
      ranges: set.ranges,
      raw: raw === undefined ? this.source.slice(start, this.pos) : raw,
      index: start,
      end: this.pos
    });

    if (ch === 'd' || ch === 'D' || ch === 'w' || ch === 'W' || ch === 's' || ch === 'S') {
      const lower = ch.toLowerCase();
      const negated = ch !== lower;
      return setNode(CharSet.category(lower, negated), this.source.slice(start, this.pos));
    }
    if (ch === 'b') {
      if (inClass) return charNode(0x08);
      return { type: 'anchor', kind: 'word-boundary', index: start, end: this.pos };
    }
    if (ch === 'B') {
      if (inClass) return charNode(0x42);
      return { type: 'anchor', kind: 'non-word-boundary', index: start, end: this.pos };
    }
    const simple = { n: 0x0a, r: 0x0d, t: 0x09, f: 0x0c, v: 0x0b }[ch];
    if (simple !== undefined) return charNode(simple);
    if (ch === '0') {
      // \0 is NUL. Numeric tails after it are legacy octal and only meaningful
      // outside unicode mode; consume up to three octal digits in total.
      let digits = '0';
      if (!this.unicode) {
        while (!this.eof() && digits.length < 3 && /[0-7]/.test(this.peek())) {
          digits += this.peek();
          this.pos += 1;
        }
      }
      return charNode(parseInt(digits, 8));
    }
    if (ch === 'x') {
      if (pnIsHexDigit(this.peek()) && pnIsHexDigit(this.peek(1))) {
        const hex = this.source.slice(this.pos, this.pos + 2);
        this.pos += 2;
        return charNode(parseInt(hex, 16));
      }
      if (this.unicode) this.error('Invalid hexadecimal escape', start);
      return charNode(0x78);
    }
    if (ch === 'u') {
      if (this.peek() === '{') {
        const saved = this.pos;
        let hex = '';
        this.pos += 1;
        while (!this.eof() && /[0-9a-fA-F]/.test(this.peek())) {
          hex += this.peek();
          this.pos += 1;
        }
        if (this.eat('}') && hex.length > 0 && parseInt(hex, 16) <= 0x10ffff && this.unicode) {
          return charNode(parseInt(hex, 16));
        }
        this.pos = saved;
        if (this.unicode) this.error('Invalid unicode escape', start);
        return charNode(0x75);
      }
      if (pnIsHexDigit(this.peek()) && pnIsHexDigit(this.peek(1)) && pnIsHexDigit(this.peek(2)) && pnIsHexDigit(this.peek(3))) {
        const hex = this.source.slice(this.pos, this.pos + 4);
        this.pos += 4;
        return charNode(parseInt(hex, 16));
      }
      if (this.unicode) this.error('Invalid unicode escape', start);
      return charNode(0x75);
    }
    if (ch === 'c') {
      const letter = this.peek();
      if (letter !== undefined && /[A-Za-z]/.test(letter)) {
        this.pos += 1;
        return charNode(letter.toUpperCase().charCodeAt(0) - 64);
      }
      if (this.unicode) this.error('Invalid control escape', start);
      return charNode(0x63);
    }
    if (ch === 'p' || ch === 'P') {
      if (this.unicode && this.peek() === '{') {
        let body = '';
        this.pos += 1;
        while (!this.eof() && this.peek() !== '}') {
          body += this.peek();
          this.pos += 1;
        }
        if (!this.eat('}')) this.error('Unterminated unicode property escape', start);
        return setNode(CharSet.property(`${ch}{${body}}`, ch === 'P'), this.source.slice(start, this.pos));
      }
      return charNode(ch.charCodeAt(0));
    }
    if (ch === 'k' && !inClass) {
      if (this.peek() === '<') {
        let nameText = '';
        this.pos += 1;
        while (!this.eof() && this.peek() !== '>') {
          nameText += this.peek();
          this.pos += 1;
        }
        if (!this.eat('>')) this.error('Unterminated named backreference', start);
        const node = { type: 'backref', ref: nameText, index: start, end: this.pos };
        this.backrefs.push(node);
        return node;
      }
      return charNode(0x6b);
    }
    if (/[1-9]/.test(ch) && !inClass) {
      let digits = ch;
      while (!this.eof() && /[0-9]/.test(this.peek())) {
        digits += this.peek();
        this.pos += 1;
      }
      const node = { type: 'backref', ref: Number(digits), index: start, end: this.pos };
      this.backrefs.push(node);
      return node;
    }
    if (/[1-9]/.test(ch) && inClass) {
      let digits = ch;
      while (!this.eof() && digits.length < 3 && /[0-7]/.test(this.peek())) {
        digits += this.peek();
        this.pos += 1;
      }
      return charNode(parseInt(digits, 8));
    }
    return charNode(ch.codePointAt(0));
  }

  // Decimal references above the number of capture groups are not references at
  // all under Annex B: they are legacy octal escapes or literal digits. Rewrite
  // those nodes so the analyzer never sees a reference that cannot exist.
  resolveBackreferences(root) {
    const self = this;
    const rewrite = (node) => {
      if (!node || typeof node !== 'object') return node;
      if (node.type === 'backref') {
        if (typeof node.ref === 'number' && node.ref > self.captureCount) {
          const text = String(node.ref);
          const octal = /^[0-7]+$/.test(text) ? parseInt(text, 8) : NaN;
          const codePoint = Number.isFinite(octal) && octal <= 0x10ffff ? octal : text.codePointAt(0);
          return { type: 'char', codePoint, raw: text, index: node.index, end: node.end, legacyEscape: true };
        }
        return node;
      }
      if (node.type === 'group') node.body = rewrite(node.body);
      else if (node.type === 'quantifier') node.body = rewrite(node.body);
      else if (node.type === 'sequence') node.elements = node.elements.map(rewrite);
      else if (node.type === 'alternation') node.options = node.options.map(rewrite);
      return node;
    };
    rewrite(root);
  }
}

export function parseRegex(pattern, flags) {
  if (typeof pattern !== 'string') {
    throw new TypeError('parseRegex expects a pattern string');
  }
  const flagText = flags === undefined ? '' : String(flags);
  const seen = new Set();
  for (const flag of flagText) {
    if (!PN_ALLOWED_FLAGS.includes(flag)) {
      throw new RegexParseError(`Invalid regular expression flag "${flag}"`, pattern, 0);
    }
    if (seen.has(flag)) {
      throw new RegexParseError(`Duplicate regular expression flag "${flag}"`, pattern, 0);
    }
    seen.add(flag);
  }
  if (seen.has('u') && seen.has('v')) {
    throw new RegexParseError('Flags "u" and "v" cannot be combined', pattern, 0);
  }
  // Constructing a RegExp validates the pattern without running it. This keeps
  // the parser honest about syntax the JavaScript engine accepts.
  try {
    new RegExp(pattern, flagText);
  } catch (error) {
    throw new RegexParseError(error.message.replace(/^Invalid regular expression: /, ''), pattern, 0);
  }
  return new RegexParser(pattern, flagText).parse();
}
