// regex-shield: public API.
//
// The package is intentionally small at the surface: one analyzer, two
// convenience predicates, the parser for tooling, and the error types. Rules and
// CWE identifiers are exported so downstream linters can map findings onto their
// own severity scales.

import {
  analyzeRegex,
  isSafeRegex,
  assertSafeRegex,
  UnsafeRegexError,
  RULES,
  CWE_ID,
  CWE_URL
} from './analyzer.mjs';
import { parseRegex, RegexParseError } from './parser.mjs';
import { CharSet } from './charset.mjs';

export const VERSION = '1.0.0';

// Batch helper: analyze an array of patterns and return one result per entry.
// Invalid patterns throw, exactly like analyzeRegex, so a scan failure is never
// silently reported as "safe".
export function scan(patterns, options) {
  if (!Array.isArray(patterns)) {
    throw new TypeError('scan expects an array of patterns or RegExp objects');
  }
  return patterns.map((pattern, index) => ({
    index,
    ...analyzeRegex(pattern, options)
  }));
}

export {
  analyzeRegex,
  isSafeRegex,
  assertSafeRegex,
  UnsafeRegexError,
  parseRegex,
  RegexParseError,
  CharSet,
  RULES,
  CWE_ID,
  CWE_URL
};
