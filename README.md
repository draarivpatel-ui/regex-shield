# @aarivbuildz/regex-shield

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/draarivpatel-ui/regex-shield/badge)](https://scorecard.dev/viewer/?uri=github.com/draarivpatel-ui/regex-shield)

Static ReDoS analysis for JavaScript regular expressions, with a real regex
parser and CWE-1333 classification.

`regex-shield` is a zero dependency replacement for the 2019 `safe-regex`
heuristic. Instead of counting repetition operators, it parses the pattern into
an AST, computes the code point sets every atom can match, and reports the
structural ambiguity that makes backtracking engines explode: nested
quantifiers, overlapping adjacent quantifiers, overlapping alternation branches,
wildcard chains, quantified backreferences and lookarounds, and nullable loop
bodies.

Zero dependencies at runtime. Node 18 or later. ESM and CommonJS from the same
named exports, with TypeScript definitions.

```
npm install @aarivbuildz/regex-shield
```

## Quick start

```js
import { analyzeRegex, isSafeRegex, assertSafeRegex } from '@aarivbuildz/regex-shield';

const result = analyzeRegex('(a+)+$');
result.risk;       // 'critical'
result.safe;       // false
result.score;      // 70
result.findings;   // [{ code: 'RS001', severity: 'critical', ... }]
result.witnessHint; // 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!'
```

CommonJS works without a build step:

```js
const { analyzeRegex } = require('@aarivbuildz/regex-shield');
console.log(analyzeRegex('^(a|aa)+$').risk); // 'critical'
```

Gate untrusted patterns in a validator or a plugin loader:

```js
import { assertSafeRegex, UnsafeRegexError } from '@aarivbuildz/regex-shield';

try {
  assertSafeRegex(userSuppliedPattern);
} catch (error) {
  if (error instanceof UnsafeRegexError) {
    throw new Error(`unsafe pattern: ${error.findings[0].message}`);
  }
  throw error;
}
```

## API

### `analyzeRegex(input, options?)`

Accepts a pattern string, a `RegExp`, or an object with `pattern` and optional
`flags`. Returns a deterministic analysis:

| Field | Meaning |
| --- | --- |
| `pattern`, `flags` | Normalized input |
| `safe` | `true` when risk is `safe` or `low` |
| `risk` | `safe`, `low`, `medium`, `high`, `critical` |
| `score` | 0 to 100, weighted by severity |
| `findings` | Ordered findings with CWE-1333 metadata |
| `witnessHint` | Short reproducible input shape for the worst finding |
| `witnesses` | One witness per finding |
| `starHeight` | Nesting depth of unbounded repetition |
| `complexity` | Counts plus `worstCase` complexity class |
| `parsed` | Capture count and group names |

Options: `flags`, `threshold` (used by the predicates), `witnesses` (default
`true`), `includeBroad` (default `true`), and `maxFindings` (default `100`).

### `isSafeRegex(input, options?)`

Boolean convenience wrapper. The default threshold is `medium`, so low
informational findings do not fail the gate.

### `assertSafeRegex(input, options?)`

Returns the analysis when the pattern is below the threshold, otherwise throws
an `UnsafeRegexError` carrying `analysis`, `findings`, `pattern`, `flags`,
`risk` and `score`.

### `scan(patterns, options?)`

Analyzes an array of patterns and adds a zero based `index` to each result. An
invalid pattern throws instead of being silently reported as safe.

### `parseRegex(pattern, flags?)`

Returns the parser AST. Useful for editor tooling that wants positions and
character sets without the analyzer. Syntax errors throw `RegexParseError` with
`pattern` and `index` fields.

### `CharSet`

The code point range algebra used by the analyzer. Ranges are normalized and
clipped to the Unicode code space. Exposes `literal`, `category`, `dot`,
`universe`, `intersect`, `union`, `subsetOf`, `contains`, `sampleCodePoint` and
`describe`.

## Rules

All findings map to CWE-1333, Inefficient Regular Expression Complexity.

| Code | Rule | Typical shape | Worst case |
| --- | --- | --- | --- |
| RS001 | Nested quantifiers over an overlapping body | `(a+)+$`, `(\d+)*$` | Exponential |
| RS002 | Adjacent quantified atoms match overlapping characters | `\d+\d+$`, `.*.*$`, `.*a.*$` | Quadratic |
| RS003 | Quantified alternation with overlapping branches | `(a\|aa)+$`, `(a\|)+$` | Exponential |
| RS004 | Backreference inside a quantified loop | `(?:(a)\1)+$` | Exponential |
| RS005 | Unbounded lookaround inside a quantified loop | `(?:(?=a+)\w)+$` | Quadratic |
| RS006 | Quantifier body can match the empty string | `(?:a?)*$` | Quadratic |
| RS007 | Chain of three or more unbounded wildcards | `.*.*.*$`, `.*a.*b.*c` | Cubic |
| RS008 | Unanchored unbounded scan over a broad set | `.+`, `[^<]+` | Linear |

RS008 is informational and only emitted when no stronger finding exists. The
predicates treat `low` as safe by default, which keeps broad but linear scans
from breaking builds.

Each finding carries `message`, `explanation`, `remediation`, the source
`index`, and a `detail` object with the bounds, a sample character, a failing
terminator, and the intersecting code point ranges. The witness hint is a short
string built from the sample character and terminator. It is a debugging aid,
not a proof of exploitability.

## CLI

```
regex-shield [options] <pattern> [pattern...]
regex-shield [options] --stdin
```

```
$ regex-shield '(a+)+$'
/(a+)+$/  risk: critical  score: 70
  RS001 critical  Nested quantifiers over an overlapping body
    A quantified subexpression ("+") sits inside another quantifier ("+") ...
    fix: Make one repetition own the characters. ...
  witness hint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"

1 pattern checked, at least one at or above "medium"
$ echo $?
1
```

Options: `--flags`, `--threshold`, `--json`, `--no-witness`, `--no-broad`,
`--stdin`. Exit codes: `0` below threshold, `1` at or above threshold, `2`
usage or parse error. `--json` output is stable and contains no timings or
absolute paths, so it can be diffed in CI.

## Historical coverage

The test corpus includes the published vulnerable regexes from these advisories,
copied from the affected package versions:

| Advisory | Package | Finding |
| --- | --- | --- |
| CVE-2021-23424 | ansi-html 0.0.7 | RS001 nested capture repetition |
| CVE-2020-7661 | url-regex 4.1.0 | RS002 host label overlap |
| CVE-2021-3807 | ansi-regex 5.0.0 | RS002 semicolon run split |
| CVE-2021-23343 | path-parse 1.0.6 | RS002 lazy tail with nullable branches |

The corpus also keeps the canonical teaching patterns from public ReDoS
write-ups: the OWASP evil regex, `^(\w+\s?)*$`, `^(a|aa)+$`, `^(\d+)*$`, a
backreference loop, and a three wildcard chain.

Advisories whose cost comes from generated route regexes (path-to-regexp),
brace expansion algorithms (minimatch, micromatch), or engine internals (debug
`%o`, trim-newlines) are out of scope for a static AST analyzer. They are
documented here so the boundary of the rule set is explicit rather than implied.

## Design and limits

- The analyzer never executes the pattern. It validates syntax with the
  platform `RegExp` constructor and then parses the source itself.
- Every rule reasons about code point sets, not string heuristics. A rule fires
  only when the junction sets actually intersect.
- Fixed stride repetitions such as `(?:[A-Za-z0-9+/]{4})*` are deliberately not
  reported: a fixed length unit has exactly one partition per run.
- Bounded neighbours such as `\d{2}\d{3}` are not reported: they can only split
  a run a fixed number of ways.
- The analyzer is conservative by design. A finding means the structure can
  backtrack super-linearly on a crafted input; it is not a promise that a
  particular engine will hang, and a clean result is not a formal proof.
- Annex B syntax is reproduced where it changes the reading of a pattern:
  literal braces, legacy octal escapes, identity escapes, and the literal hyphen
  beside a class escape. In particular `\8` and `\9` are identity escapes inside
  a class, exactly as the engine reads them.
- The `i` flag folds literal and class sets before any overlap test, so `(a|A)+`
  and `[a-z]+[A-Z]+` are reported under `/i`. The `s` flag widens the dot to the
  whole code space, and without it the dot excludes all four line terminators.
- A one character separator does not split a chain when both neighbouring scans
  can consume it: `.*a.*` is quadratic and `.*a.*b.*c` is cubic.
- Patterns nested more than 500 groups deep are rejected with `RegexParseError`
  before the recursive parser can exhaust the stack. v-mode class set operators
  (`--`, `&&`, nested classes, `\q{...}`) are rejected the same way instead of
  being silently read as flat literals.

## Tests

The suite has 262 deterministic tests and runs on the built in Node test runner:

```
npm test
npm run test:coverage
```

The tests cover the parser, the character set algebra, every rule, the API
surface, the CLI, witness generation, the historical CVE corpus, a production
regex corpus, flag-sensitive sets (`i` and `s`), literal separated backtracking
chains, parser resource limits, and ESM/CommonJS parity. No network access, no
fixtures outside the repository, no timing assertions.

## Benchmarks

```
npm run bench
npm run bench -- --json --iterations 5000
```

The benchmark parses and analyzes a corpus from scratch on every iteration,
which matches the cost paid by a linter or a CI gate.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md). Security reports go through
[SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
