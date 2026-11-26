# Good first issues

Ten small, well-scoped tasks for new contributors. Each one names the module to touch and has a deterministic acceptance check. Comment on the issue before starting so work is not duplicated.

## Issue 1: Add parser position fixtures

- **Area:** `src/parser.mjs`, `tests/parser.test.mjs`
- **Task:** Add a table asserting start and end positions for nested groups, alternation branches, class ranges and quantifiers in compact patterns.
- **Acceptance:** Fixtures are deterministic and cover at least one astral character without changing parser behavior.

## Issue 2: Expand charset algebra invariants

- **Area:** `tests/charset.test.mjs`
- **Task:** Add a seeded invariant test that compares union, intersection, complement and subset identities across small fixed range sets.
- **Acceptance:** The seed is fixed, failures print the input ranges, and the test completes instantly with no dependency.

## Issue 3: Document every rule with a safe rewrite

- **Area:** `README.md`
- **Task:** Add one safe rewrite example for each RS001 through RS008 finding. Keep the examples short and make clear that rewrites depend on the intended language.
- **Acceptance:** Examples use valid JavaScript regex syntax and the README remains free of em dashes and en dashes.

## Issue 4: Add CLI JSON schema fixtures

- **Area:** `tests/cli.test.mjs`
- **Task:** Snapshot the exact top-level keys and nested finding keys emitted by `--json` for one safe pattern and one critical pattern.
- **Acceptance:** The assertions are key-by-key rather than a brittle full-string snapshot and include no timings or absolute paths.

## Issue 5: Test threshold boundary behavior

- **Area:** `src/analyzer.mjs`, `tests/analyzer.test.mjs`
- **Task:** Add a matrix proving which risk levels pass or fail at every threshold from `safe` through `critical`.
- **Acceptance:** The matrix includes custom threshold input and invalid threshold behavior already required by the public API.

## Issue 6: Improve witness readability

- **Area:** `src/witness.mjs`, `tests/witness.test.mjs`
- **Task:** Add escaped rendering for witness hints containing tabs, newlines, quotes or non-printable code points so CLI output remains one line per finding.
- **Acceptance:** Regression tests cover each escaped class and existing witness lengths remain unchanged.

## Issue 7: Add a TypeScript consumer smoke test

- **Area:** `types/`, `tests/package.test.mjs`
- **Task:** Add a small type-only consumer fixture that exercises `analyzeRegex`, `scan`, `CharSet`, `Analysis`, `Finding` and `RiskLevel`, then document how contributors can check it.
- **Acceptance:** The fixture uses only TypeScript syntax compatible with the published declarations and adds no runtime dependency.

## Issue 8: Extend production corpus metadata

- **Area:** `tests/production-regexes.test.mjs`, `README.md`
- **Task:** For each production regex fixture, record a short source note explaining where the pattern shape came from and why it is safe or unsafe.
- **Acceptance:** Notes are factual, deterministic and do not copy large upstream files or license-incompatible text.

## Issue 9: Add benchmark output validation

- **Area:** `benchmarks/bench.mjs`, `tests/cli.test.mjs`
- **Task:** Add a small validation mode or test fixture proving benchmark JSON contains the documented fields and never includes absolute paths.
- **Acceptance:** The check runs in milliseconds with a fixed iteration count and does not make CI timing-sensitive.

## Issue 10: Deepen CJS error parity

- **Area:** `tests/parity.test.mjs`
- **Task:** Compare `RegexParseError` and `UnsafeRegexError` properties across ESM and CJS for invalid syntax, unsafe patterns and invalid option input.
- **Acceptance:** Name, message, enumerable fields and stable metadata are asserted independently for both module systems.
