# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |

The package has no runtime dependencies and no network code. Security fixes are
released as patch versions on the latest minor line.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the GitHub private
vulnerability reporting flow:

1. Open the repository Security tab.
2. Select "Report a vulnerability", or open
   https://github.com/draarivpatel-ui/regex-shield/security/advisories/new
   directly.
3. Include the pattern, the flags, the observed analysis, and the expected
   analysis.

A maintainer will acknowledge the report, reproduce it with the current test
suite, and coordinate a release. Please allow up to 90 days for disclosure.

## Scope

In scope:

- A pattern that `analyzeRegex` reports as safe while it is structurally
  vulnerable to catastrophic backtracking, with a minimal reproduction.
- A false positive that blocks a common, safe production pattern.
- Parser crashes, hangs, or incorrect AST positions on valid JavaScript regex
  syntax.
- CLI exit code or JSON output defects.

Out of scope:

- Runtime execution of a regex against a hostile input. This package is a static
  analyzer and never runs the pattern.
- Patterns whose cost depends on a specific engine implementation rather than
  the structure of the pattern.
- Denial of service caused by passing extremely large pattern strings to the
  parser itself.

## Dependency policy

The package must stay dependency free in `dependencies` and `devDependencies`.
Any proposal that adds a runtime dependency is rejected. Build and test tooling
must rely on the Node standard library.
