# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |

The package has no runtime dependencies and no network code. Security fixes are
released as patch versions on the latest minor line.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. [Report a vulnerability privately through GitHub](https://github.com/draarivpatel-ui/regex-shield/security/advisories/new).

Please include:

- A minimal reproduction that uses synthetic input only.
- The affected project version, commit or action ref, and Node.js version.
- The expected security boundary and the observed violation.
- Logs, output, or proof-of-concept code needed to reproduce the finding, with real secrets removed.

Never include a real token, cookie, password, private key, production log line or real personal data in a report.

Vulnerability handling steps:

1. The maintainer acknowledges the private report within 72 hours.
2. The maintainer reproduces the finding against the latest supported version and confirms severity within 14 days when enough information is available.
3. A fix is developed privately, with regression coverage where practical.
4. The maintainer coordinates the advisory, affected versions, reporter credit and disclosure date with the reporter.
5. The target coordinated disclosure window is 90 days or less from acknowledgment. If more time is needed, the maintainer and reporter agree on a new date before disclosure.

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

The package must stay dependency free in `dependencies`. Any proposal that adds
a runtime dependency is rejected. Build tooling relies on the Node standard
library; fast-check is development-only fuzz tooling and is never imported by
shipped library code.
