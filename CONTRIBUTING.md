# Contributing to regex-shield

Thanks for helping make regular expressions safer. The project is intentionally
small: a parser, a character set algebra, the analyzer, a witness generator, and
two entry points. Please keep changes inside that shape.

## Ground rules

- Zero runtime and development dependencies. Use the Node standard library.
- ESM sources in `src/` are the single source of truth. Never edit
  `cjs/index.cjs` by hand.
- Tests must be deterministic. No network, no wall clock assertions, no random
  inputs, no absolute paths or personal data in the repository.
- Keep the public API backward compatible within a major version.
- Every finding must map to CWE-1333 and to exactly one rule identifier.

## Development

Node 18 or later is required. There is nothing to install.

```sh
git clone https://github.com/draarivpatel-ui/regex-shield.git
cd regex-shield
npm test
```

Useful commands:

```sh
npm test                  # node --test tests/
npm run test:coverage     # coverage report from the built in runner
npm run build:cjs         # regenerate cjs/index.cjs from src/
npm run check:cjs         # verify the committed CJS artifact is current
npm run bench             # analyzer throughput
node bin/regex-shield.mjs '(a+)+$'
```

## Changing a rule

1. Add or update the rule in `src/analyzer.mjs`.
2. Add at least one positive case and one negative case in
   `tests/analyzer.test.mjs`.
3. If the rule belongs to the historical corpus, update
   `tests/cve-corpus.test.mjs` with the source pattern and its provenance.
4. Run `npm run build:cjs` so the CommonJS artifact matches.
5. Run `npm test` and `npm run check:cjs`.

New rules need a stable `RSxxx` code, a title, a remediation string, a sample
character, and a failing terminator so the witness generator can build a hint.

## Parser changes

The parser must accept everything the platform `RegExp` constructor accepts,
including Annex B forms such as literal braces, legacy octal escapes, and the
literal hyphen beside a class escape. Add a parser test for every syntax change
and keep `index` and `end` positions exact.

## Pull request checklist

- [ ] `npm test` passes
- [ ] `npm run check:cjs` reports the artifact is up to date
- [ ] New behaviour has a positive and a negative test
- [ ] README rule table and test count are current
- [ ] No dependency was added
- [ ] No personal paths, secrets, or em dashes in shipped files

## Release checklist

Maintainers only:

1. Update `VERSION` in `src/index.mjs` and `version` in `package.json`.
2. Run `npm run build:cjs` after the version bump.
3. Run the full suite and the benchmark smoke run.
4. Commit, tag, and publish from a clean checkout.
