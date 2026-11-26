#!/usr/bin/env node
// regex-shield command line interface.
//
// Exit codes are stable so the tool can gate CI: 0 when every pattern is below
// the threshold, 1 when at least one pattern reaches it, 2 for usage or parse
// errors. Output is deterministic and never includes timings or absolute paths.

import { readFileSync } from 'node:fs';
import process from 'node:process';
import { analyzeRegex, RegexParseError, VERSION } from '../src/index.mjs';

const EXIT_SAFE = 0;
const EXIT_UNSAFE = 1;
const EXIT_USAGE = 2;

const RISK_ORDER = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
const RISK_NAMES = Object.keys(RISK_ORDER);

const HELP = `regex-shield ${VERSION}

Usage:
  regex-shield [options] <pattern> [pattern...]
  regex-shield [options] --stdin

Options:
  --flags <flags>        Flags applied to every pattern string (default: "")
  --threshold <level>    Lowest risk that fails the run: ${RISK_NAMES.join(", ")}
                         (default: medium)
  --json                 Print machine readable JSON instead of text
  --no-witness           Omit witness hints from the report
  --no-broad             Omit the informational broad-unbounded rule
  --stdin                Read one pattern from standard input
  -h, --help             Show this help
  -v, --version          Print the version

Exit codes:
  0  every pattern is below the threshold
  1  at least one pattern reaches the threshold
  2  invalid usage, flags, or pattern syntax

Examples:
  regex-shield '(a+)+$'
  regex-shield --json --flags i '^(\\w|_)+$'
  printf '%s' '(a|aa)+$' | regex-shield --stdin
`;

function fail(message) {
  process.stderr.write(`regex-shield: ${message}\n`);
  process.stderr.write('Run "regex-shield --help" for usage.\n');
  process.exit(EXIT_USAGE);
}

function parseArgs(argv) {
  const options = {
    flags: '',
    threshold: 'medium',
    json: false,
    witnesses: true,
    includeBroad: true,
    stdin: false,
    patterns: []
  };
  let endOfOptions = false;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (endOfOptions || !arg.startsWith('-') || arg === '-') {
      options.patterns.push(arg);
      continue;
    }
    if (arg === '--') {
      endOfOptions = true;
      continue;
    }
    if (arg === '-h' || arg === '--help') {
      process.stdout.write(HELP);
      process.exit(EXIT_SAFE);
    }
    if (arg === '-v' || arg === '--version') {
      process.stdout.write(`${VERSION}\n`);
      process.exit(EXIT_SAFE);
    }
    if (arg === '--json') {
      options.json = true;
      continue;
    }
    if (arg === '--no-witness') {
      options.witnesses = false;
      continue;
    }
    if (arg === '--no-broad') {
      options.includeBroad = false;
      continue;
    }
    if (arg === '--stdin') {
      options.stdin = true;
      continue;
    }
    if (arg === '--flags' || arg === '--threshold') {
      const value = argv[index + 1];
      if (value === undefined) fail(`missing value for ${arg}`);
      index += 1;
      if (arg === '--flags') options.flags = value;
      else options.threshold = value;
      continue;
    }
    if (arg.startsWith('--flags=')) {
      options.flags = arg.slice('--flags='.length);
      continue;
    }
    if (arg.startsWith('--threshold=')) {
      options.threshold = arg.slice('--threshold='.length);
      continue;
    }
    fail(`unknown option "${arg}"`);
  }
  if (!RISK_NAMES.includes(options.threshold)) {
    fail(`invalid threshold "${options.threshold}"`);
  }
  if (options.stdin && options.patterns.length > 0) {
    fail('use either --stdin or positional patterns, not both');
  }
  if (!options.stdin && options.patterns.length === 0) {
    fail('no patterns supplied');
  }
  return options;
}

function formatFinding(finding) {
  const lines = [];
  lines.push(`  ${finding.code} ${finding.severity.padEnd(8)} ${finding.title}`);
  lines.push(`    ${finding.message}`);
  lines.push(`    fix: ${finding.remediation}`);
  return lines.join('\n');
}

function formatText(result) {
  const header = `/${result.pattern}/${result.flags}`;
  const lines = [`${header}  risk: ${result.risk}  score: ${result.score}`];
  if (result.findings.length === 0) {
    lines.push('  no findings');
  } else {
    for (const finding of result.findings) lines.push(formatFinding(finding));
  }
  if (result.witnessHint) lines.push(`  witness hint: ${JSON.stringify(result.witnessHint)}`);
  return lines.join('\n');
}

function jsonPayload(results, threshold, failed) {
  return {
    tool: 'regex-shield',
    version: VERSION,
    threshold,
    safe: !failed,
    results: results.map((entry) => ({
      index: entry.index,
      pattern: entry.analysis.pattern,
      flags: entry.analysis.flags,
      risk: entry.analysis.risk,
      score: entry.analysis.score,
      safe: entry.analysis.safe,
      findings: entry.analysis.findings,
      witnessHint: entry.analysis.witnessHint,
      witnesses: entry.analysis.witnesses,
      complexity: entry.analysis.complexity
    }))
  };
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  let patterns = options.patterns;
  if (options.stdin) {
    patterns = [readFileSync(0, 'utf8').replace(/\r?\n$/, '')];
  }

  const analyzeOptions = {
    flags: options.flags,
    witnesses: options.witnesses,
    includeBroad: options.includeBroad
  };
  const results = [];
  let failed = false;
  let parseFailure = false;
  for (const [index, pattern] of patterns.entries()) {
    try {
      const analysis = analyzeRegex(pattern, analyzeOptions);
      const above = RISK_ORDER[analysis.risk] >= RISK_ORDER[options.threshold];
      if (above) failed = true;
      results.push({ index, analysis, above });
    } catch (error) {
      if (!(error instanceof RegexParseError)) throw error;
      parseFailure = true;
      if (options.json) {
        results.push({ index, error: { name: error.name, message: error.message } });
      } else {
        process.stderr.write(`regex-shield: ${error.message}\n`);
      }
    }
  }

  if (options.json) {
    const payload = jsonPayload(results.filter((entry) => entry.analysis), options.threshold, failed);
    if (parseFailure) {
      payload.parseErrors = results.filter((entry) => entry.error).map((entry) => ({
        index: entry.index,
        ...entry.error
      }));
    }
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  } else {
    for (const entry of results) {
      if (!entry.analysis) continue;
      process.stdout.write(`${formatText(entry.analysis)}\n`);
    }
    const checked = results.filter((entry) => entry.analysis).length;
    process.stdout.write(
      `${checked} pattern${checked === 1 ? '' : 's'} checked, ` +
        `${failed ? 'at least one at or above' : 'all below'} "${options.threshold}"\n`
    );
  }

  if (parseFailure) process.exit(EXIT_USAGE);
  process.exit(failed ? EXIT_UNSAFE : EXIT_SAFE);
}

main();
