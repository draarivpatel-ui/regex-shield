// Throughput benchmark for the analyzer.
//
// The goal is a stable order of magnitude, not a micro benchmark: every pattern
// is parsed and analysed from scratch, which is the cost paid by a linter or a
// CI gate. Run with "npm run bench" and pass --json for machine readable output.

import { performance } from 'node:perf_hooks';
import process from 'node:process';

import { analyzeRegex } from '../src/index.mjs';

const CORPUS = [
  ['literal', '^hello world$'],
  ['email', '^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$'],
  ['url', '^(https?):\\/\\/([^:\\/\\s]+)(?::(\\d+))?(\\/[^\\s]*)?$'],
  ['uuid', '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'],
  ['semver', '^v?(\\d+)\\.(\\d+)\\.(\\d+)(?:-([0-9A-Za-z.-]+))?$'],
  ['base64', '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'],
  ['nested', '(a+)+$'],
  ['nullable', '(?:a*)*$'],
  ['alternation', '^(a|aa)+$'],
  ['adjacent', '\\d+\\d+$'],
  ['wildcards', '.*.*.*$'],
  ['backreference', '(?:(\\w)\\1)+$'],
  ['lookaround', '(?:(?=a+)\\w)+$'],
  ['ansi-regex', '[\\u001B\\u009B][[\\]()#;?]*(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~])'],
  ['cve path parse', '^([\\s\\S]*?)((?:\\.{1,2}|[^\\\\\\/]+?|)(\\.[^.\\/\\\\]*|))(?:[\\\\\\/]*)$']
];

function parseArgs(argv) {
  const options = { iterations: 2000, json: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--json') options.json = true;
    else if (arg === '--iterations') {
      options.iterations = Number(argv[index + 1]);
      index += 1;
    } else if (arg === '--help') {
      process.stdout.write('Usage: node benchmarks/bench.mjs [--json] [--iterations N]\n');
      process.exit(0);
    } else {
      process.stderr.write(`unknown argument: ${arg}\n`);
      process.exit(2);
    }
  }
  if (!Number.isInteger(options.iterations) || options.iterations < 1) {
    process.stderr.write('iterations must be a positive integer\n');
    process.exit(2);
  }
  return options;
}

const options = parseArgs(process.argv.slice(2));
const rows = [];

for (const [name, pattern] of CORPUS) {
  analyzeRegex(pattern);
  const start = performance.now();
  for (let index = 0; index < options.iterations; index += 1) analyzeRegex(pattern);
  const elapsed = performance.now() - start;
  const opsPerSecond = Math.round((options.iterations / elapsed) * 1000);
  rows.push({
    name,
    pattern,
    iterations: options.iterations,
    milliseconds: Number(elapsed.toFixed(3)),
    opsPerSecond
  });
}

if (options.json) {
  process.stdout.write(`${JSON.stringify({ tool: 'regex-shield-bench', iterations: options.iterations, rows }, null, 2)}\n`);
} else {
  const width = Math.max(...rows.map((row) => row.name.length));
  process.stdout.write(`regex-shield analyzer benchmark (${options.iterations} iterations per pattern)\n\n`);
  for (const row of rows) {
    process.stdout.write(`${row.name.padEnd(width)}  ${String(row.opsPerSecond).padStart(9)} ops/s  ${row.milliseconds} ms\n`);
  }
}
