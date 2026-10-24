#!/usr/bin/env node
// AA1-T9: the comparison half of the customer-run bench (`bench.ps1`,
// `bench.sh`). Reads the k6 summaries the bench wrote, one per concurrency
// level, and prints the customer's p50/p95/p99 per operation class next to
// the published numbers (`latency-<version>.json`, written by
// `latency-report.mjs`).
//
//   node loadtest/scripts/bench-compare.mjs --published docs/evidence/latency-1.0.0.json \
//     --summary 1=results/bench-c1.json --summary 10=results/bench-c10.json
//
// Without --published it prints the customer's numbers alone.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseSummary } from './latency-report.mjs';

const OPS = ['read', 'list', 'query', 'write', 'search', 'bulk'];

const cell = (v) => (typeof v === 'number' ? v.toFixed(1) : '—');

/**
 * The comparison table. `runs` is `[{ level, ops }]` with `ops` from
 * `parseSummary`; `published` is a `latency-report.mjs` JSON document or
 * null. A published row matches on class and concurrency level; when the
 * published report has several targets for a level, the `primary` one is
 * used. Pure.
 */
export function compare(runs, published) {
  const rows = published?.rows ?? [];
  const find = (op, level) =>
    rows.find((r) => r.op === op && r.level === level && r.target === 'primary') ??
    rows.find((r) => r.op === op && r.level === level) ??
    null;
  const lines = [];
  lines.push(`Published: ${published ? `${published.version ?? 'unversioned'} (${published.profile ?? 'unknown profile'})` : 'none given'}`);
  lines.push('');
  lines.push('| Concurrency | Class | Your p50 | Your p95 | Your p99 | Published p50 | Published p95 | Published p99 | p95 vs published |');
  lines.push('|---:|---|---:|---:|---:|---:|---:|---:|---:|');
  const table = [];
  for (const run of [...runs].sort((a, b) => a.level - b.level)) {
    for (const op of OPS) {
      const mine = run.ops[op];
      if (!mine) continue;
      const theirs = find(op, run.level);
      let ratio = null;
      if (theirs && typeof theirs.p95 === 'number' && theirs.p95 > 0 && typeof mine.p95 === 'number') {
        ratio = mine.p95 / theirs.p95;
      }
      table.push({ level: run.level, op, mine, published: theirs, ratio });
      lines.push(
        `| ${run.level} | ${op} | ${cell(mine.p50)} | ${cell(mine.p95)} | ${cell(mine.p99)} | ` +
          `${cell(theirs?.p50)} | ${cell(theirs?.p95)} | ${cell(theirs?.p99)} | ` +
          `${ratio === null ? '—' : `${ratio.toFixed(2)}x`} |`,
      );
    }
  }
  lines.push('');
  lines.push('Times are milliseconds. Above 1.00x your hardware is slower than the published machine for that class.');
  return { table, text: lines.join('\n') };
}

function parseArgs(argv) {
  const out = { published: null, summaries: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--published') out.published = argv[++i];
    else if (a === '--summary') {
      const [level, file] = argv[++i].split('=');
      out.summaries.push({ level: Number(level), file });
    } else throw new Error(`unknown argument: ${a}`);
  }
  return out;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = parseArgs(process.argv.slice(2));
  if (args.summaries.length === 0) {
    console.error('bench-compare: pass at least one --summary <level>=<file>');
    process.exit(2);
  }
  const runs = args.summaries.map((s) => ({
    level: s.level,
    ops: parseSummary(JSON.parse(readFileSync(s.file, 'utf8'))),
  }));
  const published = args.published ? JSON.parse(readFileSync(args.published, 'utf8')) : null;
  console.log(compare(runs, published).text);
}
