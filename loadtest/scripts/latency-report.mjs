#!/usr/bin/env node
// AA1-T8: the per-release latency report. Reads the production mix's k6
// summaries (run-matrix.ps1 writes results/production_mix-<profile>-c<N>-<target>.json),
// tabulates p50/p95/p99 per operation class and concurrency, puts the previous
// release's numbers beside them and marks a p95 more than 10% slower in bold.
//
//   node loadtest/scripts/latency-report.mjs --version 1.4.0 --profile solo \
//     [--results loadtest/results] [--previous docs/evidence/latency-1.3.0.json] \
//     [--method "warm, primary"] [--machine "what ran the load"] [--dry-run]
//
// Without --dry-run it writes docs/evidence/latency-<version>.md and .json;
// the .json is the next release's --previous. The numbers are the machine's
// they ran on, which the header names: a dev box is not a reference machine.

import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { cpus, totalmem, type as osType, release as osRelease } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The production mix's operation classes, in report order. */
export const OPS = ['read', 'list', 'query', 'write', 'search', 'bulk'];
/** A p95 this much slower than the previous release's is a regression. */
export const REGRESSION_PCT = 10;
const FILE = /^production_mix-([a-z0-9_]+)-c(\d+)-(primary|replica)\.json$/;

/** One class's percentiles from a k6 summary export, flat
 * (`metrics[key]['p(95)']`) or nested (`metrics[key].values['p(95)']`). */
function trend(metrics, op) {
  const entry = metrics[`http_req_duration{op:${op},phase:measure}`] ?? metrics[`http_req_duration{op:${op}}`];
  if (!entry) return null;
  const values = entry.values ?? entry;
  const pick = (k) => (typeof values[k] === 'number' ? values[k] : null);
  const p50 = pick('p(50)') ?? pick('med');
  const p95 = pick('p(95)');
  const p99 = pick('p(99)');
  return p50 === null && p95 === null && p99 === null ? null : { p50, p95, p99 };
}

/** The classes a k6 summary measured: `{ read: {p50, p95, p99}, ... }`. */
export function parseSummary(summary) {
  const metrics = summary?.metrics ?? {};
  const out = {};
  for (const op of OPS) {
    const t = trend(metrics, op);
    if (t) out[op] = t;
  }
  return out;
}

const ms = (v) => (v === null || v === undefined ? '—' : `${v.toFixed(1)}`);

/**
 * The report for `summaries` (`[{ level, target, ops }]`) beside `previous`
 * (an earlier report's data, or null). `meta` carries the header facts.
 * Pure: returns `{ markdown, data }`.
 */
export function buildReport(summaries, previous, meta = {}) {
  const rows = [];
  for (const s of [...summaries].sort((a, b) => a.level - b.level || a.target.localeCompare(b.target))) {
    for (const op of OPS) {
      const t = s.ops[op];
      if (t) rows.push({ op, level: s.level, target: s.target, ...t });
    }
  }
  const before = new Map((previous?.rows ?? []).map((r) => [`${r.op}/${r.level}/${r.target}`, r]));
  const data = {
    format: 'attome-latency/v1',
    version: meta.version ?? null,
    profile: meta.profile ?? null,
    generated_at: meta.date ?? new Date().toISOString(),
    commit: meta.commit ?? null,
    machine: meta.machine ?? null,
    ran_on: meta.ranOn ?? null,
    dataset: meta.dataset ?? null,
    method: meta.method ?? null,
    previous_version: previous?.version ?? null,
    rows,
  };

  const lines = [];
  lines.push(`# Latency, ${data.version ?? 'unversioned'} (${data.profile ?? 'unknown profile'})`, '');
  lines.push(`- Date: ${data.generated_at}`);
  lines.push(`- Commit: ${data.commit ?? 'unknown'}`);
  lines.push(`- Ran on: ${data.ran_on ?? 'not recorded'} (the numbers are this machine's)`);
  lines.push(`- Reference machine for the profile: ${data.machine ?? 'not recorded'}`);
  lines.push(`- Data set: ${data.dataset ?? 'not recorded'}`);
  lines.push(`- Method: ${data.method ?? 'not recorded'}`);
  lines.push(`- Compared with: ${data.previous_version ?? 'no previous report'}`, '');
  const groups = new Map();
  for (const r of rows) {
    const key = `${r.level}/${r.target}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }
  for (const [key, group] of groups) {
    const [level, target] = key.split('/');
    lines.push(`## Concurrency ${level}, ${target}`, '');
    lines.push('| Class | p50 ms | p95 ms | p99 ms | Previous p95 ms | Change ms | Change % |');
    lines.push('|---|---:|---:|---:|---:|---:|---:|');
    for (const r of group) {
      const prev = before.get(`${r.op}/${r.level}/${r.target}`);
      let prevCell = '—';
      let delta = '—';
      let pct = '—';
      if (prev && typeof prev.p95 === 'number' && typeof r.p95 === 'number') {
        const d = r.p95 - prev.p95;
        const p = prev.p95 === 0 ? 0 : (d / prev.p95) * 100;
        prevCell = ms(prev.p95);
        delta = `${d >= 0 ? '+' : ''}${d.toFixed(1)}`;
        pct = `${p >= 0 ? '+' : ''}${p.toFixed(1)}%`;
        if (p > REGRESSION_PCT) {
          delta = `**${delta}**`;
          pct = `**${pct}**`;
        }
      }
      lines.push(`| ${r.op} | ${ms(r.p50)} | ${ms(r.p95)} | ${ms(r.p99)} | ${prevCell} | ${delta} | ${pct} |`);
    }
    lines.push('');
  }
  if (rows.length === 0) lines.push('No production-mix summaries were found.', '');
  return { markdown: lines.join('\n'), data };
}

function args(argv) {
  const out = { results: 'loadtest/results', dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--version') out.version = next();
    else if (a === '--profile') out.profile = next();
    else if (a === '--results') out.results = next();
    else if (a === '--previous') out.previous = next();
    else if (a === '--method') out.method = next();
    else if (a === '--machine') out.machine = next();
    else if (a === '--dry-run') out.dryRun = true;
    else throw new Error(`unknown argument ${a}`);
  }
  if (!out.version || !out.profile) throw new Error('--version and --profile are required');
  return out;
}

/** The machine this script runs on, as the load test's results came from
 * it unless --machine says otherwise. */
function thisMachine() {
  const cores = cpus();
  const gb = Math.round(totalmem() / 2 ** 30);
  return `${cores.length} x ${cores[0]?.model?.trim() ?? 'unknown CPU'}, ${gb} GB RAM, ${osType()} ${osRelease()}`;
}

function main() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const opts = args(process.argv.slice(2));
  const dir = resolve(root, opts.results);
  const summaries = readdirSync(dir)
    .map((name) => ({ name, m: FILE.exec(name) }))
    .filter(({ m }) => m && m[1] === opts.profile)
    .map(({ name, m }) => ({
      level: Number(m[2]),
      target: m[3],
      ops: parseSummary(JSON.parse(readFileSync(join(dir, name), 'utf8'))),
    }));
  const profiles = JSON.parse(readFileSync(join(root, 'loadtest', 'profiles.json'), 'utf8'));
  const seedPath = join(dir, `seed-${opts.profile}.json`);
  const seed = existsSync(seedPath) ? JSON.parse(readFileSync(seedPath, 'utf8').replace(/^﻿/, '')) : null;
  let commit = null;
  try {
    commit = execSync('git rev-parse --short HEAD', { cwd: root, stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .trim();
  } catch {
    commit = null;
  }
  const dataset = seed
    ? Object.entries(seed.counts ?? {})
        .map(([entity, n]) => `${entity} ${n}`)
        .concat([`${seed.users ?? '?'} users`, `${seed.roles ?? '?'} roles`])
        .join(', ')
    : `${profiles[opts.profile]?.records_per_entity ?? '?'} records per entity (profiles.json; no seed summary)`;
  const previous = opts.previous ? JSON.parse(readFileSync(resolve(root, opts.previous), 'utf8')) : null;
  const { markdown, data } = buildReport(summaries, previous, {
    version: opts.version,
    profile: opts.profile,
    commit,
    machine: profiles[opts.profile]?.machine ?? null,
    ranOn: opts.machine ?? thisMachine(),
    dataset,
    method: opts.method ?? `${summaries.some((s) => s.target === 'replica') ? 'replica' : 'primary'}, warm (30 s warm-up excluded)`,
  });
  if (opts.dryRun) {
    process.stdout.write(`${markdown}\n`);
    return;
  }
  const out = join(root, 'docs', 'evidence');
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, `latency-${opts.version}.md`), `${markdown}\n`);
  writeFileSync(join(out, `latency-${opts.version}.json`), `${JSON.stringify(data, null, 2)}\n`);
  process.stdout.write(`wrote docs/evidence/latency-${opts.version}.md and .json\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`latency-report: ${error.message}\n`);
    process.exit(1);
  }
}
