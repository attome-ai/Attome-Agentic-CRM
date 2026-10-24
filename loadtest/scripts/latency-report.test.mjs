// AA1-T8: `node --test loadtest/scripts/latency-report.test.mjs`
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { buildReport, parseSummary } from './latency-report.mjs';

const fixture = JSON.parse(
  readFileSync(new URL('./fixtures/production_mix-solo-c1-primary.json', import.meta.url), 'utf8'),
);

test('a k6 summary gives each class its percentiles', () => {
  const ops = parseSummary(fixture);
  assert.deepEqual(Object.keys(ops), ['read', 'list', 'query', 'write', 'search', 'bulk']);
  assert.equal(ops.read.p95, 21.5);
  // The nested shape older k6 versions write reads the same.
  const nested = parseSummary({ metrics: { 'http_req_duration{op:read,phase:measure}': { values: { 'p(50)': 1, 'p(95)': 2, 'p(99)': 3 } } } });
  assert.deepEqual(nested.read, { p50: 1, p95: 2, p99: 3 });
});

test('the report compares with the previous release and marks a regression', () => {
  const summaries = [{ level: 1, target: 'primary', ops: parseSummary(fixture) }];
  const first = buildReport(summaries, null, { version: '1.0.0', profile: 'solo', machine: 'reference', ranOn: 'test box' });
  assert.match(first.markdown, /\| read \| 8\.2 \| 21\.5 \| 40\.1 \| — \|/);
  assert.match(first.markdown, /Ran on: test box/);
  assert.match(first.markdown, /Reference machine for the profile: reference/);
  const slower = structuredClone(first.data);
  const previous = { ...slower, version: '0.9.0', rows: slower.rows.map((r) => ({ ...r, p95: r.op === 'list' ? 30 : r.p95 })) };
  const second = buildReport(summaries, previous, { version: '1.0.0', profile: 'solo' });
  // list went from 30 ms to 38.2 ms at p95: +27%, a regression, in bold.
  assert.match(second.markdown, /\| list \| 14\.0 \| 38\.2 \| 70\.9 \| 30\.0 \| \*\*\+8\.2\*\* \| \*\*\+27\.3%\*\* \|/);
  assert.match(second.markdown, /\| read \| 8\.2 \| 21\.5 \| 40\.1 \| 21\.5 \| \+0\.0 \| \+0\.0% \|/);
  assert.match(second.markdown, /Compared with: 0\.9\.0/);
});
