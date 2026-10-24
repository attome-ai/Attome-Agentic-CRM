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

// AA1-T10: two releases' summaries, side by side.
const at = (p95) => ({ level: 1, target: 'primary', ops: { read: { p50: 1, p95, p99: p95 * 2 } } });

test('adds delta column against previous', () => {
  const previous = buildReport([at(20)], null, { version: '1.0.0' }).data;
  const report = buildReport([at(23)], previous, { version: '1.1.0' });
  // 20 ms to 23 ms at p95: +3.0 ms, +15.0%.
  assert.match(report.markdown, /\| read \| 1\.0 \| 23\.0 \| 46\.0 \| 20\.0 \| \*\*\+3\.0\*\* \| \*\*\+15\.0%\*\* \|/);
  assert.equal(report.data.previous_version, '1.0.0');
});

test('bolds regressions above 10 percent', () => {
  const previous = buildReport([at(100)], null, { version: '1.0.0' }).data;
  const slower = buildReport([at(115)], previous, { version: '1.1.0' }).markdown;
  const slightly = buildReport([at(105)], previous, { version: '1.1.0' }).markdown;
  const faster = buildReport([at(80)], previous, { version: '1.1.0' }).markdown;
  assert.match(slower, /\*\*\+15\.0%\*\*/);
  assert.match(slightly, /\| \+5\.0 \| \+5\.0% \|/);
  assert.doesNotMatch(slightly, /\*\*/);
  assert.match(faster, /\| -20\.0 \| -20\.0% \|/);
  assert.doesNotMatch(faster, /\*\*/);
});
