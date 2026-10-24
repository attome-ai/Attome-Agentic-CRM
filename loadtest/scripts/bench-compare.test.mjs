// AA1-T9: `node --test loadtest/scripts/bench-compare.test.mjs`
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { compare } from './bench-compare.mjs';
import { buildReport, parseSummary } from './latency-report.mjs';

const fixture = JSON.parse(
  readFileSync(new URL('./fixtures/production_mix-solo-c1-primary.json', import.meta.url), 'utf8'),
);

test('puts the customer next to the published numbers', () => {
  const ops = parseSummary(fixture);
  const published = buildReport([{ level: 1, target: 'primary', ops }], null, { version: '1.0.0', profile: 'solo' }).data;
  // The customer's read p95 is twice the published one.
  const mine = { ...ops, read: { ...ops.read, p95: ops.read.p95 * 2 } };
  const { table, text } = compare([{ level: 1, ops: mine }], published);
  const read = table.find((r) => r.op === 'read');
  assert.equal(read.ratio, 2);
  assert.equal(read.published.p95, 21.5);
  assert.match(text, /\| 1 \| read \| 8\.2 \| 43\.0 \| 40\.1 \| 8\.2 \| 21\.5 \| 40\.1 \| 2\.00x \|/);
  assert.match(text, /Published: 1\.0\.0 \(solo\)/);
});

test('a level the published report lacks shows dashes', () => {
  const ops = parseSummary(fixture);
  const { table, text } = compare([{ level: 10, ops }], { version: '1.0.0', rows: [] });
  assert.ok(table.every((r) => r.ratio === null && r.published === null));
  assert.match(text, /\| 10 \| read \| 8\.2 \| 21\.5 \| 40\.1 \| — \| — \| — \| — \|/);
});
