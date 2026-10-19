// J9-T1: the co-browse script's pure parts. Run with
//   node --test web/scripts/cobrowse-embed.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../public/embed/cobrowse.js', import.meta.url), 'utf8');
const window = {};
// No document: the script defines its helpers and stops before touching a page.
runInNewContext(source, { window });
const cb = window.AttomeCobrowse;

test('speaks Arabic or English and runs Arabic right to left', () => {
  assert.equal(cb.language('ar'), 'ar');
  assert.equal(cb.language('de-DE'), 'en');
  assert.equal(cb.isRtl('ar'), true);
  assert.equal(cb.isRtl('en'), false);
});

test('takes the six-digit code however it is typed', () => {
  assert.equal(cb.cleanCode(' 123 456 '), '123456');
  assert.equal(cb.cleanCode('123-456'), '123456');
  assert.equal(cb.cleanCode('12345'), null);
  assert.equal(cb.cleanCode('abcdef'), null);
});

test('never sends marked, password, card, one-time-code or national-id fields', () => {
  assert.equal(cb.isSensitive({ mask: true }), true);
  assert.equal(cb.isSensitive({ type: 'password' }), true);
  assert.equal(cb.isSensitive({ autocomplete: 'cc-number' }), true);
  assert.equal(cb.isSensitive({ autocomplete: 'one-time-code' }), true);
  assert.equal(cb.isSensitive({ name: 'national_id' }), true);
  assert.equal(cb.isSensitive({ type: 'text', name: 'city' }), false);
  assert.equal(cb.isSensitive(null), false);
});

test('a frame over the channel limit is refused', () => {
  assert.equal(cb.fits({ kind: 'scroll', payload: { x: 0, y: 10 } }), true);
  assert.equal(cb.fits({ kind: 'snapshot', payload: { html: 'x'.repeat(300 * 1024) } }), false);
});

test("the agent's pointer lands inside this viewport", () => {
  // Objects from the script's own context: compare their JSON.
  const at = (p) => JSON.stringify(cb.pointerPosition(p, 1000, 800));
  assert.equal(at({ x: 0.5, y: 0.25 }), JSON.stringify({ left: 500, top: 200 }));
  assert.equal(at({ x: 2, y: -1 }), JSON.stringify({ left: 1000, top: 0 }));
  assert.equal(cb.pointerPosition({ x: 'a' }, 1000, 800), null);
});

test('the read cursor moves to the newest frame', () => {
  assert.equal(cb.lastId([{ id: 'a' }, { id: 'b' }], null), 'b');
  assert.equal(cb.lastId([], 'a'), 'a');
});
