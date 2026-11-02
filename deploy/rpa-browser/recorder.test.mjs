// M16-T3: run with `node --test deploy/rpa-browser/recorder.test.mjs`.
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { checkStart, pointOk, selectorFor } from './recorder.mjs';
import { hostAllowed } from './steps.mjs';

test('selectors prefer test ids, ids, names, labels, then text and paths', () => {
  assert.equal(selectorFor({ tag: 'button', testid: 'save', id: 'x' }), '[data-testid="save"]');
  assert.equal(selectorFor({ tag: 'input', id: 'user', name: 'u' }), '#user');
  assert.equal(selectorFor({ tag: 'input', id: '1bad', name: 'user' }), 'input[name="user"]');
  assert.equal(selectorFor({ tag: 'input', ariaLabel: 'Order "no"' }), 'input[aria-label="Order \\"no\\""]');
  assert.equal(selectorFor({ tag: 'button', text: '  Sign\n in ' }), 'button:has-text("Sign in")');
  assert.equal(selectorFor({ tag: 'div', text: 'Sign in', path: 'main > div:nth-of-type(2)' }), 'main > div:nth-of-type(2)');
  assert.equal(selectorFor({ tag: 'a', text: 'x'.repeat(41), path: '#nav > a' }), '#nav > a');
});

test('a recording starts only on an allowed host, and clicks stay in the viewport', () => {
  assert.equal(checkStart({ url: 'https://portal.example.com', allowed_hosts: ['portal.example.com'] }, hostAllowed).ok, true);
  assert.match(checkStart({ url: 'https://evil.example', allowed_hosts: ['portal.example.com'] }, hostAllowed).error, /allowed host/);
  assert.match(checkStart({ url: 'https://portal.example.com', allowed_hosts: [] }, hostAllowed).error, /allowed_hosts/);
  assert.equal(pointOk({ x: 10, y: 10 }), true);
  assert.equal(pointOk({ x: 1280, y: 10 }), false);
  assert.equal(pointOk({ x: '1', y: 2 }), false);
});
