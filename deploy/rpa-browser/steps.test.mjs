// M16-T1: run with `node --test deploy/rpa-browser/steps.test.mjs`.
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { MAX_STEPS, checkRun, hostAllowed } from './steps.mjs';

test('hosts: exact names, dot-prefixed subdomains, http(s) only', () => {
  assert.equal(hostAllowed('https://portal.example.com/a', ['portal.example.com']), true);
  assert.equal(hostAllowed('https://evil.com/?portal.example.com', ['portal.example.com']), false);
  assert.equal(hostAllowed('https://a.b.example.com', ['.example.com']), true);
  assert.equal(hostAllowed('https://example.com', ['.example.com']), true);
  assert.equal(hostAllowed('https://notexample.com', ['.example.com']), false);
  assert.equal(hostAllowed('file:///etc/passwd', ['localhost']), false);
  assert.equal(hostAllowed('not a url', ['x']), false);
});

test('a valid run passes; bad ones say why', () => {
  const run = {
    allowed_hosts: ['portal.example.com'],
    steps: [
      { kind: 'goto', url: 'https://portal.example.com/login' },
      { kind: 'fill', selector: '#user', value: 'me' },
      { kind: 'click', selector: 'button[type=submit]' },
      { kind: 'text', selector: '.balance' },
      { kind: 'screenshot' },
    ],
  };
  assert.equal(checkRun(run).ok, true);
  assert.match(checkRun({ ...run, allowed_hosts: [] }).error, /allowed_hosts/);
  assert.match(checkRun({ ...run, steps: [{ kind: 'goto', url: 'https://other.com' }] }).error, /not on an allowed host/);
  assert.match(checkRun({ ...run, steps: [{ kind: 'fill', selector: '#x' }] }).error, /needs value/);
  assert.match(checkRun({ ...run, steps: [{ kind: 'eval', code: '1' }] }).error, /kind is one of/);
  assert.match(checkRun({ ...run, steps: Array(MAX_STEPS + 1).fill({ kind: 'screenshot' }) }).error, /1 to/);
  assert.match(checkRun({ ...run, timeout_ms: 10 }).error, /timeout_ms/);
});
