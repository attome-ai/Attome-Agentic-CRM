// C7-T1: the Gmail add-on's synchronous driver, against fake Apps Script
// services: it keeps the session in the user's properties, refreshes it
// before it expires and sends it as a bearer. Run with `npm test` here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');

function world(script) {
  const props = new Map();
  const calls = [];
  const sandbox = {
    Date,
    JSON,
    PropertiesService: {
      getUserProperties: () => ({ getProperty: (k) => props.get(k) ?? null, setProperty: (k, v) => props.set(k, v) }),
    },
    Session: { getActiveUserLocale: () => 'ar' },
    UrlFetchApp: {
      fetch: (url, options) => {
        calls.push({ url, options });
        const [status, body] = script.shift() ?? [500, null];
        return { getResponseCode: () => status, getContentText: () => (body === null ? '' : JSON.stringify(body)) };
      },
    },
  };
  runInNewContext(read('../shared/attome-mail-client.js') + '\n' + read('./Code.js'), sandbox);
  return { sandbox, props, calls };
}

test('a signed-out person gets no request sent', () => {
  const { sandbox, calls } = world([]);
  const answer = sandbox.send_(sandbox.AttomeMail.contactByEmail('a@b.sa'));
  assert.equal(answer.status, 401);
  assert.equal(calls.length, 0);
});

test('the session is refreshed before it expires and sent as a bearer', () => {
  const { sandbox, props, calls } = world([
    [200, { access_token: 'new', refresh_token: 'r2', expires_in: 900 }],
    [200, { data: { records: [] } }],
  ]);
  const now = Math.floor(Date.now() / 1000);
  props.set('attome', JSON.stringify({
    url: 'https://crm', session: { access_token: 'old', refresh_token: 'r1', expires_at: now + 5 },
  }));
  const answer = sandbox.send_(sandbox.AttomeMail.contactByEmail('a@b.sa'));
  assert.equal(answer.status, 200);
  assert.equal(calls[0].url, 'https://crm/api/v1/oauth/device/token');
  assert.equal(calls[0].options.payload.includes('client_id=attome-gmail'), true);
  assert.equal(calls[1].options.headers.Authorization, 'Bearer new');
  assert.equal(JSON.parse(props.get('attome')).session.refresh_token, 'r2');
  assert.equal(sandbox.t_('signIn'), 'تسجيل الدخول إلى أتوم');
});

test('an ended session signs the person out', () => {
  const { sandbox, props } = world([[401, { error: 'invalid_grant' }]]);
  props.set('attome', JSON.stringify({
    url: 'https://crm', session: { access_token: 'old', refresh_token: 'r1', expires_at: 0 },
  }));
  assert.equal(sandbox.session_(), null);
  assert.deepEqual(JSON.parse(props.get('attome')), { url: 'https://crm' });
});
