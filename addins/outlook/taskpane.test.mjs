// C7-T1: the Outlook task pane's driver: it signs in with the device grant,
// keeps the session in the add-in's storage, sends it as a bearer and
// refreshes it before it expires. Run with `npm test` here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const sandbox = { Date, JSON, Promise };
runInNewContext(
  read('../shared/attome-mail-client.js') + '\n' + read('./taskpane.js') +
    '\nthis.AttomeMail = AttomeMail; this.AttomeOutlook = AttomeOutlook;',
  sandbox,
);
const { AttomeOutlook, AttomeMail } = sandbox;

function memoryStorage() {
  const items = new Map();
  return { getItem: (k) => items.get(k) ?? null, setItem: (k, v) => items.set(k, String(v)), items };
}

/** A fetch answering from `script` (a list of `[status, body]`), recording calls. */
function fakeFetch(script) {
  const calls = [];
  const fn = (url, init) => {
    calls.push({ url, init });
    const [status, body] = script.shift() ?? [500, null];
    return Promise.resolve({ status, text: () => Promise.resolve(body === null ? '' : JSON.stringify(body)) });
  };
  fn.calls = calls;
  return fn;
}

test('signs in with the device grant and sends the session as a bearer', async () => {
  const storage = memoryStorage();
  const now = Math.floor(Date.now() / 1000);
  const fetch = fakeFetch([
    [200, { device_code: 'dc', user_code: 'BCDF-GHJK', verification_uri: 'https://crm/xrm/device', interval: 5 }],
    [400, { error: 'authorization_pending' }],
    [200, { access_token: 'a.b.c', refresh_token: 'r1', expires_in: 900 }],
    [200, { data: { records: [{ id: 'c1', full_name: 'Sara' }] } }],
  ]);
  const api = AttomeOutlook.driver(fetch, storage);
  assert.equal(api.signedIn(), false);
  const grant = await api.start('https://crm');
  assert.equal(grant.body.user_code, 'BCDF-GHJK');
  assert.equal(fetch.calls[0].url, 'https://crm/api/v1/oauth/device_authorization');
  assert.equal(fetch.calls[0].init.body, 'client_id=attome-outlook');
  assert.equal((await api.poll('dc')).state, 'pending');
  assert.equal((await api.poll('dc')).state, 'ok');
  assert.equal(api.signedIn(), true);
  const saved = JSON.parse(storage.getItem('attome.outlook'));
  assert.equal(saved.session.refresh_token, 'r1');
  assert.ok(saved.session.expires_at >= now + 899);

  const answer = await api.send(AttomeMail.contactByEmail('sara@x.sa'));
  assert.equal(answer.status, 200);
  const call = fetch.calls[3];
  assert.equal(call.url, 'https://crm/api/v1/query/execute');
  assert.equal(call.init.headers.Authorization, 'Bearer a.b.c');
  assert.equal(JSON.parse(call.init.body).entity, 'contact');
});

test('refreshes a session about to expire, and forgets one that has ended', async () => {
  const storage = memoryStorage();
  const now = Math.floor(Date.now() / 1000);
  storage.setItem('attome.outlook', JSON.stringify({
    url: 'https://crm', session: { access_token: 'old', refresh_token: 'r1', expires_at: now + 10 },
  }));
  const fetch = fakeFetch([
    [200, { access_token: 'new', refresh_token: 'r2', expires_in: 900 }],
    [200, { items: [] }],
    [401, { error: 'invalid_grant' }],
  ]);
  const api = AttomeOutlook.driver(fetch, storage);
  await api.send(AttomeMail.replyTemplates('contact', 'c1'));
  assert.equal(fetch.calls[0].init.body.includes('grant_type=refresh_token'), true);
  assert.equal(fetch.calls[1].init.headers.Authorization, 'Bearer new');
  assert.equal(JSON.parse(storage.getItem('attome.outlook')).session.refresh_token, 'r2');

  storage.setItem('attome.outlook', JSON.stringify({
    url: 'https://crm', session: { access_token: 'new', refresh_token: 'r2', expires_at: now },
  }));
  const answer = await api.send(AttomeMail.contactByEmail('a@b.sa'));
  assert.equal(answer.status, 401, 'signed out: the pane shows the sign-in again');
  assert.equal(api.signedIn(), false);
  api.signOut();
  assert.equal(JSON.parse(storage.getItem('attome.outlook')).url, 'https://crm');
});
