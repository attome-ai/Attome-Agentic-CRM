// C7-T1: the mail add-ins' shared logic. Run with
//   node --test addins/shared/attome-mail-client.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('./attome-mail-client.js', import.meta.url), 'utf8');
const sandbox = {};
runInNewContext(source + '\nthis.AttomeMail = AttomeMail;', sandbox);
const m = sandbox.AttomeMail;
const plain = (v) => JSON.parse(JSON.stringify(v));

test('speaks Arabic or English with the same keys', () => {
  assert.equal(m.language('ar-SA'), 'ar');
  assert.equal(m.language('en-GB'), 'en');
  assert.deepEqual(Object.keys(m.TEXT.ar).sort(), Object.keys(m.TEXT.en).sort());
  assert.equal(m.t('en', 'logged', { name: 'Acme' }), 'The email is logged on Acme.');
  assert.equal(m.t('ar', 'notFound', { email: 'a@b.sa' }), 'a@b.sa ليس جهة اتصال.');
});

test('a deployment address is https, or http on the machine itself', () => {
  assert.equal(m.normaliseUrl(' https://crm.example.com/ '), 'https://crm.example.com');
  assert.equal(m.normaliseUrl('http://localhost:7865'), 'http://localhost:7865');
  assert.equal(m.normaliseUrl('http://crm.example.com'), null);
  assert.equal(m.normaliseUrl('javascript:alert(1)'), null);
  assert.equal(m.normaliseUrl(''), null);
});

test('the sender address is read from a header', () => {
  assert.equal(m.emailOf('Sara Ali <Sara@Example.SA>'), 'sara@example.sa');
  assert.equal(m.emailOf('omar@example.com'), 'omar@example.com');
  assert.equal(m.emailOf('no address'), null);
});

test('the device grant is asked for, polled and refreshed as forms', () => {
  assert.deepEqual(plain(m.deviceAuthorization('attome-outlook')), {
    method: 'POST', path: '/api/v1/oauth/device_authorization', form: { client_id: 'attome-outlook' },
  });
  const poll = m.pollToken('attome-gmail', 'dev-code');
  assert.equal(poll.form.grant_type, 'urn:ietf:params:oauth:grant-type:device_code');
  assert.equal(m.formBody(poll.form).includes('device_code=dev-code'), true);
  assert.equal(m.refreshToken('attome-gmail', 'r.s').form.grant_type, 'refresh_token');
});

test('a token answer says what to do next', () => {
  const ok = m.readToken(200, { access_token: 'a', refresh_token: 'r', expires_in: 900 }, 1000);
  assert.deepEqual(plain(ok), { state: 'ok', session: { access_token: 'a', refresh_token: 'r', expires_at: 1900 } });
  assert.equal(m.readToken(400, { error: 'authorization_pending' }, 0).state, 'pending');
  assert.equal(m.readToken(400, { error: 'slow_down' }, 0).state, 'slow_down');
  assert.equal(m.readToken(400, { error: 'access_denied' }, 0).state, 'denied');
  assert.equal(m.readToken(400, { error: 'expired_token' }, 0).state, 'expired');
  assert.equal(m.readToken(500, null, 0).state, 'error');
  assert.equal(m.needsRefresh({ expires_at: 2000 }, 1000), false);
  assert.equal(m.needsRefresh({ expires_at: 1030 }, 1000), true);
  assert.equal(m.needsRefresh(null, 0), true);
  assert.equal(m.bearer({ access_token: 'x.y.z' }), 'Bearer x.y.z');
});

test('the sender is looked up by email, and their open work by account', () => {
  const contact = m.contactByEmail('sara@example.sa');
  assert.equal(contact.path, '/api/v1/query/execute');
  assert.deepEqual(plain(contact.json.filters), [{ field: 'email', op: 'eq', value: 'sara@example.sa' }]);
  const deals = m.openOpportunities('acc1');
  assert.equal(deals.json.entity, 'opportunity');
  assert.deepEqual(plain(deals.json.filters[1].value), plain(m.OPEN_STAGES));
  assert.equal(m.openCases('acc1').json.filters[0].field, 'customer_ref');

  const contactRows = m.rows(200, { data: { records: [{ id: 'c1', full_name: 'Sara Ali', account_ref: { id: 'acc1' } }] } });
  const view = m.summary(contactRows, [{ id: 'o1', name: 'Renewal', stage: 'proposal' }], m.rows(404, null));
  assert.deepEqual(plain(view), {
    found: true,
    contact: { id: 'c1', name: 'Sara Ali', title: '' },
    accountId: 'acc1',
    opportunities: [{ id: 'o1', name: 'Renewal', stage: 'proposal' }],
    cases: [],
  });
  assert.deepEqual(plain(m.summary([], [], [])), { found: false });
});

test('an email is logged as a communication on the record', () => {
  const request = m.logEmail('contact', 'c1', {
    subject: 'Quote', body: 'x'.repeat(25000), to: ['a@b.sa', 'c@d.sa'],
    sentAt: '2026-10-30T10:00:00Z', messageId: '<m1@mail>',
  });
  assert.equal(request.path, '/api/v1/communication');
  assert.equal(request.json.channel, 'email');
  assert.equal(request.json.entity_name, 'contact');
  assert.equal(request.json.record_id, 'c1');
  assert.equal(request.json.body.length, 20000);
  assert.equal(request.json.to_addresses, 'a@b.sa, c@d.sa');
  assert.equal(request.json.message_id, '<m1@mail>');
});

test('a lead, a case and the reply templates', () => {
  assert.deepEqual(plain(m.createLead('', 'new@x.sa', 'X Co').json), {
    name: 'new@x.sa', email: 'new@x.sa', company_name: 'X Co', source: 'email',
  });
  assert.equal(m.createCase('Broken', 'It broke', 'acc1').json.customer_ref, 'acc1');
  const templates = m.replyTemplates('contact', 'c1');
  assert.equal(m.urlOf('https://a', templates), 'https://a/api/v1/model/reply-suggestions?entity=contact&record_id=c1&channel=email');
  assert.deepEqual(plain(m.templates(200, { items: [{ id: 't1', name: 'Thanks', reply: 'Thank you', score: 1 }] })), [
    { id: 't1', name: 'Thanks', reply: 'Thank you' },
  ]);
  assert.deepEqual(plain(m.templates(403, {})), []);
});
