// J3-T2: the embeddable chat widget's pure parts. Run with
//   node --test web/scripts/webchat-embed.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../public/embed/webchat.js', import.meta.url), 'utf8');
const window = {};
// No document: the widget defines its helpers and stops before touching a page.
runInNewContext(source, { window });
const chat = window.AttomeWebchat;

test('speaks Arabic or English and runs Arabic right to left', () => {
  assert.equal(chat.language('ar-SA'), 'ar');
  assert.equal(chat.language('fr'), 'en');
  assert.equal(chat.language(undefined), 'en');
  assert.equal(chat.isRtl('ar'), true);
  assert.equal(chat.isRtl('en'), false);
});

test('the first message says who is asking', () => {
  const t = chat.TEXT.en;
  assert.equal(chat.firstMessage(t, 'Sara', 'sara@example.com', ' Hello '), 'From: Sara <sara@example.com>\n\nHello');
  assert.equal(chat.firstMessage(t, '', 'sara@example.com', 'Hi'), 'From: sara@example.com\n\nHi');
  assert.equal(chat.firstMessage(t, '', '', 'Hi'), 'Hi');
  assert.equal(chat.firstMessage(chat.TEXT.ar, 'سارة', '', 'مرحبا'), 'من: سارة\n\nمرحبا');
});

test('the survey is a rating from 1 to 5 with an optional comment', () => {
  const t = chat.TEXT.en;
  assert.equal(chat.surveyMessage(t, '4', ' Quick help '), 'Rating: 4/5\nQuick help');
  assert.equal(chat.surveyMessage(t, 9, ''), 'Rating: 5/5');
  assert.equal(chat.surveyMessage(t, 'x', ''), 'Rating: 1/5');
});

test('messages are shown once and the cursor moves to the newest', () => {
  const a = { created_at: '2026-10-19T08:00:00Z', direction: 'inbound', body: 'hi' };
  const b = { created_at: '2026-10-19T08:00:05Z', direction: 'outbound', body: 'hello' };
  assert.equal(chat.newest(null, [b, a]), b.created_at);
  assert.equal(chat.newest(b.created_at, [a]), b.created_at);
  assert.equal(chat.newest(null, []), null);
  assert.notEqual(chat.messageKey(a), chat.messageKey(b));
  assert.equal(chat.messageKey({ direction: 'outbound', body: 'local', created_at: null }), null);
});
