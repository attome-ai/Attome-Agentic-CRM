import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fill, icons, parseArgs, values } from './build.mjs';

const BOT = '11111111-2222-3333-4444-555555555555';
const args = ['--url', 'https://crm.example.com/x', '--bot-app-id', BOT, '--company', 'Example "Co"'];

test('the manifest names the bot, the link domain and the deployment', () => {
  const vals = values(parseArgs(args));
  const manifest = JSON.parse(fill(readFileSync(new URL('./manifest.template.json', import.meta.url), 'utf8'), vals));
  assert.equal(manifest.bots[0].botId, BOT);
  assert.equal(manifest.composeExtensions[0].botId, BOT);
  assert.deepEqual(manifest.composeExtensions[0].messageHandlers[0].value.domains, ['crm.example.com']);
  assert.deepEqual(manifest.validDomains, ['crm.example.com']);
  assert.equal(manifest.developer.websiteUrl, 'https://crm.example.com');
  assert.equal(manifest.developer.name, 'Example "Co"');
  assert.match(manifest.id, /^[0-9a-f-]{36}$/);
});

test('the Arabic localization is valid JSON', () => {
  const ar = JSON.parse(readFileSync(new URL('./ar.template.json', import.meta.url), 'utf8'));
  assert.ok(ar['name.short']);
});

test('bad input is refused', () => {
  assert.throws(() => values(parseArgs(['--url', 'http://crm.example.com', '--bot-app-id', BOT, '--company', 'x'])));
  assert.throws(() => values(parseArgs(['--url', 'https://crm.example.com', '--bot-app-id', 'nope', '--company', 'x'])));
  assert.throws(() => values(parseArgs(['--url', 'https://crm.example.com', '--bot-app-id', BOT])));
});

test('the icons are PNGs of the sizes Teams asks for', () => {
  const { color, outline } = icons();
  for (const [file, size] of [[color, 192], [outline, 32]]) {
    assert.deepEqual([...file.subarray(1, 4)], [0x50, 0x4e, 0x47]);
    assert.equal(file.readUInt32BE(16), size);
    assert.equal(file.readUInt32BE(20), size);
  }
});
