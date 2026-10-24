// R6-T1: the consent banner's pure parts. Run with
//   node --test web/scripts/consent-banner.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../public/embed/consent-banner.js', import.meta.url), 'utf8');
const window = {};
// No document: the banner defines its helpers and stops before touching a page.
runInNewContext(source, { window, JSON });
const c = window.AttomeConsent;
const plain = (v) => JSON.parse(JSON.stringify(v));

test('speaks Arabic or English with the same keys', () => {
  assert.equal(c.language('ar-SA'), 'ar');
  assert.equal(c.language('de'), 'en');
  assert.deepEqual(Object.keys(c.TEXT.ar).sort(), Object.keys(c.TEXT.en).sort());
});

test('the region comes from the attribute, else the time zone', () => {
  assert.equal(c.regionOf('US', 'Europe/Paris'), 'us');
  assert.equal(c.regionOf('', 'Europe/Paris'), 'eu');
  assert.equal(c.regionOf('', 'Europe/London'), 'uk');
  assert.equal(c.regionOf('', 'Asia/Riyadh'), 'sa');
  assert.equal(c.regionOf('', 'Asia/Dubai'), 'gcc');
  assert.equal(c.regionOf('', 'America/Chicago'), 'us');
  assert.equal(c.regionOf('', 'America/Sao_Paulo'), 'other');
  assert.equal(c.regionOf('', ''), 'other');
});

test('opt-in regions start with nothing optional; the US starts on, marketing off under GPC', () => {
  for (const region of ['eu', 'uk', 'sa', 'gcc', 'other']) {
    assert.deepEqual(plain(c.defaultsFor(region, false)), { necessary: true, preferences: false, analytics: false, marketing: false });
  }
  assert.deepEqual(plain(c.defaultsFor('us', false)), { necessary: true, preferences: true, analytics: true, marketing: true });
  assert.equal(c.defaultsFor('us', true).marketing, false);
});

test('Consent Mode v2 signals follow the categories', () => {
  const mode = plain(c.consentModeFor({ analytics: true }));
  assert.deepEqual(mode, {
    ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied',
    analytics_storage: 'granted', functionality_storage: 'denied', personalization_storage: 'denied',
    security_storage: 'granted',
  });
  assert.equal(c.consentModeFor({ marketing: true }).ad_user_data, 'granted');
});

test('the GPP usnat section opts out of sale and sharing without marketing', () => {
  const out = plain(c.usnatSection({ analytics: true }, true));
  assert.equal(out.SaleOptOut, 1);
  assert.equal(out.SharingOptOut, 1);
  assert.equal(out.TargetedAdvertisingOptOut, 1);
  assert.equal(out.Gpc, true);
  assert.equal(c.usnatSection({ marketing: true }, false).SaleOptOut, 2);
});

test('scripts run only in allowed categories; necessary always', () => {
  const choices = { analytics: true };
  assert.equal(c.allowed('necessary', choices), true);
  assert.equal(c.allowed('', choices), true);
  assert.equal(c.allowed('analytics', choices), true);
  assert.equal(c.allowed('marketing', choices), false);
});

test('proof is posted for each allowed category that maps to a purpose', () => {
  const purposes = { analytics: 'cookies_analytics', marketing: 'cookies_marketing' };
  assert.deepEqual(plain(c.proofs({ analytics: true, preferences: true }, purposes)), [
    { category: 'analytics', purpose_key: 'cookies_analytics' },
  ]);
  assert.deepEqual(plain(c.proofs({}, purposes)), []);
  const evidence = JSON.parse(c.evidence({ marketing: true }, { version: '2026-10', region: 'eu', page: 'https://x.example/', at: 'T', lang: 'ar' }));
  assert.equal(evidence.banner_version, '2026-10');
  assert.equal(evidence.choices.marketing, true);
  assert.equal(evidence.choices.necessary, true);
});

test('a stored choice counts only for the same banner version', () => {
  const raw = JSON.stringify({ version: '2', choices: { analytics: true } });
  assert.equal(c.readStored(raw, '2').analytics, true);
  assert.equal(c.readStored(raw, '3'), null);
  assert.equal(c.readStored('{broken', '2'), null);
  assert.equal(c.readStored(null, '2'), null);
});
