/*
 * Attome consent banner for another website (roadmap R6-T1).
 *
 *   <script src="https://crm.example.com/embed/consent-banner.js"
 *           data-lang="ar" data-version="2026-10"
 *           data-purposes='{"analytics":"cookies_analytics","marketing":"cookies_marketing"}'></script>
 *
 * Load it first, synchronously, at the top of <head>: before anything else
 * runs it sets the Google Consent Mode v2 defaults and installs the IAB GPP
 * API (`__gpp`), so tags that read either see the visitor's state.
 *
 * - Categories: necessary (always on), preferences, analytics, marketing.
 * - Other scripts wait for their category: write them as
 *   <script type="text/plain" data-consent-category="analytics" src="..."></script>
 *   and the banner runs them once that category is allowed, including ones
 *   added to the page later.
 * - Region defaults (`data-region`, else the browser's time zone): in the
 *   EU, the UK, Saudi Arabia, the Gulf and anywhere unknown nothing optional
 *   runs until the visitor agrees; in the United States analytics and
 *   preferences run until the visitor opts out, and marketing (sale and
 *   sharing) is off when the browser sends Global Privacy Control.
 * - Arabic or English (`data-lang`, else the page's lang); Arabic runs right
 *   to left. The banner sits in a shadow root at the page's block end.
 * - Proof: every category the visitor allows that `data-purposes` maps to a
 *   consent purpose is posted to POST /api/v1/consents/capture (E27) with
 *   the choices, the banner version, the region and the page as evidence,
 *   under an anonymous visitor id kept in this browser. Withdrawing is kept
 *   in the browser and in Consent Mode; the public capture route records
 *   grants only.
 * - The choice is kept in localStorage; a new `data-version` asks again.
 *   `AttomeConsent.open()` reopens the choices (link it from the privacy
 *   page) and `AttomeConsent.get()` returns them.
 *
 * The server must list the page's origin in cors.allowed_origins for the
 * proof to be recorded; the banner works without it.
 */
(function () {
  'use strict';

  var CATEGORIES = ['necessary', 'preferences', 'analytics', 'marketing'];

  var TEXT = {
    en: {
      title: 'Your privacy', body: 'We use cookies and similar tools. Necessary ones keep the site working; the others run only if you allow them.',
      accept: 'Accept all', reject: 'Necessary only', choose: 'Choose', save: 'Save my choices', close: 'Close',
      usBody: 'We use cookies and similar tools for analytics and to remember your preferences. You can opt out of any of them, including the sale or sharing of your information.',
      optOut: 'Do not sell or share my information', privacy: 'Privacy policy',
      necessary: 'Necessary', necessaryHint: 'Needed for the site to work. Always on.',
      preferences: 'Preferences', preferencesHint: 'Remember your settings, such as language.',
      analytics: 'Analytics', analyticsHint: 'Help us understand how the site is used.',
      marketing: 'Marketing', marketingHint: 'Personalised advertising, and sharing with advertising partners.'
    },
    ar: {
      title: 'خصوصيتك', body: 'نستخدم ملفات تعريف الارتباط وأدوات مشابهة. الضرورية منها تُبقي الموقع يعمل، والبقية لا تعمل إلا إذا سمحت بها.',
      accept: 'قبول الكل', reject: 'الضرورية فقط', choose: 'اختيار', save: 'حفظ اختياراتي', close: 'إغلاق',
      usBody: 'نستخدم ملفات تعريف الارتباط وأدوات مشابهة للتحليلات ولتذكّر تفضيلاتك. يمكنك إيقاف أي منها، بما في ذلك بيع معلوماتك أو مشاركتها.',
      optOut: 'لا تبع معلوماتي ولا تشاركها', privacy: 'سياسة الخصوصية',
      necessary: 'ضرورية', necessaryHint: 'لازمة ليعمل الموقع. مفعّلة دائمًا.',
      preferences: 'التفضيلات', preferencesHint: 'تذكّر إعداداتك مثل اللغة.',
      analytics: 'التحليلات', analyticsHint: 'تساعدنا على فهم كيفية استخدام الموقع.',
      marketing: 'التسويق', marketingHint: 'إعلانات مخصصة ومشاركة مع شركاء الإعلان.'
    }
  };

  /** The language the banner speaks: `ar` or `en`. */
  function language(raw) {
    var two = String(raw || '').slice(0, 2).toLowerCase();
    return TEXT[two] ? two : 'en';
  }

  /** The visitor's region: the attribute when it names one, else from the time zone. */
  function regionOf(explicit, timeZone) {
    var r = String(explicit || '').toLowerCase();
    if (['eu', 'uk', 'sa', 'gcc', 'us', 'other'].indexOf(r) >= 0) return r;
    var tz = String(timeZone || '');
    if (tz === 'Europe/London') return 'uk';
    if (tz.indexOf('Europe/') === 0) return 'eu';
    if (tz === 'Asia/Riyadh') return 'sa';
    if (['Asia/Dubai', 'Asia/Qatar', 'Asia/Kuwait', 'Asia/Bahrain', 'Asia/Muscat'].indexOf(tz) >= 0) return 'gcc';
    if (tz.indexOf('America/') === 0 && ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
      'America/Phoenix', 'America/Anchorage', 'America/Detroit', 'America/Boise', 'Pacific/Honolulu'].indexOf(tz) >= 0) return 'us';
    return 'other';
  }

  /** Whether optional categories run before the visitor chooses (opt-out). */
  function optOutRegion(region) {
    return region === 'us';
  }

  /** The choices before the visitor makes any. */
  function defaultsFor(region, gpc) {
    var on = optOutRegion(region);
    return { necessary: true, preferences: on, analytics: on, marketing: on && !gpc };
  }

  /** A full choice set: `necessary` always on, every other category a boolean. */
  function normalise(choices) {
    var out = { necessary: true };
    for (var i = 1; i < CATEGORIES.length; i++) out[CATEGORIES[i]] = !!(choices && choices[CATEGORIES[i]]);
    return out;
  }

  /** Google Consent Mode v2 signals for a choice set. */
  function consentModeFor(choices) {
    var c = normalise(choices);
    var g = function (on) { return on ? 'granted' : 'denied'; };
    return {
      ad_storage: g(c.marketing), ad_user_data: g(c.marketing), ad_personalization: g(c.marketing),
      analytics_storage: g(c.analytics), functionality_storage: g(c.preferences),
      personalization_storage: g(c.preferences), security_storage: 'granted'
    };
  }

  /** The GPP US national section (`usnat`) for a choice set: 1 opted out, 2 did not. */
  function usnatSection(choices, gpc) {
    var c = normalise(choices);
    var out = c.marketing ? 2 : 1;
    return {
      Version: 1, SharingNotice: 1, SaleOptOutNotice: 1, SharingOptOutNotice: 1, TargetedAdvertisingOptOutNotice: 1,
      SaleOptOut: out, SharingOptOut: out, TargetedAdvertisingOptOut: out, Gpc: !!gpc
    };
  }

  /** Whether a script of `category` may run. */
  function allowed(category, choices) {
    if (!category || category === 'necessary') return true;
    return normalise(choices)[category] === true;
  }

  /** The consent purposes to record: each allowed optional category `purposes` maps. */
  function proofs(choices, purposes) {
    var c = normalise(choices);
    var out = [];
    for (var i = 1; i < CATEGORIES.length; i++) {
      var cat = CATEGORIES[i];
      if (c[cat] && purposes && typeof purposes[cat] === 'string' && purposes[cat]) {
        out.push({ category: cat, purpose_key: purposes[cat] });
      }
    }
    return out;
  }

  /** The evidence a proof carries. */
  function evidence(choices, meta) {
    return JSON.stringify({
      banner_version: meta.version, region: meta.region, choices: normalise(choices),
      page: meta.page, at: meta.at, language: meta.lang
    });
  }

  /** A stored choice, or null when there is none for this banner version. */
  function readStored(raw, version) {
    try {
      var v = JSON.parse(raw || 'null');
      if (v && v.version === version && v.choices) return normalise(v.choices);
    } catch (e) { /* a damaged value asks again */ }
    return null;
  }

  var api = {
    CATEGORIES: CATEGORIES, TEXT: TEXT, language: language, regionOf: regionOf, defaultsFor: defaultsFor,
    normalise: normalise, consentModeFor: consentModeFor, usnatSection: usnatSection, allowed: allowed,
    proofs: proofs, evidence: evidence, readStored: readStored
  };
  if (typeof window !== 'undefined') window.AttomeConsent = api;

  var script = typeof document !== 'undefined' ? document.currentScript : null;
  if (!script) return;

  var STORE = 'attome-consent';
  var VISITOR = 'attome-consent-visitor';
  var lang = language(script.getAttribute('data-lang') || document.documentElement.lang || navigator.language);
  var t = TEXT[lang];
  var version = script.getAttribute('data-version') || '1';
  var privacyUrl = script.getAttribute('data-privacy-url') || '';
  var base = script.getAttribute('data-api') || new URL(script.src).origin;
  var purposes = {};
  try { purposes = JSON.parse(script.getAttribute('data-purposes') || '{}') || {}; } catch (e) { purposes = {}; }
  var timeZone = '';
  try { timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { timeZone = ''; }
  var region = regionOf(script.getAttribute('data-region'), timeZone);
  var gpc = navigator.globalPrivacyControl === true;

  function storage(key, value) {
    try {
      if (value === undefined) return window.localStorage.getItem(key);
      window.localStorage.setItem(key, value);
    } catch (e) { /* private mode: the choice lasts this page */ }
    return null;
  }

  var stored = readStored(storage(STORE), version);
  var choices = stored || defaultsFor(region, gpc);

  // ── Consent Mode v2, before any tag runs ────────────────────────────────
  window.dataLayer = window.dataLayer || [];
  function gtag() { window.dataLayer.push(arguments); }
  var defaults = consentModeFor(choices);
  if (!stored) defaults.wait_for_update = 500;
  gtag('consent', 'default', defaults);

  // ── IAB GPP CMP API ─────────────────────────────────────────────────────
  var listeners = [];
  var nextListener = 1;
  function pingData() {
    return {
      gppVersion: '1.1', cmpStatus: 'loaded', cmpDisplayStatus: shown ? 'visible' : 'hidden',
      signalStatus: 'ready', supportedAPIs: ['7:usnat'], cmpId: 0, sectionList: [7],
      applicableSections: region === 'us' ? [7] : [-1], gppString: '', parsedSections: { usnat: usnatSection(choices, gpc) }
    };
  }
  var shown = false;
  window.__gpp = function (command, callback, parameter) {
    if (typeof callback !== 'function') return;
    if (command === 'ping') callback(pingData(), true);
    else if (command === 'addEventListener') {
      var id = nextListener++;
      listeners.push({ id: id, cb: callback });
      callback({ eventName: 'listenerRegistered', listenerId: id, data: true, pingData: pingData() }, true);
    } else if (command === 'removeEventListener') {
      var before = listeners.length;
      listeners = listeners.filter(function (l) { return l.id !== parameter; });
      callback(listeners.length < before, true);
    } else if (command === 'hasSection') callback(parameter === 'usnat', true);
    else if (command === 'getSection') callback(parameter === 'usnat' ? usnatSection(choices, gpc) : null, true);
    else callback(null, false);
  };
  function gppEvent(name) {
    listeners.forEach(function (l) { l.cb({ eventName: name, listenerId: l.id, data: true, pingData: pingData() }, true); });
  }

  // ── Scripts waiting for a category ───────────────────────────────────────
  function release(node) {
    var category = node.getAttribute('data-consent-category');
    if (!allowed(category, choices)) return;
    var run = document.createElement('script');
    for (var i = 0; i < node.attributes.length; i++) {
      var a = node.attributes[i];
      if (a.name !== 'type') run.setAttribute(a.name, a.value);
    }
    if (!node.src) run.text = node.text;
    node.parentNode.insertBefore(run, node);
    node.parentNode.removeChild(node);
  }
  function releaseAll() {
    var waiting = document.querySelectorAll('script[type="text/plain"][data-consent-category]');
    for (var i = 0; i < waiting.length; i++) release(waiting[i]);
  }
  if (typeof MutationObserver !== 'undefined') {
    new MutationObserver(function (records) {
      records.forEach(function (r) {
        r.addedNodes.forEach(function (n) {
          if (n.nodeName === 'SCRIPT' && n.getAttribute('type') === 'text/plain' && n.hasAttribute('data-consent-category')) release(n);
        });
      });
    }).observe(document.documentElement, { childList: true, subtree: true });
  }

  // ── Recording a choice ──────────────────────────────────────────────────
  function visitorId() {
    var id = storage(VISITOR);
    if (!id) {
      id = (window.crypto && window.crypto.randomUUID) ? window.crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2);
      storage(VISITOR, id);
    }
    return 'visitor:' + id;
  }
  function record(next) {
    choices = normalise(next);
    var at = new Date().toISOString();
    storage(STORE, JSON.stringify({ version: version, choices: choices, at: at, region: region }));
    gtag('consent', 'update', consentModeFor(choices));
    gppEvent('signalStatus');
    releaseAll();
    try { window.dispatchEvent(new CustomEvent('attome-consent', { detail: choices })); } catch (e) { /* old browsers */ }
    var proof = evidence(choices, { version: version, region: region, page: location.href, at: at, lang: lang });
    var subject = visitorId();
    proofs(choices, purposes).forEach(function (p) {
      try {
        fetch(base + '/api/v1/consents/capture', {
          method: 'POST', keepalive: true, headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ purpose_key: p.purpose_key, subject_reference: subject, evidence: proof })
        }).catch(function () { /* the choice stands without the proof */ });
      } catch (e) { /* no fetch */ }
    });
    hide();
  }

  // ── The banner ──────────────────────────────────────────────────────────
  var host = null, root = null;
  function hide() {
    if (host) host.style.display = 'none';
    shown = false;
    gppEvent('cmpDisplayStatus');
  }
  function build() {
    host = document.createElement('div');
    host.setAttribute('data-attome-consent', '');
    root = host.attachShadow({ mode: 'open' });
    var rows = CATEGORIES.map(function (cat) {
      return '<label class="row"><input type="checkbox" data-cat="' + cat + '"' + (cat === 'necessary' ? ' checked disabled' : '') +
        '><span><strong>' + t[cat] + '</strong><small>' + t[cat + 'Hint'] + '</small></span></label>';
    }).join('');
    root.innerHTML =
      '<style>' +
      ':host{all:initial}' +
      '.b{position:fixed;inset-inline:0;inset-block-end:0;z-index:2147483646;font:14px/1.5 system-ui,sans-serif;color:#1a202c;' +
      'background:#fff;border-block-start:1px solid #cbd5e0;box-shadow:0 -4px 16px rgba(0,0,0,.08);padding:16px}' +
      '.in{max-inline-size:960px;margin-inline:auto;display:grid;gap:10px}' +
      'h2{margin:0;font-size:16px}p{margin:0}' +
      '.acts{display:flex;flex-wrap:wrap;gap:8px}' +
      'button{font:inherit;padding:8px 14px;border-radius:6px;border:1px solid #2b6cb0;background:#fff;color:#2b6cb0;cursor:pointer}' +
      'button.p{background:#2b6cb0;color:#fff}' +
      '.rows{display:none;gap:8px}.open .rows{display:grid}' +
      '.row{display:flex;gap:8px;align-items:flex-start}.row small{display:block;color:#4a5568}' +
      'a{color:#2b6cb0}' +
      '</style>' +
      '<div class="b" role="dialog" aria-modal="false" aria-labelledby="t" dir="' + (lang === 'ar' ? 'rtl' : 'ltr') + '" lang="' + lang + '">' +
      '<div class="in"><h2 id="t">' + t.title + '</h2>' +
      '<p>' + (optOutRegion(region) ? t.usBody : t.body) +
      (privacyUrl ? ' <a target="_blank" rel="noopener"></a>' : '') + '</p>' +
      '<div class="rows">' + rows + '</div>' +
      '<div class="acts">' +
      '<button type="button" class="p" data-act="accept">' + t.accept + '</button>' +
      '<button type="button" data-act="reject">' + (optOutRegion(region) ? t.optOut : t.reject) + '</button>' +
      '<button type="button" data-act="choose">' + t.choose + '</button>' +
      '<button type="button" class="p" data-act="save" hidden>' + t.save + '</button>' +
      '</div></div></div>';
    if (privacyUrl) {
      var link = root.querySelector('a');
      link.textContent = t.privacy;
      link.href = privacyUrl;
    }
    root.addEventListener('click', function (e) {
      var act = e.target && e.target.getAttribute && e.target.getAttribute('data-act');
      if (act === 'accept') record({ preferences: true, analytics: true, marketing: true });
      else if (act === 'reject') {
        record(optOutRegion(region) ? { preferences: choices.preferences, analytics: choices.analytics, marketing: false } : {});
      } else if (act === 'choose') openChoices();
      else if (act === 'save') {
        var next = {};
        root.querySelectorAll('input[data-cat]').forEach(function (i) { next[i.getAttribute('data-cat')] = i.checked; });
        record(next);
      }
    });
    document.body.appendChild(host);
  }
  function show(withChoices) {
    if (!document.body) {
      document.addEventListener('DOMContentLoaded', function () { show(withChoices); });
      return;
    }
    if (!host) build();
    host.style.display = '';
    root.querySelectorAll('input[data-cat]').forEach(function (i) { i.checked = allowed(i.getAttribute('data-cat'), choices); });
    root.querySelector('.b').classList.toggle('open', !!withChoices);
    root.querySelector('[data-act="save"]').hidden = !withChoices;
    root.querySelector('[data-act="choose"]').hidden = !!withChoices;
    shown = true;
    gppEvent('cmpDisplayStatus');
  }
  function openChoices() { show(true); }

  api.open = openChoices;
  api.get = function () { return normalise(choices); };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', releaseAll);
  else releaseAll();
  if (!stored) show(false);
})();
