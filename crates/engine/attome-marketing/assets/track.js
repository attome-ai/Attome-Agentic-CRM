/* Attome website tracking (E14-T4). Served by the deployment itself; it
 * talks to nothing else. Does nothing until the visitor grants the
 * analytics consent category (window.attomeConsent, the consent banner's
 * API), stays anonymous under Global Privacy Control, and identifies a
 * browser only by its own first-party cookie: no fingerprinting. */
(function () {
  'use strict';
  var cfg = window.__attomeTrack || {};
  if (!cfg.site || window.__attomeTrackLoaded) return;
  window.__attomeTrackLoaded = true;

  var ENDPOINT = (cfg.origin || '') + '/api/v1/track/collect';
  var CLICK_IDS = ['gclid', 'fbclid', 'li_fat_id', 'ttclid', 'msclkid'];
  var UTM = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'];
  var queue = [];
  var timer = null;
  var started = false;
  var pageStart = Date.now();

  function consented() {
    var c = window.attomeConsent;
    if (!c) return false;
    if (typeof c.granted === 'function') return !!c.granted('analytics');
    return !!(c.analytics || (c.categories && c.categories.analytics));
  }

  function anonymous() {
    return navigator.globalPrivacyControl === true;
  }

  function uuid() {
    var b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    var h = [];
    for (var i = 0; i < 16; i++) h.push((b[i] + 256).toString(16).slice(1));
    return h.slice(0, 4).join('') + '-' + h.slice(4, 6).join('') + '-' + h.slice(6, 8).join('') + '-' +
      h.slice(8, 10).join('') + '-' + h.slice(10, 16).join('');
  }

  function readCookie(name) {
    var parts = document.cookie.split('; ');
    for (var i = 0; i < parts.length; i++) {
      var kv = parts[i].split('=');
      if (kv[0] === name) return decodeURIComponent(kv.slice(1).join('='));
    }
    return null;
  }

  function writeCookie(name, value, seconds) {
    var secure = location.protocol === 'https:' ? '; Secure' : '';
    document.cookie = name + '=' + encodeURIComponent(value) + '; Max-Age=' + seconds +
      '; Path=/; SameSite=Lax' + secure;
  }

  function visitor() {
    if (anonymous()) return null;
    var id = readCookie('atm_vid');
    if (!id) id = uuid();
    writeCookie('atm_vid', id, 60 * 60 * 24 * 396);
    return id;
  }

  function session() {
    var id = readCookie('atm_sid') || uuid();
    writeCookie('atm_sid', id, 30 * 60);
    return id;
  }

  function landing() {
    var params = new URLSearchParams(location.search);
    var out = {};
    UTM.concat(CLICK_IDS).forEach(function (k) {
      var v = params.get(k);
      if (v) out[k] = v.slice(0, 200);
    });
    return out;
  }

  function flush(useBeacon) {
    if (!queue.length) return;
    var body = JSON.stringify({ site: cfg.site, visitor: visitor(), session: session(), events: queue.splice(0, 20) });
    // text/plain: a cross-site post a browser sends without a preflight;
    // the deployment reads the body as JSON.
    if (useBeacon && navigator.sendBeacon) {
      navigator.sendBeacon(ENDPOINT, new Blob([body], { type: 'text/plain' }));
    } else if (window.fetch) {
      fetch(ENDPOINT, { method: 'POST', body: body, headers: { 'Content-Type': 'text/plain' }, keepalive: true,
        credentials: 'omit', mode: 'no-cors' })
        .catch(function () { /* tracking never breaks the page */ });
    }
    if (queue.length) flush(useBeacon);
  }

  function push(event) {
    if (!consented()) return;
    event.at = new Date().toISOString();
    queue.push(event);
    if (queue.length >= 20) flush(false);
    if (!timer) timer = setInterval(function () { flush(false); }, 5000);
  }

  function pageView() {
    push({ kind: 'page_view', url: location.href.slice(0, 2000), title: document.title.slice(0, 300),
      referrer: document.referrer.slice(0, 2000), landing: landing() });
  }

  function start() {
    if (started || !consented()) return;
    started = true;
    pageView();
    addEventListener('pagehide', function () {
      push({ kind: 'page_leave', url: location.href.slice(0, 2000), time_on_page_ms: Date.now() - pageStart });
      flush(true);
    });
  }

  var api = window.attome || {};
  if (cfg.customEvents) {
    api.track = function (eventType, payload) {
      if (typeof eventType !== 'string' || !eventType) return;
      push({ kind: 'custom', event_type: eventType.slice(0, 100), payload: payload || {} });
    };
  }
  window.attome = api;

  start();
  // The banner tells us when consent changes.
  addEventListener('attome:consent', start);
})();
