/*
 * Attome co-browse for portal pages (roadmap J9-T1).
 *
 *   <script src="https://crm.example.com/embed/cobrowse.js" data-lang="ar" async></script>
 *
 * A "Share this page with support" button opens a small panel (in a shadow
 * root, so the page's styles do not reach it). The customer types the
 * six-digit code the agent gave them; from then on the agent sees the page:
 *
 * - a snapshot of the page's DOM, then its changes (batched every half
 *   second; a page that changes too much is re-sent whole) and the scroll
 *   position, over the J9-T2 session channel;
 * - every form field's value is replaced by dots before it leaves the page,
 *   and so is the text of any element marked `data-attome-mask` or holding a
 *   password, card, one-time-code or national-id field. Scripts, iframes and
 *   the panel itself are never sent;
 * - the agent's pointer shows as a dot over the page, and their notes appear
 *   in the panel. Either side can stop; stopping ends the session.
 *
 * Nothing is captured before the customer enters a code, and nothing is
 * sent after they stop. The server must list the page's origin in
 * cors.allowed_origins and have the omnichannel module licensed.
 */
(function () {
  'use strict';

  var TEXT = {
    en: {
      share: 'Share this page with support', code: 'Code from the agent', join: 'Start sharing',
      sharing: 'Support can see this page. Form fields are hidden from them.', stop: 'Stop sharing',
      stopped: 'Sharing has stopped.', badCode: 'That code did not work. Check it with the agent.',
      failed: 'Sharing stopped because the connection was lost.', close: 'Close', note: 'Support'
    },
    ar: {
      share: 'شارك هذه الصفحة مع الدعم', code: 'الرمز من الموظف', join: 'ابدأ المشاركة',
      sharing: 'يرى فريق الدعم هذه الصفحة. حقول النماذج مخفية عنهم.', stop: 'أوقف المشاركة',
      stopped: 'توقفت المشاركة.', badCode: 'لم يعمل هذا الرمز. تحقق منه مع الموظف.',
      failed: 'توقفت المشاركة لانقطاع الاتصال.', close: 'إغلاق', note: 'الدعم'
    }
  };

  /** The largest frame the channel takes (J9-T2), less room for the envelope. */
  var MAX_FRAME = 250 * 1024;
  var MASK = '••••';
  /** Autocomplete tokens and input types whose values are never sent. */
  var SENSITIVE = /password|cc-|one-time-code|national|ssn|iban|card/i;

  function language(raw) {
    var two = String(raw || '').slice(0, 2).toLowerCase();
    return TEXT[two] ? two : 'en';
  }

  function isRtl(lang) {
    return lang === 'ar';
  }

  /** A six-digit code as typed (spaces and dashes dropped), or null. */
  function cleanCode(raw) {
    var digits = String(raw || '').replace(/[\s-]/g, '');
    return /^\d{6}$/.test(digits) ? digits : null;
  }

  /**
   * Whether an element's own text or value must not leave the page: anything
   * marked `data-attome-mask`, and fields whose type, name or autocomplete
   * says password, card, one-time code or national id. Takes a plain
   * description so it can be tested without a page.
   */
  function isSensitive(el) {
    if (!el) return false;
    if (el.mask) return true;
    return SENSITIVE.test(el.type || '') || SENSITIVE.test(el.autocomplete || '') ||
      SENSITIVE.test(el.name || '');
  }

  /** Whether a frame fits the channel. */
  function fits(frame) {
    return JSON.stringify(frame).length <= MAX_FRAME;
  }

  /** Where the agent's pointer goes on this viewport, from their fractions. */
  function pointerPosition(payload, width, height) {
    var x = Number(payload && payload.x);
    var y = Number(payload && payload.y);
    if (!isFinite(x) || !isFinite(y)) return null;
    var clamp = function (v) { return Math.min(Math.max(v, 0), 1); };
    return { left: Math.round(clamp(x) * width), top: Math.round(clamp(y) * height) };
  }

  /** The newest frame id, the read cursor. */
  function lastId(frames, current) {
    return frames && frames.length ? frames[frames.length - 1].id : current;
  }

  var api = {
    language: language, isRtl: isRtl, cleanCode: cleanCode, isSensitive: isSensitive, fits: fits,
    pointerPosition: pointerPosition, lastId: lastId, MASK: MASK, TEXT: TEXT
  };
  if (typeof window !== 'undefined') window.AttomeCobrowse = api;

  var script = typeof document !== 'undefined' ? document.currentScript : null;
  if (!script || !script.src) return;

  var lang = language(script.getAttribute('data-lang') || document.documentElement.lang);
  var t = TEXT[lang];
  var base = new URL(script.src).origin;

  var host = document.createElement('div');
  host.setAttribute('data-attome-cobrowse', '');
  document.body.appendChild(host);
  var root = host.attachShadow({ mode: 'open' });
  root.innerHTML =
    '<style>' +
    ':host{all:initial}' +
    '.c{position:fixed;inset-block-end:1rem;inset-inline-start:1rem;z-index:2147483000;font:14px/1.5 system-ui,sans-serif;color:CanvasText}' +
    '.p{background:Canvas;border:1px solid GrayText;border-radius:10px;padding:12px;display:grid;gap:8px;inline-size:min(320px,90vw);box-shadow:0 4px 16px rgba(0,0,0,.2)}' +
    'button,input{font:inherit}' +
    '.b{padding:8px 12px;border-radius:8px;border:1px solid GrayText;background:Canvas;color:CanvasText;cursor:pointer}' +
    '.n{font-size:13px;color:GrayText}' +
    '.dot{position:fixed;inline-size:18px;block-size:18px;margin:-9px;border-radius:50%;background:rgba(220,38,38,.6);border:2px solid #fff;pointer-events:none;z-index:2147483001}' +
    '[hidden]{display:none!important}' +
    '</style>' +
    '<div class="c" dir="' + (isRtl(lang) ? 'rtl' : 'ltr') + '" lang="' + lang + '">' +
    '<button type="button" class="b" data-open></button>' +
    '<form class="p" data-join hidden><label><span data-code-label></span><br>' +
    '<input name="code" inputmode="numeric" autocomplete="off" maxlength="9" required></label>' +
    '<button class="b" type="submit" data-join-btn></button><p class="n" data-msg></p></form>' +
    '<div class="p" data-live hidden><p data-sharing></p><p class="n" data-notes></p>' +
    '<button type="button" class="b" data-stop></button></div>' +
    '</div><div class="dot" data-dot hidden></div>';

  var $ = function (sel) { return root.querySelector(sel); };
  $('[data-open]').textContent = t.share;
  $('[data-code-label]').textContent = t.code;
  $('[data-join-btn]').textContent = t.join;
  $('[data-sharing]').textContent = t.sharing;
  $('[data-stop]').textContent = t.stop;

  var token = null;
  var after = null;
  var observer = null;
  var pending = [];
  var timers = [];

  function show(which) {
    $('[data-open]').hidden = which !== 'open';
    $('[data-join]').hidden = which !== 'join';
    $('[data-live]').hidden = which !== 'live';
  }

  function elementInfo(el) {
    return {
      mask: el.hasAttribute && el.hasAttribute('data-attome-mask'),
      type: el.getAttribute && el.getAttribute('type'),
      name: el.getAttribute && el.getAttribute('name'),
      autocomplete: el.getAttribute && el.getAttribute('autocomplete')
    };
  }

  /** A masked copy of `node` as HTML: no scripts, no frames, no values. */
  function maskedHtml(node) {
    var copy = node.cloneNode(true);
    var drop = copy.querySelectorAll ? copy.querySelectorAll('script,iframe,object,embed,noscript,[data-attome-cobrowse]') : [];
    for (var i = 0; i < drop.length; i++) drop[i].remove();
    var fields = copy.querySelectorAll ? copy.querySelectorAll('input,textarea,select,option') : [];
    for (var j = 0; j < fields.length; j++) {
      var f = fields[j];
      if (f.tagName === 'OPTION') { f.removeAttribute('selected'); continue; }
      if (f.tagName === 'TEXTAREA') { f.textContent = f.textContent ? MASK : ''; continue; }
      if (f.hasAttribute('value')) f.setAttribute('value', f.getAttribute('value') ? MASK : '');
    }
    var marked = copy.querySelectorAll ? copy.querySelectorAll('[data-attome-mask]') : [];
    for (var k = 0; k < marked.length; k++) marked[k].textContent = MASK;
    // Live values are not attributes: mark which fields hold something.
    var live = node.querySelectorAll ? node.querySelectorAll('input,textarea') : [];
    var copies = copy.querySelectorAll ? copy.querySelectorAll('input,textarea') : [];
    for (var m = 0; m < live.length && m < copies.length; m++) {
      if (live[m].value && !isSensitive(elementInfo(live[m]))) copies[m].setAttribute('data-filled', '');
    }
    return copy.outerHTML || '';
  }

  /** An element's place in the page, as child indexes from <html>. */
  function pathOf(el) {
    var path = [];
    while (el && el.parentElement) {
      path.unshift(Array.prototype.indexOf.call(el.parentElement.children, el));
      el = el.parentElement;
    }
    return path;
  }

  function send(kind, payload) {
    if (!token) return;
    var frame = { token: token, kind: kind, payload: payload };
    if (!fits(frame)) {
      if (kind === 'snapshot') {
        frame.payload = { url: location.href, too_large: true };
      } else {
        snapshot();
        return;
      }
    }
    fetch(base + '/api/v1/cobrowse/visitor/messages', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(frame)
    }).then(function (r) { if (r.status === 404) stop(t.stopped); })
      .catch(function () { stop(t.failed); });
  }

  function snapshot() {
    pending = [];
    send('snapshot', {
      url: location.href,
      width: window.innerWidth,
      height: window.innerHeight,
      scroll: { x: window.scrollX, y: window.scrollY },
      html: maskedHtml(document.documentElement)
    });
  }

  function flush() {
    if (!pending.length) return;
    var changed = [];
    var seen = new Set();
    for (var i = 0; i < pending.length; i++) {
      var el = pending[i];
      if (!el || !el.isConnected || seen.has(el) || host.contains(el)) continue;
      seen.add(el);
      changed.push({ path: pathOf(el), html: maskedHtml(el) });
    }
    pending = [];
    if (changed.length > 50) { snapshot(); return; }
    if (changed.length) send('mutation', { changes: changed });
  }

  var scrollTimer = null;
  function onScroll() {
    if (scrollTimer) return;
    scrollTimer = setTimeout(function () {
      scrollTimer = null;
      send('scroll', { x: window.scrollX, y: window.scrollY });
    }, 200);
  }

  function poll() {
    if (!token) return;
    var url = base + '/api/v1/cobrowse/visitor/messages?token=' + encodeURIComponent(token) +
      (after ? '&after=' + encodeURIComponent(after) : '');
    fetch(url).then(function (r) {
      if (r.status === 404) { stop(t.stopped); return null; }
      return r.ok ? r.json() : null;
    }).then(function (frames) {
      if (!frames) return;
      after = lastId(frames, after);
      frames.forEach(function (f) {
        if (f.kind === 'pointer') {
          var at = pointerPosition(f.payload, window.innerWidth, window.innerHeight);
          var dot = $('[data-dot]');
          if (at) { dot.style.left = at.left + 'px'; dot.style.top = at.top + 'px'; dot.hidden = false; }
        } else if (f.kind === 'note' && f.payload && f.payload.text) {
          $('[data-notes]').textContent = t.note + ': ' + String(f.payload.text).slice(0, 500);
        } else if (f.kind === 'control' && f.payload && f.payload.action === 'end') {
          stop(t.stopped);
        } else if (f.kind === 'control' && f.payload && f.payload.action === 'resend') {
          snapshot();
        }
      });
    }).catch(function () { stop(t.failed); });
  }

  function start(sessionToken) {
    token = sessionToken;
    after = null;
    show('live');
    snapshot();
    observer = new MutationObserver(function (records) {
      records.forEach(function (rec) {
        pending.push(rec.type === 'childList' ? rec.target : (rec.target.parentElement || rec.target));
      });
    });
    observer.observe(document.documentElement, { subtree: true, childList: true, attributes: true, characterData: true });
    window.addEventListener('scroll', onScroll, { passive: true });
    timers.push(setInterval(flush, 500));
    timers.push(setInterval(poll, 2000));
  }

  function stop(message) {
    if (!token) return;
    var ending = token;
    token = null;
    if (observer) observer.disconnect();
    observer = null;
    timers.forEach(clearInterval);
    timers = [];
    window.removeEventListener('scroll', onScroll);
    $('[data-dot]').hidden = true;
    fetch(base + '/api/v1/cobrowse/visitor/end', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: ending })
    }).catch(function () { /* already gone */ });
    show('open');
    $('[data-msg]').textContent = message || '';
  }

  $('[data-open]').addEventListener('click', function () { show('join'); $('[data-msg]').textContent = ''; });
  $('[data-stop]').addEventListener('click', function () { stop(t.stopped); });
  $('[data-join]').addEventListener('submit', function (e) {
    e.preventDefault();
    var code = cleanCode(e.target.elements.code.value);
    if (!code) { $('[data-msg]').textContent = t.badCode; return; }
    fetch(base + '/api/v1/cobrowse/join', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: code })
    }).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (joined) {
        if (!joined || !joined.token) { $('[data-msg]').textContent = t.badCode; return; }
        e.target.elements.code.value = '';
        start(joined.token);
      })
      .catch(function () { $('[data-msg]').textContent = t.failed; });
  });
  window.addEventListener('pagehide', function () { stop(null); });
  show('open');
})();
