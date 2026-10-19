/*
 * Attome web chat for another website (roadmap J3-T2).
 *
 *   <script src="https://crm.example.com/embed/webchat.js"
 *           data-lang="ar" data-title="Talk to us" async></script>
 *
 * One script tag: a chat button in the page's inline-end corner opens a
 * panel in a shadow root, so the page's styles do not reach it and its
 * styles do not leak out. Arabic runs right to left.
 *
 * - Pre-chat form: name, email (optional) and the first message; the name
 *   and email lead the first message so whoever answers knows who is asking.
 * - Messages go to POST /api/v1/omnichannel/webchat/message; replies arrive
 *   live through GET /api/v1/omnichannel/webchat/stream (Server-Sent Events,
 *   J3-T1), and through the poll every few seconds when the browser cannot
 *   hold a stream. The session token lives in sessionStorage, so a reload
 *   keeps the conversation.
 * - Ending the chat asks for a 1-5 rating and a comment, sent as the
 *   conversation's last message, then forgets the session.
 *
 * The server must list the page's origin in cors.allowed_origins and have
 * the omnichannel module licensed. Sharing files is not offered: uploads
 * need a signed-in person, and a visitor has none.
 */
(function () {
  'use strict';

  var TEXT = {
    en: {
      open: 'Chat with us', close: 'Close', title: 'Chat', name: 'Your name', email: 'Your email (optional)',
      message: 'How can we help?', start: 'Start chat', send: 'Send', placeholder: 'Type a message',
      end: 'End chat', rate: 'How was this chat?', comment: 'Anything to add? (optional)', submit: 'Send rating',
      thanks: 'Thank you. The chat has ended.', failed: 'The message could not be sent. Please try again.',
      busy: 'Too many messages. Please wait a moment.', unavailable: 'Chat is not available right now.',
      from: 'From', rating: 'Rating'
    },
    ar: {
      open: 'تحدث معنا', close: 'إغلاق', title: 'المحادثة', name: 'اسمك', email: 'بريدك الإلكتروني (اختياري)',
      message: 'كيف يمكننا مساعدتك؟', start: 'ابدأ المحادثة', send: 'إرسال', placeholder: 'اكتب رسالة',
      end: 'إنهاء المحادثة', rate: 'كيف كانت هذه المحادثة؟', comment: 'هل تود إضافة شيء؟ (اختياري)', submit: 'إرسال التقييم',
      thanks: 'شكرًا لك. انتهت المحادثة.', failed: 'تعذّر إرسال الرسالة. حاول مرة أخرى.',
      busy: 'رسائل كثيرة. انتظر قليلًا.', unavailable: 'المحادثة غير متاحة الآن.',
      from: 'من', rating: 'التقييم'
    }
  };

  /** The language the widget speaks: `ar` or `en`. */
  function language(raw) {
    var two = String(raw || '').slice(0, 2).toLowerCase();
    return TEXT[two] ? two : 'en';
  }

  /** Whether a language is written right to left. */
  function isRtl(lang) {
    return lang === 'ar';
  }

  /** The first message: who is asking, then what they asked. */
  function firstMessage(t, name, email, text) {
    var who = String(name || '').trim();
    var mail = String(email || '').trim();
    var lead = who ? t.from + ': ' + who + (mail ? ' <' + mail + '>' : '') : (mail ? t.from + ': ' + mail : '');
    var body = String(text || '').trim();
    return lead ? lead + '\n\n' + body : body;
  }

  /** The post-chat survey as the conversation's last message. */
  function surveyMessage(t, rating, comment) {
    var stars = Math.max(1, Math.min(5, Math.round(Number(rating) || 0)));
    var note = String(comment || '').trim();
    return t.rating + ': ' + stars + '/5' + (note ? '\n' + note : '');
  }

  /** One message's identity, to show it once; none for a local notice. */
  function messageKey(m) {
    return m && m.created_at ? m.created_at + '|' + m.direction + '|' + m.body : null;
  }

  /** The newest `created_at` among messages, else `since`. */
  function newest(since, messages) {
    var latest = since || null;
    (messages || []).forEach(function (m) {
      if (m && m.created_at && (!latest || m.created_at > latest)) latest = m.created_at;
    });
    return latest;
  }

  // Exposed for the widget's own tests and for a page that wants them.
  var api = {
    language: language, isRtl: isRtl, firstMessage: firstMessage, surveyMessage: surveyMessage,
    newest: newest, messageKey: messageKey, TEXT: TEXT
  };
  if (typeof window !== 'undefined') window.AttomeWebchat = api;

  var script = typeof document !== 'undefined' ? document.currentScript : null;
  if (!script || !script.src) return;

  var lang = language(script.getAttribute('data-lang') || document.documentElement.lang);
  var t = TEXT[lang];
  var base = new URL(script.src).origin;
  var titleText = script.getAttribute('data-title') || t.title;
  var STORE = 'attome-webchat-token';

  var host = document.createElement('div');
  document.body.appendChild(host);
  var root = host.attachShadow({ mode: 'open' });
  root.innerHTML =
    '<style>' +
    ':host{all:initial}' +
    '.w{position:fixed;inset-block-end:1rem;inset-inline-end:1rem;z-index:2147483000;font:14px/1.5 system-ui,sans-serif;color:CanvasText}' +
    '.fab{border:0;border-radius:2rem;padding-block:.75rem;padding-inline:1.25rem;background:Highlight;color:HighlightText;cursor:pointer;font:inherit}' +
    '.p{display:none;flex-direction:column;inline-size:min(22rem,calc(100vw - 2rem));block-size:min(32rem,calc(100vh - 6rem));background:Canvas;border:1px solid GrayText;border-radius:.75rem;overflow:hidden}' +
    '.p.o{display:flex}.h{display:flex;justify-content:space-between;align-items:center;padding:.5rem .75rem;border-block-end:1px solid GrayText}' +
    '.l{flex:1;overflow-y:auto;padding:.5rem;display:flex;flex-direction:column;gap:.375rem}' +
    '.m{max-inline-size:80%;padding:.375rem .625rem;border-radius:.625rem;white-space:pre-wrap;overflow-wrap:anywhere}' +
    '.in{align-self:flex-end;background:Highlight;color:HighlightText}.out{align-self:flex-start;border:1px solid GrayText}' +
    'form{display:flex;flex-direction:column;gap:.5rem;padding:.5rem}.row{flex-direction:row}' +
    'input,textarea,select{font:inherit;padding:.375rem .5rem;border:1px solid GrayText;border-radius:.375rem}' +
    '.row input{flex:1}button{font:inherit;cursor:pointer}.e{font-weight:600;padding-inline:.5rem}' +
    '[hidden]{display:none!important}' +
    '</style>' +
    '<div class="w" dir="' + (isRtl(lang) ? 'rtl' : 'ltr') + '" lang="' + lang + '">' +
    '<div class="p" role="dialog">' +
    '<div class="h"><strong class="tt"></strong><span><button type="button" class="end" hidden></button> <button type="button" class="x"></button></span></div>' +
    '<form class="pre"><label><span class="ln"></span><input name="name" required maxlength="100"></label>' +
    '<label><span class="le"></span><input name="email" type="email" maxlength="200"></label>' +
    '<label><span class="lm"></span><textarea name="message" required maxlength="2000"></textarea></label>' +
    '<button type="submit" class="go"></button></form>' +
    '<div class="l" aria-live="polite" hidden></div>' +
    '<p class="e" role="alert" hidden></p>' +
    '<form class="say row" hidden><input name="text" maxlength="2000" autocomplete="off"><button type="submit" class="sd"></button></form>' +
    '<form class="sv" hidden><span class="lr"></span><select name="rating"><option>5</option><option>4</option><option>3</option><option>2</option><option>1</option></select>' +
    '<textarea name="comment" maxlength="1000"></textarea><button type="submit" class="sb"></button></form>' +
    '</div><button type="button" class="fab"></button></div>';

  function q(sel) { return root.querySelector(sel); }
  var panel = q('.p'), list = q('.l'), err = q('.e'), pre = q('.pre'), say = q('.say'), survey = q('.sv');
  q('.tt').textContent = titleText;
  q('.fab').textContent = t.open;
  q('.x').textContent = t.close;
  q('.end').textContent = t.end;
  q('.ln').textContent = t.name;
  q('.le').textContent = t.email;
  q('.lm').textContent = t.message;
  q('.go').textContent = t.start;
  q('.sd').textContent = t.send;
  q('.lr').textContent = t.rate;
  q('.sb').textContent = t.submit;
  say.elements.text.placeholder = t.placeholder;
  survey.elements.comment.placeholder = t.comment;

  var token = null;
  try { token = sessionStorage.getItem(STORE); } catch (e) { token = null; }
  var since = null, stream = null, pollTimer = null, seen = {}, ended = false;

  function show(form) {
    pre.hidden = form !== pre;
    say.hidden = form !== say;
    survey.hidden = form !== survey;
    list.hidden = form === pre;
    q('.end').hidden = form !== say;
  }

  function fail(message) {
    err.textContent = message || '';
    err.hidden = !message;
  }

  function add(messages) {
    if (ended) return;
    (messages || []).forEach(function (m) {
      // The stream and the poll can both deliver a message: show it once.
      var key = messageKey(m);
      if (key && seen[key]) return;
      if (key) seen[key] = true;
      var div = document.createElement('div');
      div.className = 'm ' + (m.direction === 'inbound' ? 'in' : 'out');
      div.textContent = m.body;
      list.appendChild(div);
    });
    since = newest(since, messages);
    list.scrollTop = list.scrollHeight;
  }

  function remember(value) {
    token = value;
    try {
      if (value) sessionStorage.setItem(STORE, value); else sessionStorage.removeItem(STORE);
    } catch (e) { /* storage blocked: the chat lasts until reload */ }
  }

  function statusText(status) {
    if (status === 429) return t.busy;
    if (status === 404) return t.unavailable;
    return t.failed;
  }

  function post(text, done) {
    fetch(base + '/api/v1/omnichannel/webchat/message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_token: token, message: text })
    }).then(function (r) {
      if (!r.ok) { fail(statusText(r.status)); return null; }
      return r.json();
    }).then(function (body) {
      if (!body) return;
      fail('');
      var fresh = !token;
      remember(body.session_token);
      // The server keeps the visitor's message and any reply: fetch them.
      poll();
      if (fresh) listen();
      if (done) done();
    }).catch(function () { fail(t.failed); });
  }

  function poll() {
    if (!token) return;
    var url = base + '/api/v1/omnichannel/webchat/poll?token=' + encodeURIComponent(token) +
      (since ? '&since=' + encodeURIComponent(since) : '');
    fetch(url).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (body) { if (body) add(body.messages); })
      .catch(function () { /* the next poll tries again */ });
  }

  function listen() {
    stop();
    if (!token) return;
    if (typeof EventSource === 'undefined') {
      pollTimer = setInterval(poll, 4000);
      return;
    }
    var url = base + '/api/v1/omnichannel/webchat/stream?token=' + encodeURIComponent(token) +
      (since ? '&since=' + encodeURIComponent(since) : '');
    stream = new EventSource(url);
    stream.addEventListener('messages', function (e) {
      try { add(JSON.parse(e.data).messages); } catch (x) { /* a bad frame is skipped */ }
    });
    stream.onerror = function () {
      // The stream ended (its lifetime) or broke: poll until it is back.
      stop();
      pollTimer = setInterval(poll, 4000);
      setTimeout(listen, 15000);
    };
  }

  function stop() {
    if (stream) { stream.close(); stream = null; }
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  q('.fab').addEventListener('click', function () {
    panel.classList.toggle('o');
    if (panel.classList.contains('o')) {
      show(token ? say : pre);
      if (token) { poll(); listen(); }
    } else {
      stop();
    }
  });
  q('.x').addEventListener('click', function () { panel.classList.remove('o'); stop(); });
  q('.end').addEventListener('click', function () { show(survey); });

  pre.addEventListener('submit', function (e) {
    e.preventDefault();
    ended = false;
    list.textContent = '';
    var f = pre.elements;
    var text = firstMessage(t, f.name.value, f.email.value, f.message.value);
    if (!f.message.value.trim()) return;
    post(text, function () { show(say); });
  });
  say.addEventListener('submit', function (e) {
    e.preventDefault();
    var input = say.elements.text;
    var text = input.value.trim();
    if (!text) return;
    post(text, function () { input.value = ''; });
  });
  survey.addEventListener('submit', function (e) {
    e.preventDefault();
    var text = surveyMessage(t, survey.elements.rating.value, survey.elements.comment.value);
    post(text, function () {
      stop();
      remember(null);
      since = null;
      seen = {};
      list.textContent = '';
      add([{ direction: 'outbound', body: t.thanks, created_at: null }]);
      ended = true;
      show(null);
      list.hidden = false;
    });
  });
})();
