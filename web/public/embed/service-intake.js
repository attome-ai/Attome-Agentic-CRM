/*
 * Attome service request form for another website (roadmap G2-T1).
 *
 *   <div id="attome-request"></div>
 *   <script src="https://crm.example.com/embed/service-intake.js"
 *           data-offering="<public offering id>"
 *           data-target="#attome-request"
 *           data-lang="ar" async></script>
 *
 * The form lives in a shadow root, so the page's styles do not reach it and
 * its styles do not leak out. It posts to
 * POST /api/v1/service-portal/offerings/{id}/requests on the server the
 * script came from; that server must list the page's origin in
 * cors.allowed_origins, and the offering must be in
 * service.anonymous_intake.offerings. When the server asks for proof of work
 * (429 with Attome-Challenge: pow) the script solves it and sends again; a
 * CAPTCHA provider's challenge is not supported here and is reported.
 * After a request is filed the person sees a status token to keep.
 */
(function () {
  'use strict';

  var script = document.currentScript;
  if (!script) return;
  var offering = script.getAttribute('data-offering') || '';
  if (!/^[0-9a-fA-F-]{36}$/.test(offering)) return;
  var lang = (script.getAttribute('data-lang') || document.documentElement.lang || 'en').slice(0, 2);
  var base = new URL(script.src).origin;
  var host = document.querySelector(script.getAttribute('data-target') || '') ||
    script.parentNode.insertBefore(document.createElement('div'), script);

  var TEXT = {
    en: {
      title: 'Subject', description: 'Details', name: 'Your name', email: 'Your email',
      send: 'Send request', sending: 'Sending...', working: 'Checking you are not a robot...',
      done: 'Your request was received. Keep this code to check its status:',
      notFound: 'This form is not available.', tooMany: 'Too many requests. Please try again in a minute.',
      challenge: 'This form needs a check this page cannot show. Please contact us another way.',
      invalid: 'Please check the fields and try again.', failed: 'The request could not be sent. Please try again.'
    },
    ar: {
      title: 'الموضوع', description: 'التفاصيل', name: 'اسمك', email: 'بريدك الإلكتروني',
      send: 'إرسال الطلب', sending: 'جارٍ الإرسال...', working: 'جارٍ التحقق من أنك لست روبوتًا...',
      done: 'استلمنا طلبك. احتفظ بهذا الرمز لمتابعة حالته:',
      notFound: 'هذا النموذج غير متاح.', tooMany: 'طلبات كثيرة. حاول مرة أخرى بعد دقيقة.',
      challenge: 'يحتاج هذا النموذج إلى تحقق لا تستطيع هذه الصفحة عرضه. تواصل معنا بطريقة أخرى.',
      invalid: 'راجع الحقول وحاول مرة أخرى.', failed: 'تعذّر إرسال الطلب. حاول مرة أخرى.'
    }
  };
  var t = TEXT[lang] || TEXT.en;

  var root = host.attachShadow({ mode: 'open' });
  root.innerHTML =
    '<style>' +
    ':host{display:block;font:14px/1.5 system-ui,sans-serif;color:CanvasText}' +
    'form{display:flex;flex-direction:column;gap:.75rem;max-inline-size:32rem}' +
    'label{display:flex;flex-direction:column;gap:.25rem}' +
    'input,textarea{font:inherit;padding-block:.375rem;padding-inline:.5rem;border:1px solid GrayText;border-radius:.375rem}' +
    'textarea{min-block-size:6rem}' +
    'button{align-self:flex-start;font:inherit;padding-block:.375rem;padding-inline:1rem;cursor:pointer}' +
    '.msg{margin:0}.code{font-family:monospace;user-select:all;word-break:break-all}' +
    '</style>' +
    '<form part="form" dir="' + (lang === 'ar' ? 'rtl' : 'ltr') + '" lang="' + lang + '">' +
    '<label>' + t.title + '<input name="title" required maxlength="200"></label>' +
    '<label>' + t.description + '<textarea name="description" maxlength="10000"></textarea></label>' +
    '<label>' + t.name + '<input name="name" maxlength="200" autocomplete="name"></label>' +
    '<label>' + t.email + '<input name="email" type="email" maxlength="200" autocomplete="email"></label>' +
    '<button type="submit">' + t.send + '</button>' +
    '<p class="msg" role="status" aria-live="polite"></p>' +
    '</form>';

  var form = root.querySelector('form');
  var button = root.querySelector('button');
  var msg = root.querySelector('.msg');

  function say(text) { msg.textContent = text; }

  function leadingZeroBits(bytes) {
    var bits = 0;
    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] === 0) { bits += 8; continue; }
      return bits + Math.clz32(bytes[i]) - 24;
    }
    return bits;
  }

  // The answer whose SHA-256 with the nonce starts with `difficulty` zero
  // bits (attome_auth::pow), tried in decimal order like the sign-in page.
  async function solve(nonce, difficulty) {
    var encoder = new TextEncoder();
    for (var n = 0; n < (1 << 26); n++) {
      var digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(nonce + n)));
      if (leadingZeroBits(digest) >= difficulty) return String(n);
    }
    throw new Error('no answer');
  }

  async function send(body) {
    return fetch(base + '/api/v1/service-portal/offerings/' + offering + '/requests', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    });
  }

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    var data = new FormData(form);
    var body = {};
    ['title', 'description', 'name', 'email'].forEach(function (key) {
      var value = String(data.get(key) || '').trim();
      if (value) body[key] = value;
    });
    button.disabled = true;
    say(t.sending);
    try {
      var response = await send(body);
      // A 429 is either a limit or a challenge; the challenge endpoint
      // answers only when proof of work is in force. (The Attome-Challenge
      // header is not readable from another origin unless CORS exposes it.)
      var unsolved = false;
      if (response.status === 429) {
        var issued = await fetch(base + '/api/v1/auth/challenge');
        if (issued.ok) {
          say(t.working);
          var challenge = await issued.json();
          var answer = await solve(challenge.nonce, challenge.difficulty);
          body.captcha_token = challenge.challenge + ':' + answer;
          response = await send(body);
        } else {
          unsolved = response.headers.get('attome-challenge') !== null &&
            response.headers.get('attome-challenge') !== 'wait';
        }
      }
      if (response.status === 201) {
        var accepted = await response.json();
        form.replaceChildren(msg);
        msg.textContent = t.done + ' ';
        var code = document.createElement('span');
        code.className = 'code';
        code.textContent = accepted.status_token;
        msg.appendChild(code);
        return;
      }
      say(response.status === 404 ? t.notFound
        : response.status === 422 ? t.invalid
        : unsolved ? t.challenge
        : response.status === 429 ? t.tooMany
        : t.failed);
    } catch (e) {
      say(t.failed);
    }
    button.disabled = false;
  });
})();
