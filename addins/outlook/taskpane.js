/*
 * C7-T1: the Outlook add-in's task pane. It signs the person in to their
 * Attome deployment with the device grant, then for the open email shows the
 * sender's contact, account, open opportunities and cases, logs the email on
 * the contact, creates a lead or a case, and inserts a suggested reply while
 * composing. The logic is `AttomeMail` (../shared); this file is the fetch
 * driver and the page.
 *
 * The session is kept in the add-in's own storage (`localStorage` of the
 * add-in's origin), never in a cookie, and sent as `Authorization: Bearer`.
 */
var AttomeOutlook = (function () {
  'use strict';

  var CLIENT_ID = 'attome-outlook';
  var KEY = 'attome.outlook';

  function now() {
    return Math.floor(Date.now() / 1000);
  }

  /** The stored `{ url, session }`, or an empty one. */
  function load(storage) {
    try {
      return JSON.parse(storage.getItem(KEY) || '{}') || {};
    } catch (e) {
      return {};
    }
  }

  function save(storage, state) {
    storage.setItem(KEY, JSON.stringify(state));
  }

  /**
   * A driver over `fetchFn` and `storage`: `send(request)` sends one
   * `AttomeMail` request to the stored deployment with the session, refreshing
   * it first when it is about to expire. Answers `{ status, body }`.
   */
  function driver(fetchFn, storage) {
    var M = AttomeMail;

    function raw(url, request, session) {
      var headers = { Accept: 'application/json' };
      var body;
      if (request.form) {
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
        body = M.formBody(request.form);
      } else if (request.json) {
        headers['Content-Type'] = 'application/json';
        body = JSON.stringify(request.json);
      }
      if (session) headers.Authorization = M.bearer(session);
      return fetchFn(M.urlOf(url, request), { method: request.method, headers: headers, body: body }).then(
        function (response) {
          return response.text().then(function (text) {
            var parsed = null;
            try {
              parsed = text ? JSON.parse(text) : null;
            } catch (e) {
              parsed = null;
            }
            return { status: response.status, body: parsed };
          });
        },
      );
    }

    function session() {
      var state = load(storage);
      if (!state.url || !state.session) return Promise.resolve(null);
      if (!M.needsRefresh(state.session, now())) return Promise.resolve(state.session);
      return raw(state.url, M.refreshToken(CLIENT_ID, state.session.refresh_token)).then(function (answer) {
        var read = M.readToken(answer.status, answer.body, now());
        if (read.state !== 'ok') {
          save(storage, { url: state.url });
          return null;
        }
        save(storage, { url: state.url, session: read.session });
        return read.session;
      });
    }

    return {
      /** Sends an API request as the signed-in person; 401 when signed out. */
      send: function (request) {
        return session().then(function (current) {
          if (!current) return { status: 401, body: null };
          return raw(load(storage).url, request, current);
        });
      },
      /** Starts a sign-in to `url`; answers the device grant. */
      start: function (url) {
        save(storage, { url: url });
        return raw(url, M.deviceAuthorization(CLIENT_ID));
      },
      /** One poll; stores the session when it is `ok`. */
      poll: function (deviceCode) {
        var url = load(storage).url;
        return raw(url, M.pollToken(CLIENT_ID, deviceCode)).then(function (answer) {
          var read = M.readToken(answer.status, answer.body, now());
          if (read.state === 'ok') save(storage, { url: url, session: read.session });
          return read;
        });
      },
      signedIn: function () {
        return Boolean(load(storage).session);
      },
      signOut: function () {
        var state = load(storage);
        save(storage, { url: state.url });
      },
    };
  }

  return { CLIENT_ID: CLIENT_ID, driver: driver, load: load };
})();

/* ── The page ─────────────────────────────────────────────────────────────── */

/* global Office, document, window */
if (typeof Office !== 'undefined') {
  Office.onReady(function () {
    var M = AttomeMail;
    var lang = M.language(Office.context.displayLanguage);
    var api = AttomeOutlook.driver(window.fetch.bind(window), window.localStorage);
    var root = document.getElementById('app');
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
    var t = function (key, params) {
      return M.t(lang, key, params);
    };

    function el(tag, text, attrs) {
      var node = document.createElement(tag);
      if (text !== undefined && text !== null) node.textContent = text;
      Object.keys(attrs || {}).forEach(function (k) {
        node.setAttribute(k, attrs[k]);
      });
      return node;
    }

    function button(text, onClick) {
      var b = el('button', text, { type: 'button' });
      b.addEventListener('click', onClick);
      return b;
    }

    function status(text, kind) {
      var p = el('p', text, { role: kind === 'error' ? 'alert' : 'status', class: kind || 'status' });
      root.appendChild(p);
    }

    function failed(answer) {
      status(t('failed', { reason: (answer.body && (answer.body.message || answer.body.error)) || answer.status }), 'error');
    }

    function signInView() {
      root.textContent = '';
      root.appendChild(el('h1', t('signIn')));
      var label = el('label', t('deployment'), { for: 'url' });
      var input = el('input', null, { id: 'url', type: 'url', dir: 'ltr', placeholder: 'https://crm.example.com' });
      input.value = AttomeOutlook.load(window.localStorage).url || '';
      root.appendChild(label);
      root.appendChild(input);
      root.appendChild(
        button(t('start'), function () {
          var url = M.normaliseUrl(input.value);
          if (!url) return;
          api.start(url).then(function (answer) {
            if (answer.status !== 200) return failed(answer);
            var grant = answer.body;
            root.appendChild(el('p', t('enterCode', { url: grant.verification_uri, code: grant.user_code })));
            window.open(grant.verification_uri_complete, '_blank');
            waitFor(grant.device_code, (grant.interval || 5) * 1000);
          }, function () {
            status(t('offline'), 'error');
          });
        }),
      );
    }

    function waitFor(deviceCode, delay) {
      status(t('checking'));
      window.setTimeout(function () {
        api.poll(deviceCode).then(function (read) {
          if (read.state === 'ok') return mailView();
          if (read.state === 'pending') return waitFor(deviceCode, delay);
          if (read.state === 'slow_down') return waitFor(deviceCode, delay + 5000);
          status(t(read.state === 'denied' ? 'denied' : 'expired'), 'error');
        });
      }, delay);
    }

    function list(title, items, label) {
      root.appendChild(el('h2', title));
      if (!items.length) return root.appendChild(el('p', t('none'), { class: 'muted' }));
      var ul = el('ul');
      items.forEach(function (item) {
        ul.appendChild(el('li', label(item), { dir: 'auto' }));
      });
      root.appendChild(ul);
    }

    function message(item, done) {
      item.body.getAsync(Office.CoercionType.Text, function (result) {
        done({
          // A message being written has `subject.getAsync`, not a string.
          subject: typeof item.subject === 'string' ? item.subject : '',
          direction: typeof item.subject === 'string' ? 'inbound' : 'outbound',
          body: result.status === Office.AsyncResultStatus.Succeeded ? result.value : '',
          to: Array.isArray(item.to)
            ? item.to.map(function (r) {
                return r.emailAddress;
              })
            : [],
          sentAt: item.dateTimeCreated ? item.dateTimeCreated.toISOString() : null,
          messageId: item.internetMessageId || null,
        });
      });
    }

    /**
     * The other person of the open email: the sender of a message being
     * read, the first recipient of one being written.
     */
    function counterpart(item, done) {
      if (item.to && typeof item.to.getAsync === 'function') {
        item.to.getAsync(function (result) {
          var first = result.status === Office.AsyncResultStatus.Succeeded ? result.value[0] : null;
          done(first ? M.emailOf(first.emailAddress) : null, first ? first.displayName : '');
        });
        return;
      }
      done(item.from ? M.emailOf(item.from.emailAddress) : null, item.from ? item.from.displayName : '');
    }

    function mailView() {
      root.textContent = '';
      var item = Office.context.mailbox.item;
      root.appendChild(button(t('signOut'), function () {
        api.signOut();
        signInView();
      }));
      counterpart(item, function (from, displayName) {
        if (!from) return status(t('noSender'));
        show(item, from, displayName);
      });
    }

    function show(item, from, displayName) {
      api.send(M.contactByEmail(from)).then(function (answer) {
        if (answer.status === 401) return signInView();
        var contacts = M.rows(answer.status, answer.body);
        var view = M.summary(contacts, [], []);
        if (!view.found) {
          status(t('notFound', { email: from }));
          root.appendChild(button(t('createLead'), function () {
            api.send(M.createLead(displayName, from, null)).then(function (created) {
              return created.status === 201 ? status(t('leadCreated')) : failed(created);
            });
          }));
          return;
        }
        root.appendChild(el('h1', view.contact.name, { dir: 'auto' }));
        var related = view.accountId
          ? Promise.all([api.send(M.openOpportunities(view.accountId)), api.send(M.openCases(view.accountId))])
          : Promise.resolve([{ status: 200, body: null }, { status: 200, body: null }]);
        related.then(function (answers) {
          var full = M.summary(contacts, M.rows(answers[0].status, answers[0].body), M.rows(answers[1].status, answers[1].body));
          list(t('opportunities'), full.opportunities, function (o) { return o.name + ' · ' + o.stage; });
          list(t('cases'), full.cases, function (c) { return c.name + ' · ' + c.status; });
          root.appendChild(button(t('logEmail'), function () {
            message(item, function (msg) {
              api.send(M.logEmail('contact', view.contact.id, msg)).then(function (logged) {
                return logged.status === 201 ? status(t('logged', { name: view.contact.name })) : failed(logged);
              });
            });
          }));
          root.appendChild(button(t('createCase'), function () {
            message(item, function (msg) {
              api.send(M.createCase(msg.subject, msg.body, view.accountId)).then(function (created) {
                return created.status === 201 ? status(t('caseCreated')) : failed(created);
              });
            });
          }));
          if (item.body && item.body.setSelectedDataAsync) templatesFor(view.contact.id, item);
        });
      }, function () {
        status(t('offline'), 'error');
      });
    }

    function templatesFor(contactId, item) {
      api.send(M.replyTemplates('contact', contactId)).then(function (answer) {
        var found = M.templates(answer.status, answer.body);
        if (!found.length) return;
        root.appendChild(el('h2', t('templates')));
        found.forEach(function (template) {
          root.appendChild(button(t('insert') + ': ' + template.name, function () {
            item.body.setSelectedDataAsync(template.reply, { coercionType: Office.CoercionType.Text });
          }));
        });
      });
    }

    if (api.signedIn()) mailView();
    else signInView();
  });
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = AttomeOutlook;
}
