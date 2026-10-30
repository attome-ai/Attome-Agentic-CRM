/*
 * C7-T1: the logic the Outlook add-in and the Gmail add-on share, with no
 * framework and no I/O of its own. Every API call is described as a plain
 * request ({ method, path, form | json | query }) and every answer is read by
 * a pure function, so the Outlook task pane drives it with `fetch` (async)
 * and the Gmail add-on with `UrlFetchApp` (synchronous), and the tests drive
 * it with neither.
 *
 * It signs the person in with the deployment's device grant (RFC 8628,
 * docs/device-sign-in.md), finds the sender among contacts, shows the
 * contact's account, open opportunities and cases, logs the email as a
 * `communication` on a record, creates a lead or a case, and offers the
 * reply templates suggested for a record.
 *
 * Loaded as a browser script, a Node `vm` script or an Apps Script file: it
 * defines one global, `AttomeMail`.
 */
var AttomeMail = (function () {
  'use strict';

  var DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
  /** An access token this close to expiry (seconds) is refreshed first. */
  var REFRESH_MARGIN = 60;
  var OPEN_STAGES = ['prospecting', 'qualification', 'proposal', 'negotiation'];
  var OPEN_CASE_STATUSES = ['new', 'open', 'in_progress', 'waiting_on_customer'];
  var MAX_BODY_CHARS = 20000;

  var TEXT = {
    en: {
      title: 'Attome',
      signIn: 'Sign in to Attome',
      deployment: 'Your Attome address',
      start: 'Get a sign-in code',
      enterCode: 'Open {url} and enter the code {code}, then come back.',
      checking: 'Waiting for the approval…',
      approved: 'Signed in.',
      denied: 'The sign-in was refused.',
      expired: 'The code expired. Get a new one.',
      signOut: 'Sign out',
      noSender: 'This email has no sender address.',
      notFound: '{email} is not a contact.',
      contact: 'Contact',
      account: 'Account',
      opportunities: 'Open opportunities',
      cases: 'Open cases',
      none: 'None',
      logEmail: 'Log this email',
      logged: 'The email is logged on {name}.',
      createLead: 'Create a lead',
      leadCreated: 'Lead created.',
      createCase: 'Create a case',
      caseCreated: 'Case created.',
      templates: 'Reply templates',
      insert: 'Insert',
      failed: 'That did not work: {reason}',
      offline: 'Attome could not be reached.',
    },
    ar: {
      title: 'أتوم',
      signIn: 'تسجيل الدخول إلى أتوم',
      deployment: 'عنوان أتوم الخاص بك',
      start: 'احصل على رمز الدخول',
      enterCode: 'افتح {url} وأدخل الرمز {code} ثم عد إلى هنا.',
      checking: 'بانتظار الموافقة…',
      approved: 'تم تسجيل الدخول.',
      denied: 'تم رفض تسجيل الدخول.',
      expired: 'انتهت صلاحية الرمز. احصل على رمز جديد.',
      signOut: 'تسجيل الخروج',
      noSender: 'لا يوجد عنوان مرسل لهذه الرسالة.',
      notFound: '{email} ليس جهة اتصال.',
      contact: 'جهة الاتصال',
      account: 'الحساب',
      opportunities: 'الفرص المفتوحة',
      cases: 'الحالات المفتوحة',
      none: 'لا يوجد',
      logEmail: 'تسجيل هذه الرسالة',
      logged: 'تم تسجيل الرسالة على {name}.',
      createLead: 'إنشاء عميل محتمل',
      leadCreated: 'تم إنشاء العميل المحتمل.',
      createCase: 'إنشاء حالة',
      caseCreated: 'تم إنشاء الحالة.',
      templates: 'قوالب الرد',
      insert: 'إدراج',
      failed: 'لم ينجح ذلك: {reason}',
      offline: 'تعذر الوصول إلى أتوم.',
    },
  };

  /** `ar` for an Arabic locale, else `en`. */
  function language(locale) {
    return String(locale || '').toLowerCase().indexOf('ar') === 0 ? 'ar' : 'en';
  }

  /** The text `key` in `lang`, with `{name}` placeholders filled. */
  function t(lang, key, params) {
    var table = TEXT[lang] || TEXT.en;
    var text = table[key] || TEXT.en[key] || key;
    return text.replace(/\{(\w+)\}/g, function (match, name) {
      return params && params[name] !== undefined ? String(params[name]) : match;
    });
  }

  /** The deployment address the person typed: https, no trailing slash. */
  function normaliseUrl(url) {
    var trimmed = String(url || '').trim().replace(/\/+$/, '');
    if (!/^https:\/\/[^\s/]+/i.test(trimmed) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i.test(trimmed)) {
      return null;
    }
    return trimmed;
  }

  /** The address in `Name <a@b.com>` or `a@b.com`, lower case; null if none. */
  function emailOf(value) {
    var text = String(value || '');
    var angle = text.match(/<([^<>\s]+@[^<>\s]+)>/);
    var bare = angle ? angle[1] : (text.match(/[^\s<>"',;]+@[^\s<>"',;]+/) || [])[0];
    return bare ? bare.trim().toLowerCase() : null;
  }

  // ── Sign-in ────────────────────────────────────────────────────────────────

  function deviceAuthorization(clientId) {
    return { method: 'POST', path: '/api/v1/oauth/device_authorization', form: { client_id: clientId } };
  }

  function pollToken(clientId, deviceCode) {
    return {
      method: 'POST',
      path: '/api/v1/oauth/device/token',
      form: { grant_type: DEVICE_CODE_GRANT, client_id: clientId, device_code: deviceCode },
    };
  }

  function refreshToken(clientId, refresh) {
    return {
      method: 'POST',
      path: '/api/v1/oauth/device/token',
      form: { grant_type: 'refresh_token', client_id: clientId, refresh_token: refresh },
    };
  }

  /**
   * What a device token answer means: `ok` with the session, `pending`,
   * `slow_down`, `denied`, `expired`, or `error`. `now` is Unix seconds.
   */
  function readToken(status, body, now) {
    if (status >= 200 && status < 300 && body && body.access_token && body.refresh_token) {
      return {
        state: 'ok',
        session: {
          access_token: body.access_token,
          refresh_token: body.refresh_token,
          expires_at: now + (Number(body.expires_in) || 0),
        },
      };
    }
    var error = body && body.error;
    if (error === 'authorization_pending') return { state: 'pending' };
    if (error === 'slow_down') return { state: 'slow_down' };
    if (error === 'access_denied') return { state: 'denied' };
    if (error === 'expired_token' || error === 'invalid_grant') return { state: 'expired' };
    return { state: 'error', reason: (error || String(status)) };
  }

  /** Whether `session` must be refreshed before a call at `now`. */
  function needsRefresh(session, now) {
    return !session || !session.expires_at || session.expires_at - REFRESH_MARGIN <= now;
  }

  /** The `Authorization` header for `session`. */
  function bearer(session) {
    return 'Bearer ' + session.access_token;
  }

  // ── Looking the sender up ──────────────────────────────────────────────────

  function query(entity, filters, pageSize) {
    return {
      method: 'POST',
      path: '/api/v1/query/execute',
      json: {
        entity: entity,
        page: 1,
        page_size: pageSize || 5,
        search: '',
        order_by: '',
        order_dir: 'desc',
        filters: filters,
        include_total: true,
      },
    };
  }

  /** The contact with this email address. */
  function contactByEmail(email) {
    return query('contact', [{ field: 'email', op: 'eq', value: email }], 1);
  }

  /** The open opportunities of an account. */
  function openOpportunities(accountId) {
    return query('opportunity', [
      { field: 'account_ref', op: 'eq', value: accountId },
      { field: 'stage', op: 'in', value: OPEN_STAGES },
    ]);
  }

  /** The open cases of an account (the customer-service pack's tickets). */
  function openCases(accountId) {
    return query('service_ticket', [
      { field: 'customer_ref', op: 'eq', value: accountId },
      { field: 'status', op: 'in', value: OPEN_CASE_STATUSES },
    ]);
  }

  /** The rows of a query answer; none for a failed one (an entity not installed or not readable). */
  function rows(status, body) {
    if (status < 200 || status >= 300 || !body || !body.data || !body.data.records) return [];
    return body.data.records;
  }

  /** The id of a lookup value (`id` or `{ id }`), or null. */
  function refId(value) {
    if (!value) return null;
    if (typeof value === 'string') return value;
    return value.id || null;
  }

  /** What the pane shows for the sender. */
  function summary(contactRows, opportunityRows, caseRows) {
    var contact = contactRows[0] || null;
    if (!contact) return { found: false };
    return {
      found: true,
      contact: { id: contact.id, name: contact.full_name || contact.email || '', title: contact.job_title || '' },
      accountId: refId(contact.account_ref),
      opportunities: (opportunityRows || []).map(function (r) {
        return { id: r.id, name: r.name || '', stage: r.stage || '' };
      }),
      cases: (caseRows || []).map(function (r) {
        return { id: r.id, name: r.title || r.ticket_number || '', status: r.status || '' };
      }),
    };
  }

  // ── Writing ────────────────────────────────────────────────────────────────

  /**
   * Logs `message` ({ subject, body, from, to, sentAt, messageId }) as a
   * `communication` on the record `entity`/`recordId`.
   */
  function logEmail(entity, recordId, message) {
    var body = String(message.body || '');
    return {
      method: 'POST',
      path: '/api/v1/communication',
      json: {
        channel: 'email',
        direction: message.direction || 'inbound',
        entity_name: entity,
        record_id: recordId,
        subject: String(message.subject || '').slice(0, 500),
        body: body.length > MAX_BODY_CHARS ? body.slice(0, MAX_BODY_CHARS) : body,
        to_addresses: (message.to || []).join(', '),
        sent_at: message.sentAt || null,
        message_id: message.messageId || null,
        status: 'logged',
      },
    };
  }

  /** A lead for an unknown sender. */
  function createLead(name, email, company) {
    return {
      method: 'POST',
      path: '/api/v1/lead',
      json: { name: name || email, email: email, company_name: company || null, source: 'email' },
    };
  }

  /** A case from the email, for the sender's account. */
  function createCase(subject, body, accountId) {
    return {
      method: 'POST',
      path: '/api/v1/service_ticket',
      json: {
        title: String(subject || '').slice(0, 250),
        description: String(body || '').slice(0, MAX_BODY_CHARS),
        channel: 'email',
        customer_ref: accountId || null,
      },
    };
  }

  /** The reply templates suggested for a record. */
  function replyTemplates(entity, recordId) {
    return {
      method: 'GET',
      path: '/api/v1/model/reply-suggestions',
      query: { entity: entity, record_id: recordId, channel: 'email' },
    };
  }

  /** The templates of an answer: `[{ id, name, reply }]`. */
  function templates(status, body) {
    if (status < 200 || status >= 300 || !body || !body.items) return [];
    return body.items.map(function (s) {
      return { id: s.id, name: s.name, reply: s.reply };
    });
  }

  /** `request` as a URL with its query string, on `base`. */
  function urlOf(base, request) {
    var url = base + request.path;
    if (request.query) {
      var parts = Object.keys(request.query).map(function (k) {
        return encodeURIComponent(k) + '=' + encodeURIComponent(request.query[k]);
      });
      url += '?' + parts.join('&');
    }
    return url;
  }

  /** A form body, `a=1&b=2`. */
  function formBody(form) {
    return Object.keys(form)
      .map(function (k) {
        return encodeURIComponent(k) + '=' + encodeURIComponent(form[k]);
      })
      .join('&');
  }

  return {
    TEXT: TEXT,
    OPEN_STAGES: OPEN_STAGES,
    language: language,
    t: t,
    normaliseUrl: normaliseUrl,
    emailOf: emailOf,
    deviceAuthorization: deviceAuthorization,
    pollToken: pollToken,
    refreshToken: refreshToken,
    readToken: readToken,
    needsRefresh: needsRefresh,
    bearer: bearer,
    contactByEmail: contactByEmail,
    openOpportunities: openOpportunities,
    openCases: openCases,
    rows: rows,
    refId: refId,
    summary: summary,
    logEmail: logEmail,
    createLead: createLead,
    createCase: createCase,
    replyTemplates: replyTemplates,
    templates: templates,
    urlOf: urlOf,
    formBody: formBody,
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = AttomeMail;
}
