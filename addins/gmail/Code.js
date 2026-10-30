/*
 * C7-T1: the Gmail add-on (Apps Script, CardService). For the open message it
 * shows the sender's contact, open opportunities and cases from the person's
 * Attome deployment, logs the email on the contact, creates a lead or a case
 * and offers reply templates. It signs in with the device grant
 * (`attome-gmail`); the deployment address and the session are kept in the
 * person's own user properties. The logic is `AttomeMail`
 * (../shared/attome-mail-client.js, copied in by build.mjs); this file is the
 * synchronous `UrlFetchApp` driver and the cards.
 */

/* global AttomeMail, CardService, GmailApp, PropertiesService, Session, UrlFetchApp */

var CLIENT_ID = 'attome-gmail';

function lang_() {
  return AttomeMail.language(Session.getActiveUserLocale());
}

function t_(key, params) {
  return AttomeMail.t(lang_(), key, params);
}

function props_() {
  return PropertiesService.getUserProperties();
}

function state_() {
  var raw = props_().getProperty('attome');
  try {
    return raw ? JSON.parse(raw) : {};
  } catch (e) {
    return {};
  }
}

function saveState_(state) {
  props_().setProperty('attome', JSON.stringify(state));
}

function now_() {
  return Math.floor(Date.now() / 1000);
}

/** One request to `url`, synchronously: `{ status, body }`. */
function raw_(url, request, session) {
  var options = { method: request.method.toLowerCase(), muteHttpExceptions: true, headers: {} };
  if (request.form) {
    options.contentType = 'application/x-www-form-urlencoded';
    options.payload = AttomeMail.formBody(request.form);
  } else if (request.json) {
    options.contentType = 'application/json';
    options.payload = JSON.stringify(request.json);
  }
  if (session) options.headers.Authorization = AttomeMail.bearer(session);
  var response = UrlFetchApp.fetch(AttomeMail.urlOf(url, request), options);
  var body = null;
  try {
    body = JSON.parse(response.getContentText() || 'null');
  } catch (e) {
    body = null;
  }
  return { status: response.getResponseCode(), body: body };
}

/** The live session, refreshed when it is about to expire; null if signed out. */
function session_() {
  var state = state_();
  if (!state.url || !state.session) return null;
  if (!AttomeMail.needsRefresh(state.session, now_())) return state.session;
  var answer = raw_(state.url, AttomeMail.refreshToken(CLIENT_ID, state.session.refresh_token));
  var read = AttomeMail.readToken(answer.status, answer.body, now_());
  if (read.state !== 'ok') {
    saveState_({ url: state.url });
    return null;
  }
  saveState_({ url: state.url, session: read.session });
  return read.session;
}

function send_(request) {
  var current = session_();
  if (!current) return { status: 401, body: null };
  return raw_(state_().url, request, current);
}

function notify_(text) {
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text))
    .build();
}

function action_(name, params) {
  return CardService.newAction().setFunctionName(name).setParameters(params || {});
}

// ── Sign-in ──────────────────────────────────────────────────────────────────

function signInCard_(message) {
  var section = CardService.newCardSection()
    .addWidget(
      CardService.newTextInput()
        .setFieldName('url')
        .setTitle(t_('deployment'))
        .setValue(state_().url || ''),
    )
    .addWidget(CardService.newTextButton().setText(t_('start')).setOnClickAction(action_('startSignIn')));
  if (message) section.addWidget(CardService.newTextParagraph().setText(message));
  return CardService.newCardBuilder().setHeader(CardService.newCardHeader().setTitle(t_('signIn'))).addSection(section).build();
}

/** Asks the deployment for a device grant and shows its code. */
function startSignIn(event) {
  var url = AttomeMail.normaliseUrl(event.formInput && event.formInput.url);
  if (!url) return notify_(t_('deployment'));
  saveState_({ url: url });
  var answer = raw_(url, AttomeMail.deviceAuthorization(CLIENT_ID));
  if (answer.status !== 200) return notify_(t_('failed', { reason: answer.status }));
  var grant = answer.body;
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle(t_('signIn')))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText(
            t_('enterCode', { url: grant.verification_uri, code: grant.user_code }),
          ),
        )
        .addWidget(
          CardService.newTextButton()
            .setText(grant.verification_uri)
            .setOpenLink(CardService.newOpenLink().setUrl(grant.verification_uri_complete)),
        )
        .addWidget(
          CardService.newTextButton()
            .setText(t_('approved'))
            .setOnClickAction(action_('finishSignIn', { device_code: grant.device_code })),
        ),
    )
    .build();
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .build();
}

/** One poll, when the person says they approved it. */
function finishSignIn(event) {
  var state = state_();
  var answer = raw_(state.url, AttomeMail.pollToken(CLIENT_ID, event.parameters.device_code));
  var read = AttomeMail.readToken(answer.status, answer.body, now_());
  if (read.state === 'ok') {
    saveState_({ url: state.url, session: read.session });
    return notify_(t_('approved'));
  }
  if (read.state === 'pending' || read.state === 'slow_down') return notify_(t_('checking'));
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(signInCard_(t_(read.state === 'denied' ? 'denied' : 'expired'))))
    .build();
}

function signOut() {
  saveState_({ url: state_().url });
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(signInCard_()))
    .build();
}

// ── The open message ─────────────────────────────────────────────────────────

function message_(event) {
  GmailApp.setCurrentMessageAccessToken(event.gmail.accessToken);
  return GmailApp.getMessageById(event.gmail.messageId);
}

/** The contextual trigger: the card for the open message. */
function onGmailMessageOpen(event) {
  if (!session_()) return [signInCard_()];
  var message = message_(event);
  var from = AttomeMail.emailOf(message.getFrom());
  if (!from) return [simpleCard_(t_('noSender'))];
  var contactAnswer = send_(AttomeMail.contactByEmail(from));
  if (contactAnswer.status === 401) return [signInCard_()];
  var contacts = AttomeMail.rows(contactAnswer.status, contactAnswer.body);
  var view = AttomeMail.summary(contacts, [], []);
  if (!view.found) {
    var leadSection = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(t_('notFound', { email: from })))
      .addWidget(
        CardService.newTextButton()
          .setText(t_('createLead'))
          .setOnClickAction(action_('createLead', { email: from, name: message.getFrom().replace(/<.*>/, '').trim() })),
      );
    return [CardService.newCardBuilder().setHeader(CardService.newCardHeader().setTitle(t_('title'))).addSection(leadSection).build()];
  }
  var deals = view.accountId ? send_(AttomeMail.openOpportunities(view.accountId)) : { status: 200, body: null };
  var cases = view.accountId ? send_(AttomeMail.openCases(view.accountId)) : { status: 200, body: null };
  var full = AttomeMail.summary(contacts, AttomeMail.rows(deals.status, deals.body), AttomeMail.rows(cases.status, cases.body));

  var card = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader().setTitle(full.contact.name).setSubtitle(full.contact.title),
  );
  card.addSection(listSection_(t_('opportunities'), full.opportunities, function (o) { return o.name + ' · ' + o.stage; }));
  card.addSection(listSection_(t_('cases'), full.cases, function (c) { return c.name + ' · ' + c.status; }));
  var ids = { message_id: event.gmail.messageId, access_token: event.gmail.accessToken, contact_id: full.contact.id, contact_name: full.contact.name, account_id: full.accountId || '' };
  card.addSection(
    CardService.newCardSection()
      .addWidget(CardService.newTextButton().setText(t_('logEmail')).setOnClickAction(action_('logEmail', ids)))
      .addWidget(CardService.newTextButton().setText(t_('createCase')).setOnClickAction(action_('createCase', ids)))
      .addWidget(CardService.newTextButton().setText(t_('signOut')).setOnClickAction(action_('signOut'))),
  );
  var found = AttomeMail.templates.apply(null, (function () {
    var answer = send_(AttomeMail.replyTemplates('contact', full.contact.id));
    return [answer.status, answer.body];
  })());
  if (found.length) {
    var section = CardService.newCardSection().setHeader(t_('templates'));
    found.forEach(function (template) {
      section.addWidget(CardService.newDecoratedText().setTopLabel(template.name).setText(template.reply).setWrapText(true));
    });
    card.addSection(section);
  }
  return [card.build()];
}

function listSection_(title, items, label) {
  var section = CardService.newCardSection().setHeader(title);
  if (!items.length) section.addWidget(CardService.newTextParagraph().setText(t_('none')));
  items.forEach(function (item) {
    section.addWidget(CardService.newTextParagraph().setText(label(item)));
  });
  return section;
}

function simpleCard_(text) {
  return CardService.newCardBuilder()
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(text)))
    .build();
}

function messageOf_(params) {
  GmailApp.setCurrentMessageAccessToken(params.access_token);
  var message = GmailApp.getMessageById(params.message_id);
  return {
    subject: message.getSubject(),
    body: message.getPlainBody(),
    to: String(message.getTo() || '').split(',').map(AttomeMail.emailOf).filter(Boolean),
    sentAt: message.getDate().toISOString(),
    messageId: message.getHeader('Message-ID') || null,
  };
}

function logEmail(event) {
  var p = event.parameters;
  var answer = send_(AttomeMail.logEmail('contact', p.contact_id, messageOf_(p)));
  return notify_(answer.status === 201 ? t_('logged', { name: p.contact_name }) : t_('failed', { reason: answer.status }));
}

function createCase(event) {
  var p = event.parameters;
  var message = messageOf_(p);
  var answer = send_(AttomeMail.createCase(message.subject, message.body, p.account_id || null));
  return notify_(answer.status === 201 ? t_('caseCreated') : t_('failed', { reason: answer.status }));
}

function createLead(event) {
  var p = event.parameters;
  var answer = send_(AttomeMail.createLead(p.name, p.email, null));
  return notify_(answer.status === 201 ? t_('leadCreated') : t_('failed', { reason: answer.status }));
}
