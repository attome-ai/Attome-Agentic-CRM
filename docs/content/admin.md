# Admin guide

For the people who run a deployment: its users and roles, its settings, and keeping it healthy. Every
screen in the Administration area is a view over the HTTP API; the routes are named here so a task
can also be scripted with an API key.

## People and access

- **Users and invitations**: invite people by email (`/api/v1/admin/security/invitations`); a user
  signs in with a password and a second factor, or through the deployment's identity provider (OIDC).
- **Roles** (`/api/v1/admin/security/roles`) hold privileges and entity access: for each entity,
  what a role may read, create, update and delete, and how far (own records, team, organization,
  everyone) through `/api/v1/admin/security/role-entity-access`.
- **Teams, positions and record shares** extend access to the people around a record's owner.
- **Bulk reassign and share** (`/api/v1/admin/security/record-shares/bulk`): hand every record a
  leaver owns to someone else, or share a list of records, in the background. Send `preview: true`
  first to see how many records it changes; the job then works 500 at a time and shows its
  progress under **My background work**.
- **Field profiles** open sensitive fields (salaries, national IDs) to the roles that need them;
  everyone else sees them masked.
- **Access reviews** (`/api/v1/admin/security/access-reviews`) ask managers to confirm who still
  needs what.
- **Sessions**: revoke a person's sessions at once with `/api/v1/admin/security/sessions/revoke`;
  removing a role ends that person's sessions too.

## Settings

`/api/v1/admin/settings` lists every runtime setting with its value and where it came from; a person's
own choice wins, then their organization's, then the deployment's. Settings change without a
restart. Configuration that needs a restart lives in `config.json`; `docs/config-reference.md` lists
every key.

## Keeping it healthy

- **Status**: the banner at the top of the app says when something is down or slow; the operations
  overview shows nodes, jobs and recent requests.
- **Alerts**: built-in alerts are checked every minute. Set `observability.alert_emails` and
  `observability.alert_webhooks` to hear about them; each alert's email carries its runbook, filled
  with this deployment's addresses (`attome runbook <Alert>` prints it).
- **Limits**: `/xrm/admin/limits` shows each limit, its recent peak and a warning when callers come
  close; runtime limits are raised there within their range.
- **Jobs**: the dead-letter list (`/api/v1/admin/jobs/dead-letter`) holds jobs that failed for good;
  replay or discard them once the cause is fixed.
- **Backups**: `attome backup now`, `attome backup drill`, and `attome restore <archive|latest>`
  (see [backup](../backup.md)).
- **Drills**: `attome drill keygen --out <dir>` writes the drill signing key pair (put the public half in
  `ops.drill_public_keys`), `attome drill verify <report.json>` checks a drill report's signature, and
  `attome drill readiness` runs the preflight checks plus the drill's own (exit 2: bad signature,
  3: the drill failed, 4: not ready).

## Email

Email is off until `email.enabled` is set. Mail leaves through SMTP, Amazon SES or SendGrid, chosen
per sender address; each has a setup page: [SMTP](../email/smtp.md), [Amazon SES](../email/ses.md),
[SendGrid](../email/sendgrid.md). Before mailing customers, publish SPF, DKIM and DMARC for the
sending domain ([the sending domain](../email/sending-domain.md)). Every message is in the delivery
log (`/api/v1/admin/email/deliveries`, with resend), and addresses that must not be mailed are on
the suppression list (`/api/v1/admin/email/suppressions`). Development and copied deployments set
`email.test_mode_catch_all` so no real person is mailed. Bounce and complaint webhooks from SES and
SendGrid are not received yet.

## Records and compliance

- **Recycle bin**: deleted records wait in the bin; each entity's bin rules (reason required,
  retention days) are set at `/api/v1/admin/bin-settings/{entity}`.
- **Retention rules** (`/api/v1/admin/retention/rules`): per entity, a condition, the date the period
  starts from, the period and the action (purge, archive or review). Records past their period are
  proposed daily; nothing happens until a person approves the proposal.
- **Legal holds** stop deletion, purge and retention for the records they cover.
- **Audit**: every change is in the hash-chained audit log; search it from the audit screen, and
  `attome verify-audit-chain` checks the chain.
- **Data subject requests** (`/api/v1/admin/dsr`): access, correction and erasure requests with
  their legal deadlines.

## Master data

An entity marked as master data (an administrator sets it on the entity, which must belong to a data
domain) keeps one golden record per real-world thing, built from what each source system sends.

- **Golden record tab**: on the record's form, each value with the source system and id it came from,
  when it arrived and the rule that chose it. A steward pins a value to keep it when sources change,
  and unpins it to let the rules choose again; the contributions below can be detached.
- **Master data screen** (`/xrm/admin/master-data`): find a golden record by a source system's id, and
  work the held queue: contributions that failed the entity's validation wait there to be released
  (validated again and attached) or rejected with a reason.
- **Who may act**: anyone who can read the record sees its values and sources, never an attribute
  their field security hides. Pinning, releasing, rejecting and detaching need an owner or steward of
  the entity's data domain, or an administrator.
- **API**: `GET /api/v1/master/{entity}/xref?system=&external_id=`, `GET .../{id}/xref`,
  `GET .../{id}/provenance` and `GET .../{id}/as-of?at=` (the values held at a moment, from the change
  history).

## AI

AI is off until a model is approved. `/api/v1/admin/ai` holds the providers, the approved models,
budgets and the switch that turns every AI surface off at once. See [agents](../agents.md) and
[model servers](../model-servers.md).
