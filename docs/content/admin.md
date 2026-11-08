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
- **Configuration as a folder**: `attome config pull --out <dir>` writes the deployment's bundle and
  its metadata objects, `attome config plan --dir <dir>` shows what a push would change, `attome
  config diff` shows the drift from the last applied bundle, `attome config push --dir <dir>`
  applies the plan and saves the objects as drafts (publish them to make them live), and `attome
  config rollback <bundle> --to <version>` queues a rollback. Push and rollback need `--yes`, and on
  a production target `--confirm-target <name>`; retiring anything needs `--allow-retire`.
- **Partner portal roles**: `attome partner portal-roles --portal <id>` sets up `partner_admin`,
  `partner_sales` and `partner_service` on a portal. They read only the member's own partner account.
  Assigning one binds the person to the partner of their contact, and refuses a person with no partner
  contact or an account at its `partner_user_limit`.
- **Rotating the attribute encryption key**: add the new key to `storage.attribute_encryption_key`, keep
  the old one, make the new one active, then run `attome secrets rewrap attributes`. It moves every
  encrypted field and its blind index in resumable batches.
- **Going back to a metadata version**: `GET /api/v1/admin/metadata/versions/{version}/preview` shows
  what would be added, removed and changed, and `POST .../{version}/switch` does it.
- **Moving one app**: `attome app export <app> --out <folder>` writes the app's objects, and
  `attome app install --dir <folder>` shows what is new and changed on the target; `--yes` imports
  and publishes them, stopping at the first refusal. `attome app remove <app>` lists what the app
  holds; with `--yes` it retires all of it in one step, refused while something outside the app
  still refers to it. Entities and their records stay, and installing the app again brings its
  objects back.
- **Promoting configuration**: `attome promote --dir <folder> --to <target> --copy <target> --report
  <file> --yes` plans on the target, applies to its masked copy first, then applies to the target,
  which on production waits for a second administrator. `--at <time>` holds the apply until then.
  `--only <entity,...>` promotes those entities with their fields, the entities their lookups need,
  and their queries, views and relationships, and leaves everything else on the target alone.
  On the target, **Admin → Environments** (`/xrm/admin/environments`) shows what was promoted in (the
  changeset ledger), what waits for the second administrator, and, from changeset files you choose, what
  they would create, change, retire or be blocked by there, without applying anything.
- **Applying an upgrade**: from the installed binary, `attome upgrade apply --manifest <file>
  --new-binary <path> --restart <command> --ready-url <url> --base-url <url> --admin-key-file
  <path> --no-role-key-file <path> --yes`. The restart command receives the binary to start in
  `ATTOME_BINARY`. After the restart it checks the migration count, the audit chain, a first page of
  up to 50 entities, sampled encrypted values, metadata drift, and that the no-role key is refused,
  then stores a signed report and marks the upgrade verified or failed. It needs
  `ops.drill_signing_key_path`, a manifest with `migration_count`, and a key made by an account with
  no roles; lacking any of these it refuses before changing anything. `--pgbackrest-stanza <name>`
  also takes an incremental backup at the safety point. `attome upgrade rollback --to <version> --restart <command>
  --yes` goes back until `attome upgrade contract --manifest <file> --dir <dir> --yes` has removed
  old structure; after that only a point-in-time restore to the recorded safety point does.
- **Before an upgrade**: `attome upgrade check --manifest <file> --free-bytes <n>` verifies the
  signed release manifest and reports the version path, the dependencies, free disk against twice
  the largest table, the last proven restore and the deprecated features in use. It reads the
  database directly and writes nothing; any fail exits 5.
- **Rehearsing an upgrade**: `attome upgrade rehearse --manifest <file> --old-binary <path>
  --new-binary <path> --admin-key-file <path> --key <drill signing key> --out <dir>` restores the
  newest backup into a throwaway database, runs the new migrations on it (the column changes become
  the report's schema changes), boots the new binary on port 7998 (five entity reads and every
  customer test) and the old binary on port 7997 against the new schema without migrating, as an old
  node runs during a rolling upgrade, then drops the copy. It writes `rehearsal-<version>.json` and
  signed Upgrade evidence (with `--base-url` it also stores the evidence on the deployment). Pass the
  report to `attome upgrade apply --rehearsal <file>` and the Upgrades page (`/xrm/ops/upgrades`)
  shows it with the upgrade.
  The report also lists the customer-layer conflicts (the open conflict items of the release report
  the new binary's boot wrote on the copy: the customer's value against the release's, names only for
  a record or a field you may not read), and `--customer-test-command <command>` runs your own test
  command with `ATTOME_URL` pointing at the upgraded copy, keeping its exit code and last 50 lines.
  Nothing is decided or applied on the live deployment.

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
- **Archive tier**: archived records of one entity and month can be kept together in one Parquet
  file in object storage (`archive-tier/{entity}/{yyyy}/{mm}/`), with an index of which file holds
  each record. The live row is cleared the way a single-record archive clears it, and any record
  restores exactly from its file. Only deleted records outside a legal hold are archived.
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
