# Changelog

Every release lists what changed for administrators, users and developers. A breaking change to
`/api/v1` (a removed or renamed route, a removed response status or field, a newly required request
field, a changed type) is named under `### Breaking` in the `[Unreleased]` section in the same change
that makes it; the release gate's contract step refuses a release that breaks the API silently.

## [Unreleased]

### Security
- Legal holds block every delete (K1-T3): a record under an active hold (on it, or on its whole
  entity) now refuses an ordinary delete into the recycle bin with 409, not only a hard delete, on
  every path (single, bulk, agent, portal, merge); a held document also survives its file field
  changing. Documents gain a `document_type` (contract, invoice, identity, correspondence, policy,
  report, other), so a retention rule can target one type.
- Weekly rescan (K2-T2): every file promoted in the last 30 days is scanned again once a week with
  the scanner's current signatures (the `UploadRescanSweep` job, 200 files a run, migration 0127). A
  file now found infected moves under the quarantine prefix so nothing serves it, its upload is marked
  rejected with an audit event, and the uploader and administrators are told.
- Malware in an upload (K2-T1): when the virus scanner finds malware, the uploader (a staff user) is
  told their file was blocked and every administrator gets the file, record, field and signature;
  the file stays quarantined and is never served, as before. An unclear scanner answer keeps the
  file pending. `attome_notification::dispatch::alert_admins` now holds the administrator alert
  that `attome-ai` used.
- `attome secrets` (Z1-T9): `generate --env-file <path>` fills the secrets an install issues itself
  (encryption keys, peppers, role passwords) that are missing from an env file, never a provider's
  credential and never an existing value; `rotate <VAR>` turns a key-ring secret into
  `ring:<new>=…;<old>=…` after a `.bak` copy, so the old key stays readable; `rewrap <domain>`
  starts the rewrap through the API. No subcommand prints a secret.
- The `secrets.list` agent action (Z1-T13, administrators): each configured secret's name, the
  features that use it, whether it is set and its active key's age in days. Never a value or key id.
- Rejection counts (Z5-T11): every protective layer counts its refusals in
  `http_rejections_total{layer, reason}` with fixed reasons (`waf`, `flood`, `pre_auth_rate_limit`,
  `rate_limit` with `limit`/`temporary_ban`/`account_budget`, `body_limit`, `host_gate`, `csrf`,
  and `auth` with `no_credential`, `invalid_session`, `invalid_api_key`, `revoked_token`,
  `epoch_stale`, `ip_not_allowed`), and the new `HttpRejectionsSpike` alert fires when a layer
  refuses ten times its hourly average. `security_rejection_total` is unchanged.
- Flood protection (Z5-T5), right after the web firewall and before sign-in: at most
  `app.max_concurrent_requests` (default 1024) requests run at once on a node, past which a request
  is `503 overloaded`, and at most `app.max_concurrent_per_ip` (default 64) from one address, past
  which it is `429`; both with `Retry-After: 1`. Refusals count in
  `http_rejections_total{layer="flood"}`.
- A basic web firewall (Z5-T4) runs before body limits, rate limits and sign-in: more than 100
  headers, a header value or URI over 8 KiB, a `..` path segment (plain or percent-encoded), `%00`,
  a raw backslash, or a double-encoded dot, slash, backslash or NUL is `400 request_rejected` (new
  error code). A literal `%` or `..` inside a path value (alternate-key lookups) still passes.
  Refusals count in `http_rejections_total{layer="waf",reason}` and log the reason, never the URL;
  `/api/` requests with no `User-Agent` count in `http_waf_signal_total` and are not refused.
- A self-hosted proof-of-work challenge (Q20-T3): `portal.captcha.provider = "pow"` (the default
  on a sovereign deployment with no provider) needs no outside service. `GET /api/v1/auth/challenge`
  hands out a signed, two-minute challenge (`portal.captcha.pow_difficulty`, default 18 bits); an
  answer is accepted once. A challenged sign-in's `429` carries `Attome-Challenge`, and the sign-in
  page solves the challenge in a Web Worker and retries; portal sign-up accepts it too.
- Session and pending tokens can be signed with Ed25519 (Z4-T3): `auth.jwt_signing_keys` holds
  32-byte seeds (64 hex characters) by key id. With an active key, new tokens are EdDSA under it;
  HS256 tokens already issued keep verifying under `auth.jwt_secret` until they expire, and any
  other `alg` is refused. Empty (the default) keeps HS256. A malformed seed fails config load,
  naming the key id only.
- Sign-in slows down and resists password spraying (Q20-T2): after three failed sign-ins in a row
  an account's attempts wait 1, 2, 4, 8, 16 and then 30 seconds (never past the request timeout
  less five seconds) before the password is checked, and a success clears the streak. Ten
  different accounts failing from one address in ten minutes challenge that address for ten
  minutes: a sign-in from it needs `captcha_token` accepted by `portal.captcha`, or gets `429`
  when no provider is configured. Both triggers write a `FailedLogin` security event
  (`login.backoff_started`, `login.spray_detected`) naming only the hashed address.
- Stored third-party secrets are bound to their row (Q18-T2): integration credentials, AI
  provider keys, S2S client-key secrets and event webhook secrets are now sealed with envelope
  version 2, whose AES-GCM associated data is `table|column|row_id`, so a ciphertext copied to
  another row does not decrypt. Values written before this still open; the S2S rewrap job
  re-seals them bound.
- Stored idempotency responses can be sealed (S9-T3): with `idempotency.response_encryption_key`
  (a key ring), a durable record's response body is encrypted with AES-256-GCM, bound to the
  record's id, and its key id is kept in `idempotency_record.response_key_id` (migration 0119);
  a replay decrypts it. Without the key, bodies are stored as before.
- The audit chain is verified every week (Q16-T2): the `AuditChainVerify` job runs the same checks
  as `verify_audit_chain` for every organization, records each result in
  `audit_chain_verification` (migration 0117) and, on a failure, logs
  `audit.chain_verify_failed` and counts `audit_chain_verify_failures_total`.
- Every API response now says how it may be cached (AA7-T1): writes and every read of
  credentials, tokens, keys, sessions, secrets or exports answer `Cache-Control: no-store`; other
  API reads answer `private, no-cache` with `Vary: Authorization, Cookie`; a handler's own
  `Cache-Control` still wins.
- Cooked artefacts at hash-named URLs (AA7-T5): `GET /api/v1/cooked/{kind}` lists the published
  forms or option sets with each artefact's content hash and URL, and `GET
  /api/v1/cooked/{kind}/{hash}` serves the artefact as `private, max-age=31536000, immutable`
  (new cache class `private-immutable`), Brotli-encoded when accepted, so a browser downloads each
  once per version. Other kinds answer 404.
- Revoked session tokens stay revoked across a restart without Redis (Z4-T5): with
  `cache.backend = memory` the token denylist lives in Postgres (`auth_jti_denylist`, migration
  0114) instead of process memory, still failing closed on a database error; the auth token prune
  job deletes expired entries.
- Optional online breached-password check (Z4-T9): with `auth.breach_check_online`, registration
  and password reset also ask a k-anonymity range service (`auth.breach_range_url`, Have I Been
  Pwned's by default); only the first five hex characters of the password's SHA-1 leave the
  server, the answer is matched locally, and an unreachable service is logged and skipped (the
  offline list still applies). Off by default.
- Sign-in honours a role's concurrent-session limit (`role_auth_policy.max_sessions`, Q8-T6): at the
  limit it ends the person's least recently active sessions, or with `max_sessions_mode =
  refuse_new` refuses with `409 conflict` (`session_limit_reached`) and audits the refusal. Agent
  sessions never count; the strictest of the person's roles applies.
- ammonia 4.2.4 (RUSTSEC-2026-0373, CSS `url()` matched case-sensitively) and zip 9.0.5 through
  rust_xlsxwriter 0.100 (RUSTSEC-2026-0367, -0368, -0369, extraction permissions and symlinks).
- An erasure answers with a certificate: what was erased, when, by whom, its SHA-256 digest and
  the audit key's signature when one is configured. Legal holds still refuse the erasure.
- Data profiles keep only the shapes (`999-AAA`) of a personal, special-category or masked
  attribute's sample, minimum and maximum values, never the values.
- Workflow nodes no longer act as an administrator: a flow runs as its starter (an entity- or
  schedule-triggered run as the version's publisher), or as its own service account with
  `settings.run_as: "flow_identity"` + `run_as_user_id`; record writes need the entity privilege.
- A new password found in an offline breached-password set is refused (a small list ships;
  `auth.breach_list_file` loads the full Have I Been Pwned SHA-1 download, checked locally), and
  a password reset may not reuse the current password or any of the last five (migration `0040`).
- rustls 0.23.46 (RUSTSEC-2026-0346 to 0349).
- A password reset with an already used token answers `409` whatever password it carries.
- Removing a role from a user, or resetting their MFA, now ends the user's sessions everywhere at once
  (refresh tokens revoked and the auth epoch bumped in the same transaction), like disabling them.
- A caller (a user, or an address when anonymous) that trips a rate limit in five separate windows
  within an hour is refused outright for 15 minutes (`429` with `Retry-After`). Rate-limited
  responses also carry the IETF `RateLimit-Policy` and `RateLimit` headers.
- A JSON request body nested deeper than 64 levels, or with an array of more than 10,000 items, is
  refused with `413 payload_too_large` before authentication or any handler reads it.
- Pages carry `Permissions-Policy` (camera, microphone and location for this origin only) and
  `Cross-Origin-Opener-Policy: same-origin-allow-popups`; API responses deny every browser feature
  and carry `Cross-Origin-Resource-Policy: same-origin`.

### Added
- Email capture (D15-T2): emails in a connected Microsoft 365 or Gmail mailbox that involve known
  contacts or leads are captured once each and appear on the timelines of every matching contact,
  lead and open opportunity of their accounts. Private, automatic and bulk mail is skipped, as are
  addresses at excluded domains (`mail_capture.excluded_domains`). People can turn capture off
  (`mail_capture.enabled`). Migration 0147.
- Mailbox readers (J2-T1): a `mailbox` integration system reads IMAP (over TLS), Microsoft 365
  (Graph delta) or Gmail (history) mailboxes incrementally, each message once, through the
  connector's `pull`. Two new Rust dependencies, `async-imap` and `mail-parser`, both pure Rust.
- Browser softphone (J6-T2): with a Twilio voice system that has an API key, a TwiML app and the
  SDK's address, agents take and place calls in the browser. An incoming call pops the caller's
  record. `tel:` links on a record call through the softphone (or ring the agent's own phone when
  there is no softphone). New routes: `GET /api/v1/voice/softphone` and `GET /api/v1/voice/lookup`,
  plus `POST /api/v1/voice/twilio/{key}/client` for the TwiML app. `POST /api/v1/voice/calls` takes
  `mode`.
- Call recordings and outcomes (J6-T3): when a call ends, whoever placed it is asked for its
  outcome in the app. Its recording is fetched from the provider (only from Twilio's API host or the
  PBX's own address), stored as a document on the call through the upload pipeline and virus scan,
  and sent to transcription (the `voice_recording` job). Uploads now accept audio: MP3, WAV, Ogg and
  M4A.
- Calls (J6-T1): with a Twilio Voice or Asterisk voice system, `POST /api/v1/voice/calls` rings the
  caller's own phone (personal setting `voice.agent_number`) and then the customer, logging a phone
  call on the record. Calls to the Twilio number or reported by the PBX open a phone call on the
  matching contact. Ringing, answer, hang-up and the recording link update the call as they happen;
  a missed call is noted. Migration 0146.
- Social channels (J8-T1): Messenger messages, Instagram messages and comments, and Facebook page
  comments arrive through Meta's signed webhook (`/api/v1/social/meta/{key}`). New Google Business
  Profile reviews are read every 15 minutes. Each one becomes an inbound communication (new
  channels `messenger`, `instagram`, `facebook` and `google_review`). Staff answer them with
  `POST /api/v1/social/replies`, which sends through the provider and records the reply in the same
  thread.
- Booking links (D20-T2): a booking page (sales pack, `booking_page`) gives prospects a public
  link, `/book/{slug}`, listing the times someone on its team is free. Those times respect working
  hours, holidays and absences, Attome meetings, and the person's connected calendar. A booking goes
  round robin to a free member, becomes a meeting activity on the matching contact or lead (or a new
  lead) and lands in their calendar. The prospect gets an email with a signed link to reschedule or
  cancel. New public routes under `/api/v1/booking/`, migration 0145.
- Calendar sync (D15-T3): meeting activities a person owns sync both ways with the Microsoft 365
  or Google calendar they connected (D15-T1), every five minutes (the `calendar_sync` job,
  migration 0144). When both sides changed, the later edit wins and the other side's values are
  kept in `calendar_sync_conflict`; an event deleted in the calendar cancels the meeting.
- Video meetings on activities (J7-T2): a "Video meeting" activity creates a Teams, Meet, Zoom or
  Jitsi meeting and shows a Join button from 15 minutes before it starts.
- Offline use (B17-T4, B18-T4, B18-T5, B18-T12): `POST /api/v1/devices`, `GET /api/v1/devices/me/{id}`
  and `POST .../wiped` for the app; `GET /api/v1/offline/profile` (metadata and rules, never a
  sensitive attribute), `POST /api/v1/offline/pull` (records through the profile's stored query,
  with removals) and `POST /api/v1/offline/push` (queued changes, once each, merged per field); `GET /api/v1/admin/devices` with each device's sync state,
  `POST /api/v1/admin/devices/{id}/wipe` and `POST .../offline-refresh`. See
  [docs/offline.md](docs/offline.md).
- Scanning (B16-T5, B16-T8, B16-T13): `GET /api/v1/scan/find` finds the records a scanned value
  belongs to among scan-enabled fields, under the caller's permissions; `POST /api/v1/scan/act` runs
  a scan action (open, start its flow at a `scan` trigger, or set a field) with one audit event,
  behind the `scan.actions_enabled` flag. Agents get `scan.lookup` and `code.generate`. See
  [docs/scanning.md](docs/scanning.md).
- Batch document generation (K3-T3): `POST /api/v1/docgen/templates/{id}/render-batch` renders a
  template for up to 500 records, one render job each (attached to its record when the template names
  a field), and `GET /api/v1/docgen/batches/{batch_id}` counts them pending, running, completed,
  failed and attached (migration 0129).
- Page audiences and preview links (K5-T2): a content page is `public` or `internal`
  (`PUT /api/v1/admin/content/pages/{id}/audience`, migration 0128). The public view and delivery
  routes answer an internal page with the same 404 as a missing one; signed-in people read it at
  `GET /api/v1/content/internal`. `POST .../preview-link` makes a signed link (1 minute to 7 days) to
  the page's draft, opened at `GET /api/v1/content/preview?token=` without signing in.
- Headless delivery (K5-T3): `GET /api/v1/content/delivery?space=&path=` serves a published page's
  latest version (title, SEO text, blocks) as JSON without signing in, with an ETag naming the page and
  version so a client revalidates with `If-None-Match` and gets 304 until the next publish.
- Guided tours (B14-T1): a `tour` metadata kind (title, app route, roles, whether it starts by itself,
  and steps with a CSS selector and English/Arabic text, edited like any other kind and by agents as
  `model.tour.*`). `GET /api/v1/model/tours` gives a signed-in person the published tours for their
  roles. The web app starts a route's tour once per person (remembered in the personal setting
  `core.tours_seen`), highlights each step's element with a bubble in the page language, and offers
  "Show this page's tour" in the profile menu.
- Documentation site (AC9-T1): `node scripts/docs-build.mjs` builds static HTML from `docs/` in
  English and Arabic (right to left, `docs/ar/`, untranslated pages marked) with an API reference
  generated from `openapi.json`, one folder per version. No dependencies beyond Node.
- Anonymous service requests (G2-T1): `POST /api/v1/service-portal/offerings/{id}/requests` files a
  request on a public offering from a web form without signing in, off by default: the offering must
  be in `service.anonymous_intake.offerings` and `service.anonymous_intake.user` must name the service
  account requests are filed as. Five requests a minute per address and sixty per offering; the
  deployment's challenge (proof-of-work or CAPTCHA) when one is configured. The answer is the status
  token for `GET /api/v1/service-portal/status`. `/embed/service-intake.js` puts the form on another
  site in a shadow root (Arabic or English, solves proof-of-work); that site's origin goes in
  `cors.allowed_origins`.
- Page versions (K5-T1): every publish of a content page (by hand, by its schedule, or approved)
  keeps a numbered version (migration 0126). `GET /api/v1/admin/content/pages/{id}/versions`,
  `.../versions/{number}`, `.../versions/compare?from=&to=` (title, SEO and each block added,
  removed, changed or moved) and `POST .../versions/{number}/restore` (the old version becomes the
  draft and is published as a new version naming it). A space with `require_approval` sends every
  publish and restore through the approval engine (`content.page_publish`); scheduled publishing does
  not apply in such a space.
- Document templates in the template language (K3-T1): document generation renders a template with
  Z13 (`{{ total | currency('SAR') }}`, `hijri`, `date`, `number`, `{% if %}`, `{% for line in
  invoice_line limit 100 %}` over related records, `{% dir %}`) in the record's own `language` or the
  deployment's, before PDF conversion. Related lists hold only the child records and fields the
  requesting user may read. `{{ zatca_qr }}` is the ZATCA simplified-invoice QR (an SVG `data:` URI
  for `<img src>`) from `billing.seller_name`, `billing.seller_vat_number` and the record's
  `grand_total` and `vat_total`.
- Retention rules (R3-T1): `GET`/`POST /api/v1/admin/retention/rules` and `PUT`/`DELETE
  /api/v1/admin/retention/rules/{id}` (administrators, Configuration audit events) keep rules per
  entity and category: a filter condition, the date the period starts from (`created_at`,
  `modified_at` or a date attribute such as a closed date or contract end), the period in days and
  the action (`purge`, `archive` or `review`). The daily retention sweep proposes every live record
  past its rule's period (`rule_purge`, `rule_archive`, `rule_review`, migration 0125), never one
  under a legal hold. An approved review keeps the record; an approved purge or archive deletes it
  as the approver (audited, into the recycle bin) and then purges or archives it.
- First-run region setup (X12-T3): `GET`/`POST /api/v1/admin/setup/region` (administrators) list the
  countries the regions pack presets and set the deployment up for one: the pack is installed (the
  same idempotent path as `attome init --pack regions`) and the deployment's `core.country` (new),
  `core.locale`, `core.time_zone` and `core.calendar` are set. The web app's wizard
  (`/xrm/admin/first-run`, Arabic by default) asks for country, language and calendar, and an
  administrator sees a prompt leading to it until a country is set.
- Alert runbooks (AB10-T3): every alert in `observability/alerts.yml` and `builtin-alerts.json` has
  its own `observability/runbooks/<Alert>.md` (meaning, checks, fix, escalation), and every rule
  links to its file. Placeholders are filled with the deployment's addresses (never a secret): a
  firing built-in alert's email and webhook message carry the filled runbook, and
  `attome runbook <Alert>` prints it. `observability/RUNBOOK.md` is now the index.
- Chunked batch jobs (Z7-T4): a long job runs in chunks, each committed with its checkpoint and
  progress (`job_batch`, migration 0124), so a job killed mid-way resumes after its last committed
  chunk. `GET /api/v1/jobs/{id}` shows its status and progress and `POST /api/v1/jobs/{id}/cancel`
  stops it after the current chunk, for the person who started it or an administrator.
- The portal cache is two declared caches (Z3-T8), `attome-portal:portal` and `attome-portal:plan`,
  listed in `/api/v1/admin/caches`. Same TTL, capacity and keys; a generic write of a portal record
  now also drops its cached entry through the change feed.
- Calendar schedules (Z7-T2): a scheduled job can run on a five-field cron expression, once at an
  instant, on a Hijri day of each month or on every working day of a business calendar, each in a
  chosen time zone (`attome_jobs::schedule::Schedule`, claimed by `schedule::tick_at` once per slot
  across workers). A wall time skipped by a daylight-saving change runs one hour on; a repeated one
  runs once. Migration 0123 adds `job_schedule.schedule`.
- Secret inventory (Z1-T8): `GET /api/v1/admin/secrets` lists every secret the configuration holds by
  path, with the features that use it, its key ids, the active one, since when it has been active and
  its age, and never a value. Each start records them in `secret_inventory` (migration 0120). A daily
  job tells administrators about a secret older than `security.secret_max_age_days` (default 365,
  `0` off), at most once every 30 days per secret.
- Change-feed cache invalidation (Z3-T5): a `TieredCache` value read with `get_or_load_depending` is
  recorded under the entities and records it came from, and every node drops it within about a second
  of a write to one of them, by reading the entity change feed (no Redis needed); a record write also
  rings `attome-cache:invalidate` so nodes read at once.
- Automatic merge of a stale update (A16-T2): `PATCH /api/v1/{entity}/{id}` with
  `If-Match-Merge: attributes` and an `If-Match` version that is out of date is applied at the current
  version when none of the attributes it sends changed since that version, and answers 200 with
  `merged_over` (the attributes others changed; `merged_hidden` counts those the caller cannot read).
  An overlap, or a version the record's change history cannot account for, is the usual 409. Change
  events of generic updates now carry the row version they wrote (migration 0121).
- Job chains and fan-out (Z7-T5): a registered job can name the job to run after it
  (`RegisteredJob::then`), and `attome_jobs::chain::fan_out` runs several jobs in parallel and a final
  one once all have succeeded. Each follow-up is enqueued at most once even when a job is retried
  (`job_chain_step`, `job_group`, migration 0122).
- Job types registered at run time (Z7-T1): `attome_jobs::JobRegistry` maps a job name to its
  declaration (`JobType`: payload version, lane, priority, attempts, per-node concurrency cap) and
  handler, and `EngineJob::Registered` carries `{name, version, payload}`, so an engine adds a job
  with `attome_core::jobs::JOB_TYPES.register(...)` instead of a new enum variant. A job naming a
  type the worker does not have fails with `unknown_job_type` and ends in the dead letters; one
  written by a newer payload version fails with `newer_job_version` until the node is upgraded.
- `Server-Timing` response header (AA1-T5): `mw`, `auth`, `perm`, `db`, `app` and `ext` durations in
  milliseconds, phase names only. `observability.server_timing` says who gets it: `dev` (the
  default; every response, with `APP_ENV=debug` only), `admins` (responses to administrators) or
  `off`. While it can be sent, sqlx's per-statement debug events are enabled for the timing layer
  (log output is unchanged), which costs a little on every query.
- Configuration schema (Z1-T4): `config.schema.json` (JSON Schema, derived from the typed sections
  with `schemars`; secrets are `writeOnly` and carry no default) and `docs/config-reference.md` (one
  table per section: key, type, default, secret, description). Both are generated by
  `attome-config`'s `config_schema` test, which fails when a section changes without them; rewrite
  them with `ATTOME_WRITE_CONFIG_SCHEMA=1`.
- Changing a record's type (A27-T3): `POST /api/v1/{entity}/{id}/change-type?preview=true` lists the attributes
  holding a value the new type's form does not show and the stage a record of that type starts in; without
  `preview` it changes the type through the ordinary audited update (`row_version` required), clearing only
  the attributes named in `clear`.
- Record types per role (A27-T2): a record type may name the roles that may create it (`roles`) and the roles
  it is the default for (`default_for_roles`). A create that names no type gets its role's default, else the
  entity's default, and the type's `defaults` fill fields left out; a type the caller's roles may not use
  answers 403, and an unknown one 422.
- Record types (A27-T1): a `record_type` metadata kind (entity, code, English and Arabic labels, form, stage
  process, default values, a default flag). Publishing an entity's first type gives its table a nullable
  `record_type` text attribute, without rewriting existing rows: an empty type means the entity's default.
- A safe-SQL census (Z2-T11): `crates/apps/attome/tests/safe_sql_census.rs` finds every `format!` that builds an
  SQL statement with an argument other than `quote_ident(...)`, a constant or a number. Today's 335, in 104
  files, are baselined per file in `safe_sql_census.json`; the counts may only fall.
- The middleware order is pinned (Z5-T1): `attome_server::app::PIPELINE_ORDER` names the layers outermost
  first. A debug build with `app.debug_pipeline_trace` adds `x-attome-layers` to every response, and
  `middleware_pipeline.rs` checks the two match. New tests prove the size, rate, CSRF and authentication
  rejections answer without reading the request body.
- The release gate requires a version adapter for every breaking change (S8-T5): the OpenAPI document
  publishes `x-api-version` and the adapter chain as `x-version-adapters`, `attome release --check` fails on a
  break no adapter step covers, and `attome release --tag` writes `docs/api-versions/v{version}.md` listing
  every break and its adapter.
- The OpenAPI document describes outbound webhooks (S2-T12): a top-level `webhooks.entityChanged` with the
  `WebhookPayload` body, the `X-Attome-Signature` header (HMAC-SHA256 over `<t>.<body>`), the
  `Idempotency-Key` header and the retry schedule.
- Decrypted secrets cannot be printed (Q18-T5): `attome_auth::envelope::decrypt` and `decrypt_bound` return
  `attome_types::secret::SecretString`, whose `Debug` prints `[redacted]` and which has no `Display` or
  `Serialize`; the buffer is zeroed on drop. Reading it is `expose_secret()` or `into_exposed()`.
- Second administrator for an administrator's MFA reset (Q5-T8): `POST /api/v1/admin/security/users/{id}/mfa/reset`
  now needs a fresh step-up (`admin_mfa_reset`); resetting an administrator's factor answers `202` with an
  approval request (`security.mfa_reset_admin`) that a second administrator approves. The person is emailed
  either way.
- Limits you can see (AA9-T6): `GET /api/v1/admin/limits` lists every limit with its value in
  force, default, floor, ceiling and last week's hits and peak; `GET /api/v1/limits/me` tells any
  caller the limits that apply to them, with the requests left this minute per rate class. A
  runtime limit is changed through `PUT /api/v1/admin/settings/limits.{key}`.
- Audit inclusion proofs and evidence packs (Q16-T3): `GET /api/v1/admin/audit/events/{id}/proof`
  returns an event's Merkle path to its sealed batch's signed root, with the signature, the
  signing key's public half and the anchor key. `POST /api/v1/admin/audit/evidence-packs` (audited
  as a download) returns every sealed event of a time range or one record, at most 2,000, with
  their proofs, the public keys and the steps to verify them offline.
- Index-backed `contains` filters on large tables (AA4-T5): a filterable text attribute gets a
  trigram (GIN, `pg_trgm`) index, built `CONCURRENTLY` by the index-build job, once its table's
  estimated row count reaches `query.trigram_index_min_rows` (default 100,000). A daily
  `TrigramIndexSweep` job queues the builds for tables that have grown past the threshold.
- Service limits per deployment profile (Y5-T3): `attome service install --profile solo|team|ha|scale`
  (default `solo`; `none` sets no limit) caps the service: `MemoryHigh`, `MemoryMax` and `CPUQuota`
  in the systemd unit, a Job Object memory limit for the Windows service. The values per profile
  are in `docs/limits.md`.
- Error titles in the caller's language (Z14-T3): every error code has an English and an Arabic
  message (`attome_types::error_messages`). An error response's `title` is the code's message,
  in Arabic with `Content-Language: ar` when `Accept-Language` prefers Arabic, else in English;
  `code`, `error` and `detail` are unchanged.
- Runtime limit settings (AA9-T3): `limits.bulk.max_records_per_request` and
  `limits.query.timeout_ms.{interactive,report,export}` are deployment settings in the catalogue
  (Operations area). A stored value takes effect without a restart; with none stored the boot
  configuration (or the code default) applies, so nothing changes until an operator sets one.
- `GET /.well-known/jwks.json` publishes the public halves of the Ed25519 token-signing keys
  (Z4-T4) as a JSON Web Key Set, public and cacheable for five minutes, so another service can
  verify EdDSA tokens without a shared secret. It is empty while signing stays HS256.
- `POST /api/v1/query/execute` answers a query over one entity with a weak `ETag` (AA7-T3): a
  hash of the request, the caller and their permission set, the stored query's definition and the
  change feed's newest position. A request whose `If-None-Match` names it gets `304 Not Modified`
  without the query running, but only after the same privilege and entity-read checks the query
  itself applies. Custom queries over several entities, `include_total` requests and callers whose
  rows are filtered record by record (a share or ownership change is not in the hash) carry no ETag
  (AA7-T12).
- Priority load shedding (AB5-T7): reports, exports and AI calls each hold a number of slots
  (`shed.permits`); while more than `shed.interactive_high_water` interactive requests are in
  flight, each of those classes runs one request at a time, and a request that cannot get a slot
  within two seconds is refused with 503 `overloaded` and `Retry-After: 5`. Counted in
  `requests_shed_total`.
- Configuration fingerprints (Z1-T7): every node start records a SHA-256 fingerprint of its loaded
  configuration with secrets masked (`config_start`, migration 0118);
  `GET /api/v1/admin/config/starts` lists starts and `/starts/diff?a=&b=` names the keys that
  changed between two. Secret values are never stored: a secret-looking key shows only whether it
  is set, and a password inside a URL is replaced.
- Calendar calculations (Z12-T10): `POST /api/v1/calendars/{id}/calculate` answers `add`,
  `between`, `next` and `is_working` for any signed-in caller (or on a person's own calendar with
  `user_id`, theirs or an administrator's to ask), with the calendar version and content hash it
  used; SLA calculation rows now record `calendar_version` beside the hash.
- API versions (S8-T1): a request may name the version it was written for in an `Attome-Version`
  header (today `2026-10`, the only one); an API key or S2S client that sends none is answered at
  its `pinned_api_version` (migration 0116), a browser session at the current version. Every
  response echoes the version it was answered at; an unknown version is a 400
  `unsupported_api_version` listing the supported ones.
- Limit hit counts (AA9-T5): every refusal by a rate limit, the body limit or a named limit adds to
  `limit_hits_total{limit, principal_kind}` and to a daily table, `limit_usage_daily` (migration
  0115), with hits and the peak value per limit and caller, flushed by each node every five
  minutes.
- Encrypted cache values (Z3-T3): a cache declared `EncryptedInRedis` seals each value with
  `cache.encryption_key` (AES-256-GCM, key-id tagged) before it reaches Redis, and refuses to start
  over Redis without that key; a `LocalOnly` cache never reaches Redis. A credential column may not
  be cached at all (`attome_core::cache_sensitivity`).
- Email providers (Z8-T1): besides SMTP, mail can leave through Amazon SES (v2 API, SigV4) or
  SendGrid (v3 mail send), chosen per sender identity with `email.providers.by_sender` and
  `email.providers.default` (SMTP when unset). Every provider classifies its answers into the same
  configuration, transient, permanent and unknown outcomes. See `docs/email.md`.
- Metadata changes ring a Postgres doorbell (Y8-T1): `append_change_log` runs
  `pg_notify('attome_metadata_change', id)` in the writer's transaction, and every node listens on
  one runtime-identity connection to the `database.direct_url` endpoint and catches up on each
  notice or reconnect. Other nodes hear a committed change without Redis; with Redis both
  doorbells feed the same debounced catch-up.
- Caching: `attome_cache::tiered::TieredCache` (Z3-T2), one declared cache over an in-process tier,
  the shared store and the loader: one load per key per node for concurrent callers, TTL with
  per-entry jitter, `LocalOnly` values never leaving the process, and a store failure either
  falling back to the source (a rate-limited `cache.redis_degraded` warning) or refusing
  (`FailClosed`). Without a shared store it runs in process.
- Web: a field change's background run shows its state, a progress bar, rows done and the time
  left, polled every five seconds, with Pause, Resume and Cancel (asking first), and Abandon once
  it has failed, in English and Arabic (Y12-T13).
- Data: backfills follow the load (Y12-T6). A retype or archive run sizes each batch from what the
  last one saw: it halves and pauses under pressure (a batch over two seconds, a replica over ten
  seconds behind, most connections busy) and doubles in quiet hours (`metadata.quiet_hours`,
  default `01-05` local) up to `metadata.backfill_batch_max` (default 50,000).
- Records: a record read with `Accept-Language: ar` or `en` carries `labels`, each choice field's
  value as its label in that language (the stored value where none is written), and answers with
  `Content-Language` (S1-T13). `data` keeps the stored values.
- Web: the S2S client editor shows and edits the act-as-user grant, in English and Arabic (S1-T11).
- Calendars: each person's calendar (Z12-T5). `resolve_calendar_id_for_user` takes the person's
  own assignment, else their lowest-id team's, else the default; `load_calendar_for_user` closes
  the days they are on approved leave (HR registers itself as the absence source at boot).
- Agents: `table.health`, `table.index_proposals` and `table.change_plan` (Y2-T14, Y12-T12),
  read-only administrator tools over an entity's table: its health, the indexes slow statements
  suggest, and a preview of how structure changes would run. No agent tool applies an index or a
  structure change.
- Tests: `attome_types::Clock` with `SystemClock` and `FakeClock` (Z15-T5). The approval expiry
  sweep and step-timeout sweep have `_at` variants taking a clock, its time bound into their
  due-ness SQL, so a test advances a fake clock instead of sleeping; production passes the
  system clock. The job scheduler keeps the database's time (its slot claim needs one clock
  across nodes).
- API: `GET /api/v1/openapi/deployment.json` (Y9-T2), an OpenAPI 3.1 document of this
  deployment's own entities: typed list, get, create, update and delete per entity, schemas from
  the attributes, only the entities the caller may read; built once per metadata snapshot.
  `openapi` is now a reserved entity name.
- S2S: act as a user (S1-T10). A client granted `can_act_as_user` (admin client create/update,
  migration 0113) may send `x-attome-act-as: <user id>`; its value is a signed sixth line of the
  canonical message (requests without it sign as before). The request then runs as that user (an
  active, ordinary account; under an entity ceiling not an admin), and the access log records
  `acted_as_user_id` beside the client. Without the grant it is a 403; an unknown user a 403; a
  value that is not an id a 401.
- Records: `GET /api/v1/{entity}` (S1-T2), a keyset-paged list through the query engine (the
  entity's default view, its record scoping and masking): `select=a,b`,
  `filter[<field>][<op>]=<value>` (the column-filter operators; `in` and `contains_any/all` take a
  comma list), `sort=field` or `sort=-field`, `page_size` (1 to 200) and `cursor`; the answer is a
  `CursorPage`.
- Metadata: reserved names and layer locks (Y11-T10). Through the admin routes a new entity or
  field may not take a platform name or the prefixes `attome_` and `xrm_`; an item a layer locked
  in `metadata_lock` refuses changes (409 `metadata_locked`), and an add-only one takes additions
  (a new field, a new choice value) but refuses changing or removing what it has (409
  `metadata_add_only`). An entity's lock covers its fields.
- Performance: with no read replica (`database.readonly` without its own `host` or `port`),
  writes no longer capture an LSN and pin the writer, and reads no longer look the pin up: every
  read is on the primary already (Z2-T6). With a replica, the pin works without Redis on one
  server through the in-process store.
- Data: index proposals (Y2-T10). `GET /api/v1/admin/entities/{entity_id}/index-proposals` reads
  `pg_stat_statements` for statements on the entity averaging over 100 ms, finds the columns they
  filter on, and proposes a single-column index for each attribute no index leads on; applying
  one is making the attribute filterable, which builds the index concurrently. Without
  `pg_stat_statements` (an operator's choice: `shared_preload_libraries` and the extension) the
  answer is `available: false` with the reason.
- Data: storage tuning (Y2-T9). With `metadata.storage_tuning_enabled` (default off), the daily
  table-health job sets each entity table's fill factor from its measured updates: 80 when it is
  updated more than inserted and most updates miss heap-only updates, 100 when it is append-only.
- Data: renamed attributes keep their old name for 90 days (Y12-T8). A create or update body and
  a `query/execute` filter may use the old name; the response carries `Deprecation: true` and a
  `Link` to the current attribute, and always uses the new name. Migration 0112 adds
  `attribute_alias`; expired aliases are removed with the hourly recovery-archive purge.
- Data: data step run controls (Y12-T5). `GET /api/v1/admin/data-step-runs/{id}` shows a run's
  status, counts and ETA; `POST .../pause` stops it after its current batch, `.../resume` queues it
  to continue from its cursor, and `.../cancel` stops it (an orphan scan ends `abandoned`; a field
  run ends `failed` for the field's abandon route to undo). Migration 0111 adds the `paused`
  status and `started_at`.
- Data: the change plan (Y12-T3). `POST /api/v1/admin/entities/{entity_id}/change-plan` classifies
  proposed structure changes as `instant`, `online` (a concurrent index, a validated `max_length`
  CHECK) or `background` (a type change, backfill or delete), each with an estimate from the
  median rate of the last finished runs of its kind (20,000 rows a second until one is
  measured). A table at or under the inline limit runs everything inline. It writes nothing.
- Calendars: loading follows inheritance (Z12-T4). A calendar merges its parent chain (at most
  three levels; a loop is refused): the nearest non-empty working days and hours win, holidays
  are unioned, and a nearer exception wins on its date. Holiday rules and seasons expand for last
  year to two years ahead, a confirmed moon sighting moving a sighted Hijri holiday. Hours accept
  an overnight range (22:00 to 06:00 runs into the next weekday). `LoadedCalendar::version` is
  the content version, bumped once when the loaded definition changes.
- Workflows: a Condition node may carry `expression`, V2 rule text evaluated by `attome-rules`
  against the node's input (nested objects read as `deal.amount` and up to three-hop paths); it
  wins over the legacy `{field, op, value}`, parses at publish, and takes the false branch on a
  type or evaluation error (Z11-T15). `condition::condition_to_expression` writes a legacy
  condition as its expression.
- Fields: a text mask compiles as the rule language's `matches` (`^(?:pattern)$` under its size
  limits), so every alternative of `a|b` is anchored (Z11-T15).
- Rules: `attome_core::rules_sql::to_sql` (Z11-T10) turns the SQL-safe part of a rule expression
  into a bound predicate: literals as parameters, columns quoted from the entity's metadata,
  null-safe equality, `in`, `is_null`, `lower`/`upper`, `contains`/`startswith`/`endswith` (an
  escaped `LIKE` for a literal) and `if` as `CASE`. `translatable` tells an editor which rules
  can run in the database; lookups, paths, lists, lambdas, the clock, `trim`, Arabic and Hijri
  functions stay in the evaluator.
- Caching: `attome_cache::spec::CacheSpec` (Z3-T1), one declaration per cache of what guidelines
  section 5 asks (source of truth, key shape, TTL and jitter, L1 capacity, partition, sensitivity,
  failure mode, invalidation, cold start), validated and registered once per process.
- Tests: query budgets (Z2-T10). `attome_testkit::query_counter` (feature `query-counter`)
  counts the SQL statements a task runs; `attome-testapp`'s `query_budget` holds GET one record
  and a 50-row list to a statement budget and fails when a list's count grows with its page size.
- Operations: query tags (Z2-T8). The generic record queries, `query/execute` and the job queue
  start their SQL with a `/* class */` comment (`entity.merge`, `query.execute`, `jobs.queue`), so
  `pg_stat_statements`, the slow-query log and `pg_stat_activity` show which engine and operation
  sent a statement (`attome_db::tagged_sql!`, `attome_db::tag_dynamic`).
- Data: the orphan scan (Y2-T4). `GET /api/v1/admin/entities/{entity_id}/orphans` counts, per
  lookup field, the rows whose value names no record of the target; a table over 10,000 rows
  answers from its latest finished scan, which `POST /api/v1/admin/data-step-runs/orphan-scans` queues as a durable
  `orphan_scan` data-step run (migration 0110). The scan never changes a value.
- Tests: a fuzz target for the column-filter compiler (`crates/engine/attome-core/fuzz`) and
  `scripts/fuzz-all.ps1`, which runs every fuzz target for a set time and fails on a crash
  (Y13-T5; nightly and Linux or WSL).
- Templates: region filters (Z13-T4): `{{ total | currency('SAR') }}`, `| number(2)`,
  `| date('long')`, `| hijri`, `| digits('western')`, formatted for the render's locale (Arabic
  digits and separators, Arabic currency symbols and month names in Arabic), and `{% dir %}` for a
  block in the locale's direction.
- Rules: multi-hop paths (Z11-T7, V2): `deal.account.owner.region` (two or three hops) read from
  values the caller loads; `Compiled::paths()` lists them so the caller can check every hop's read
  access first. Four hops, or any path in V1, is `rules.lookup.multi_hop`.
- Calendar: the recurrence engine moved to `attome_calendar::rrule` (Z12-T9) and grew `COUNT`,
  `BYMONTH`, `BYMONTHDAY` (negative from the end), ordinal `BYDAY` (`2TU`, `-1FR`), exception
  dates, and `RSCALE=ISLAMIC-UMALQURA` with `SKIP=FORWARD` (Hijri months and days). Report
  schedules still refuse `COUNT`, since they keep no occurrence count.
- Email: the reset, verification, invitation and notification emails are written in the template
  language (Z8-T7), in English and Arabic (`password_reset_in("ar", ...)` and the like; the Arabic
  HTML is right to left), each with an HTML and a plain-text part. A link in `href` is now
  percent-encoded and only http, https, mailto, tel or relative links pass.
- Templates: `attome_html::tmpl` (Z13-T2), the one template language: text with `{{ expression }}`,
  `{% if %}...{% else %}...{% end %}` and `{% for item in list limit N %}...{% end %}` (N at most
  1,000; a longer list is an error), every expression a V2 rule compiled once against the
  template's schema; errors carry their line and column. HTML output escapes each value for where
  it lands (Z13-T3): text, a quoted attribute, inside a tag, or a URL attribute, where only
  http, https, mailto, tel and relative URLs pass (`javascript:` becomes `#`); text output strips
  control characters. A render stops after 100 ms, 1 MiB of output or 10,000 loop iterations
  (Z13-T6, `template.limit.*`). A `TemplateSet` (Z13-T5) holds variants by language and output
  (HTML, text, SMS, WhatsApp), falling back to the default language and then to the HTML stripped
  to text; `{% layout 'name' %}` with `{% body %}` and `{% include 'name' %}` nest at most five
  deep; an SMS render counts its GSM-7 or UCS-2 segments (Arabic is UCS-2, 70 a segment).
- Rules: Hijri, zone and working-day functions (Z11-T4, V2): `hijri_year`, `hijri_month`,
  `hijri_day`, `hijri_date`, `add_workdays`, `workdays_between`, `is_working` and `to_zone`; the
  working-day ones use the business calendar the caller supplies (`Context::with_calendar`) and
  fail with `rules.calendar.missing` without one.
- Calendar: recurring holiday rules and seasons (`attome_calendar::rules`, Z12-T2): fixed dates,
  the nth (or last) weekday of a month, Hijri dates (which can fall twice in one Gregorian year)
  and one-off dates, each spanning 1 to 15 days, expand into the calendar's holidays; a season
  (Ramadan's short hours, say) expands into per-date exceptions. `BusinessCalendar::
  next_working_moment` answers the next working instant.
- Rules: related lists and list functions (Z11-T3, V2): `sum`, `count`, `avg`, `first`, and
  `any`/`all`/`filter`/`map` with a lambda (`lines, l => l.qty > 0`) over a related list the caller
  supplies; lambdas nest two deep (`rules.budget.lambda_depth`) and each element costs a step.
- Rules: user-defined functions (`attome_rules::FunctionLibrary`, `compile_with_library`, Z11-T8).
  Typed, pure V2 expressions over their own parameters; built once in call order, recursion
  (`rules.function.recursive`) and built-in names (`rules.function.invalid`) refused; at most 200
  functions of 8 parameters; a call's steps count against the calling rule's budget.
- Rules: decision tables (`attome_rules::DecisionTable`, Z11-T9). Rows of V2 conditions on named
  inputs (`it >= 100 and it < 500`, `it == "gold"`, `in(it, [...])`, or empty for any) with a
  result, first-match or all-matches, compiled once; `check()` reports number gaps, overlapping rows
  and cells it cannot analyse. At most 500 rows and 10 inputs (`rules.budget.table_size`).
- Calendar: `attome_calendar::hijri::month_length` (Z12-T1).
- Tests: `bounded_state` (Y13-T3) fails on an unbounded channel or a moka cache without
  `max_capacity` in production code; the AI token-delta queue is now bounded (4,096, a full queue
  drops the delta, which the stored answer supersedes).
- Release: `attome perf record --release <v>` and `attome perf compare` (AA14-T5). A record
  (`docs/perf-history/<v>.json`, `attome-perf/v1`) keeps the machine, each SLO class's p95 per
  load-test run and each criterion benchmark's mean; compare fails when a class's median p95 grew
  past its `regression_threshold_pct` (new optional catalogue field, 10% when unset) against the
  previous release on the same machine. `attome release --check --perf` runs it as `perf_compare`.
- `POST /api/v1/query/execute` with only `entity` (no query, view or version) lists the entity's
  live readable attributes, as `GET /api/v1/{entity}` does, instead of the seeded default view's
  `id`-only columns: filters, sorts and selects by real attributes (and by an attribute's old name
  during its alias period, Y12-T8) now work there.
- API document: every operation carries `x-module` (S2-T9), the licence module whose gate it sits
  behind (`core` for ungated and core-gated routes), so the document can be split and filtered by
  licence. A test refuses an operation without one or with a name outside the module map.
- Docs: three Arazzo 1.0.1 workflows in `docs/api/arazzo/` (S2-T13): create an account with its
  contacts in one composite request, read an entity page by page from a keyset cursor, and approve
  and run a gated action. A test checks every step names an operation the API document has.
- Docs: [API versions](docs/api-versions.md) (S8-T6) — the `Attome-Version` header, pinning per API
  key and S2S client, adapters, the 24-month support window and the `Deprecation`/`Sunset` notices.
- Search while the index is down (AB5-T5): when the `search_index` capability is confirmed
  unavailable, `GET /api/v1/search` answers from the tables instead — a prefix match on each
  readable entity's title attribute (the one the index titles it by, never a sensitive field), five
  rows per entity, filtered by the caller's record access — with `route: "fallback"`,
  `degraded: ["search_index"]` and the new `limited: true`. At most two run at once per node and
  one a second per person.
- Chat streams survive a restart (AB7-T5): when a node starts draining, `GET
  /api/v1/ai/conversations/{id}/stream` sends one `reconnect` frame (`{retry_ms}`, 500 to 3000 ms,
  no `id`, with the SSE `retry` field) and closes instead of holding the shutdown open; the chat
  panel waits that long and reopens from its last durable ordinal, so no event is lost or repeated.
- Operations: reports and exports read through their own small pool (AB6-T6), `attome-long`: the
  `attome_readonly` role on the primary, sized by `database.pools.long` (at most 4 by default, 5% of
  the connection budget when sized from it), so a minutes-long export or a report never holds a
  connection an interactive request needs. Exports now read as the read-only role.
- Operations: a limits screen at `/xrm/admin/limits` (AA9-T8, English and Arabic): every limit with
  its value, range, seven-day peak as a bar and a warning chip; a runtime limit is raised in place
  within its floor and ceiling through the audited settings route, and a boot-config limit says it
  is set in the configuration file.
- Operations: limit warnings (AA9-T7). A limit warns when it refused someone in seven days or its
  peak use reached `limits.warn_at_percent` (new runtime setting, default 80) of its value; rate
  classes now record a signed-in caller's use past half the minute's budget. The daily
  `LimitWarningCheck` job notifies every administrator once per warning limit per day, and
  `LimitView.warning` follows the same rule. A bulk request over the cap now names the limit
  `bulk.max_records_per_request`, its registry key.
- Operations: a daily latency regression check after an upgrade (AA14-T8). The built-in metrics
  store now keeps the request-duration buckets of the nine SLO routes; the `PerfRegressionCheck` job
  compares each class's p95 since the last upgrade with the week before and fires the built-in alert
  `PerfRegression:<class>` when it rose more than 20% on at least 1,000 requests in each window.
- Operations: monthly SLO reports (AA13-T9). The `SloMonthlyReport` job writes each finished month's
  error budgets per class to `ops_slo_report` (migration 0109), read at `/api/v1/admin/slo/reports`
  and `/api/v1/admin/slo/reports/{YYYY-MM}`; the `SloBurnCheck` job notifies administrators once per
  class per hour when a class burns its budget at 14.4 times over the last hour and five minutes.
- Tests: `attome_email::testing::FakeInbox` (feature `test-support`, Z15-T6), an in-process SMTP
  inbox that keeps every message sent through `attome_email::send`, readable by recipient.
- Settings: `customer_tests.require_pass_before_publish` (off by default, Z15-T14). When on, a
  changeset apply, a model publish and a blueprint apply first run every active blocking customer
  test and are refused with the new `422 customer_tests_failed` (failing names in `tests`).
- Admin API: customer tests at `/api/v1/admin/customer-tests` (Z15-T13): list, create, show,
  PATCH with `If-Match`, delete, `/{id}/run`, `/{id}/runs`, `/run-all`, `/export` and `/import`
  (an `attome-customer-tests/v1` document of tests only; a name already here is replaced). Every
  write and run is a `Configuration` audit event (`customer_test.created|updated|deleted|run|imported`).
- Tests: customer tests (Z15-T12). `attome_records::customer_tests` runs a given/when/expect
  definition through the record mutation primitives inside one transaction that is always rolled
  back (`as_role` runs the steps with a role's privileges and field grants), and `run_and_record`
  keeps each run's outcome. Migration 0108 adds `customer_test` and `customer_test_run`.
- Migration 0107 grants `billing_gateway_event` to `attome_runtime` and `attome_readonly`
  explicitly, like the other billing tables.
- Tests: generated permission tests (Z15-T8, `attome-testapp` test `generated_permissions`): a user
  holding only one seeded role reads every entity's list (200 with `{entity}.read`, 403 without), is
  refused creating without `{entity}.create`, and never sees a sensitive attribute without a field
  profile. 11 roles by 232 entities, 5,091 checks, no leaks.
- Tests: fault injection (Z15-T7). `attome_testapp::faults` has a fake S3 endpoint that fails or
  slows down on a `FaultPlan`, and a dead Redis URL; `TestApp::start_with` builds an app of its own
  with an edited configuration. `faults.rs` proves an upload whose store fails answers a masked 5xx
  at once.
- Tests: `attome test mutants` (AC5-T9) runs cargo-mutants over the scope in `.cargo/mutants.toml`
  (the security and rules engines, and the record engine's access plan and query execution), scores
  each crate as caught over caught plus missed (unviable and timed-out mutants listed, not counted),
  and exits 2 when a missed mutant is not in `docs/testing/mutants-baseline.json`;
  `--write-baseline` records a run. No baseline is written yet: the scope holds 2,109 mutants, a run
  of well over 8 hours.
- Tests: every entity in the registry is round-tripped through the generic record API (AC5-T8,
  `attome-testapp` test `generated_entity_crud`): create, read, update with `If-Match`, a stale
  update refused with 409, delete, and a create missing each required attribute refused with 422.
  Two defects it found wait on a decision and are kept on a ratchet list (V2-D508).
- Documents: an `attome_document` whose `record_id` is not a UUID is refused at write with 422;
  before, it was accepted and every read of it failed with a 500 (found by AC5-T8).
- Tests: criterion micro-benchmarks for the hot paths (AA14-T1): rules evaluation (`attome-rules`
  bench `eval`), the record-access predicate (`attome-security` bench `permission`) and list-query
  SQL building (`attome-core` bench `query_build`); `cargo bench -p <crate> --bench <name>`.
  `criterion` is a dev-dependency only.
- Billing: customer payments (F5) summarised: `/api/v1/billing/payments*` (record, reverse, refund),
  `/api/v1/billing/payment-links`, the public `/api/v1/pay/{token}` page API, and
  `/api/v1/billing/gateways/{system}/webhook`; gateways, links, saved-card charges and
  reconciliation are off until configured; see docs/invoicing.md.
- Billing: payment screens (F5-T15). The public hosted payment page at `/pay/:token` (Arabic and
  English, right to left in Arabic, three-decimal currencies) starts the checkout and sends the
  payer to the gateway or embeds its form; Billing > Payments in the sidebar; views "Payments this
  month", "Unallocated credit", "Open disputes" and "Payouts with differences". Pack changeset 0021.
- Billing: payment roles and field security (F5-T14, roles and fields). The Payments Viewer role;
  saved-method reads for receivables and finance; `customer_payment.gateway_reference` and `fee` and
  every `gateway_payout` field are sensitive and readable only through the Finance Manager's
  "Payment finance fields" profile; `saved_payment_method.token` is sensitive and readable by no
  role. Pack changeset 0020.
- AI: payment tools for agents (F5-T13): `billing.payment.lookup` (read) and
  `billing.payment_link.create` (consequential, confirmed by the agent's user), offered in the agent
  policy's allowed actions; no tool refunds, changes payment methods, writes off or changes credit
  limits.
- Billing: settlement reconciliation (F5-T11). The daily `BillingReconcile` job lists each payment
  gateway's payouts for yesterday, upserts `gateway_payout` by system and payout reference, matches
  the payments it settles by gateway reference (`matched` or `difference`, with `differences` and
  `payment_count`), and puts the fees on the change feed as `billing.gateway_fee`. The Moyasar
  adapter now reports a payout's payments by the reference Attome stores (the invoice of a
  checkout). Pack changeset 0019 adds the fields, `gateway_payout.read` and the stored query
  "Billing: Payouts with differences".
- Billing: refunds and disputes (F5-T10). `POST /api/v1/billing/payments/{id}/refunds`
  (`payment.refund`) refunds up to what is left of a payment under its refund lock; above
  `billing.refund.approval_threshold` it waits for a `billing.refund` approval; the
  `BillingExecuteRefund` job refunds through the gateway (key `refund:{id}`), sets the payment
  `refunded` or `partially_refunded` and drafts proportional credit notes. Gateway chargebacks
  (`GatewayEvent.dispute`; HyperPay `CB`) open a `payment_dispute`, mark the payment `disputed` and
  notify Finance Managers; `GET /api/v1/billing/disputes/{id}/evidence` lists the invoices' PDFs and
  K1 attachments. Pack changeset 0018 adds the privileges.
- Billing: recurring charges to saved methods (F5-T9). The daily `BillingChargeDue` job (only when
  `billing.saved_methods.enabled`) charges due invoices to the account's default saved method with
  the key `invoice:{id}:attempt:{n}`, re-asks a pending attempt with the same key, retries failures
  after `billing.retry.days` (default 1, 3, 7) with an emailed payment link each time, and hands the
  invoice to collections after the last. Card-updater events (HyperPay registration updates) update
  saved methods. `PaymentGateway` gains `token_charge_reference`; `GatewayEvent` gains
  `card_update`. Pack changeset 0017 adds `customer_payment.charge_attempt`, `next_retry_on` and
  `charged_invoice_ref`.
- Billing: payment links (F5-T8). `POST /api/v1/billing/payment-links` (`payment_link.create`) makes
  a single-use, expiring link for an invoice, an order or an amount; the public `GET
  /api/v1/pay/{token}` and `POST /api/v1/pay/{token}/checkout` (exact bypass matches, rate limited,
  one 404 for every miss) show it and start the gateway checkout after saving a pending payment. A
  link is marked used when its payment succeeds, which allocates to the link's invoice first. Pack
  changeset 0016 adds `payment_link.account_ref`, `customer_payment.payment_link_ref` and the link
  privileges.
- Billing: payment gateway webhooks at `POST /api/v1/billing/gateways/{system}/webhook` (an exact
  bypass match; the adapter verifies the call with the gateway's `webhook_secret`), stored once per
  event in the new `billing_gateway_event` table (migration 0106) and applied to their payments by
  the `BillingGatewayEventApply` job; a gateway credential may now be JSON carrying
  `webhook_secret`, and gateway credentials are read with the live integration key ring (F5-T7).
- Billing: the HyperPay payment gateway adapter — COPYandPAY checkouts returned as an embeddable
  widget (with its integrity hash; mada on its own entity, never mixed with other methods), status
  by merchant transaction id across entities, merchant-initiated token charges and refunds that a
  retry never repeats, payouts from settlement reports, and AES-256-GCM webhooks that must decrypt
  and authenticate. `Checkout` now carries either a `redirect_url` or a `widget` (F5-T6).
- Billing: the Moyasar payment gateway adapter — hosted checkout through a Moyasar invoice, payment
  status, token charges that never charge twice for one idempotency key (`given_id`), refunds that
  never refund twice, payouts from Moyasar transfers, webhooks verified by their secret token in
  constant time, and saved cards kept as brand and last four digits only (F5-T5).
- The payment gateway seam (F5-T4): integration systems of the new kind `payment_gateway` hold a
  gateway's base URL and credential; `attome_billing::gateway` defines the `PaymentGateway` trait
  (hosted checkout, status, token charge, refund, payouts, webhook verification), an SSRF-guarded
  HTTP client with a 15-second timeout, and the `billing.gateway.rules` setting that picks the
  gateway by currency, country and amount. The Moyasar and HyperPay adapters follow.
- Payments (F5-T3): `POST /api/v1/billing/payments` records a payment received outside a gateway and
  allocates it to the payer's open invoices (oldest due first, or as given), refreshing their paid
  and open totals and payment status in the same transaction; what is left over stays as the
  customer's credit, which `POST /api/v1/billing/accounts/{id}/apply-credit` allocates later.
  `POST /api/v1/billing/payments/{id}/reverse` (`billing.payment_reverse`) reverses one with a
  reason and reopens its invoices. An account's payments are serialised by a lock (`409` to retry);
  payments are append-only for every other writer. Billing's engine writes to invoices now also
  reach the change feed (issue, write-off, payment status, e-invoice status, sending).
- E-invoicing screens (AG2-T4): `/xrm/billing/einvoice` lists the ZATCA devices with their state and
  counter, adds a device and onboards it with the Fatoora portal's OTP (ZATCA's reason shown when a
  step fails); the invoice form shows the invoice's e-invoice status with ZATCA's errors and
  warnings. Billing > E-invoicing in the sidebar for holders of `einvoice.manage`.
- E-invoicing in the issue step (AG2-T3): with `einvoice.enabled`, every issued invoice, credit and
  debit note and deposit invoice is written as ZATCA's UBL invoice, stamped on the oldest onboarded
  device (its hash chain kept under a row lock) and cleared (buyer with a VAT number) or reported
  (consumer) at once; `invoice.einvoice_status` follows (`pending`, `cleared`, `reported`,
  `rejected`). A five-minute sweep retries what ZATCA could not take and then runs the after-issue
  hooks again. The invoice PDF prints the QR code, sending waits for clearance and attaches the
  XML, and `GET /api/v1/billing/invoices/{id}/einvoice` shows the status and ZATCA's messages.
- E-invoicing devices (AG2-T3): `GET/POST /api/v1/einvoice/devices` and
  `POST /api/v1/einvoice/devices/{id}/onboard` (`einvoice.manage`, granted to Finance Manager by the
  billing pack) create a device with its key and CSR from the new seller settings
  (`billing.seller_crn` and the seller's national address) and onboard it with the portal's OTP:
  compliance CSID, a compliance check per document kind, production CSID. Keys and secrets are
  stored encrypted (migration `0105`), each credential write is audited, and a refused step leaves
  the device `failed` with ZATCA's reason. Accounts gain national-address fields for B2B e-invoices.
- ZATCA onboarding and API client (AG2-T3, library): the device's certificate signing request with
  ZATCA's template name and directory-name fields (checked with OpenSSL), reading the CSID
  certificate's issuer, serial number, public key and CA signature, and a typed client for the
  compliance CSID, compliance checks, production CSID, clearance and reporting calls that tells
  accepted, rejected, unauthorised and retry-later answers apart.
- ZATCA stamping (AG2-T2): `attome-einvoice` signs the invoice hash with a device's ECDSA
  secp256k1 key (pure Rust `k256`), writes the XAdES `ext:UBLExtensions` block (certificate and
  signed-properties digests as ZATCA's validator computes them) and the QR code TLV (tags 1 to 8,
  and 9 for simplified invoices); device keys are encrypted at rest under the new
  `einvoice.key_encryption_key` ring (config section `einvoice`, off by default).
- ZATCA e-invoicing groundwork (AG2-T1): a new `attome-einvoice` crate writes the UBL 2.1 invoice
  ZATCA receives (standard and simplified; invoices, credit and debit notes, prepayments), the
  canonical form it hashes (C14N in Rust, no native XML-security library) and the invoice hash with
  the per-device counter and previous-hash chain; it reproduces the hashes of signed sample invoices.
- Invoicing (F4) is documented in `docs/invoicing.md`: records, issue and numbering, the
  after-issue document and sending, corrections, requests and schedules, payment status,
  statements, ageing, write-offs, roles and agent tools. No breaking change to `/api/v1`.
- Billing forms: the invoice form shows the billing pack's buyer, amounts, corrections and document
  sections when the pack is installed, and `invoice_line`, `invoice_schedule` and `region_tax_rate`
  have their own forms, labelled in Arabic and English.
- Billing screens: the receivables ageing (`/xrm/billing/ageing`: five buckets per account and
  currency with per-currency totals) and an account's statement
  (`/xrm/billing/accounts/{id}/statement`: a period picker that also shows the Hijri dates for
  viewers who read them, a printable layout), both right to left in Arabic and with each currency's
  decimals (three for KWD, BHD, OMR, JOD). The billing pack adds a Billing sidebar group.
- After an invoice is issued, its bilingual PDF (Arabic and English side by side, seller and buyer
  VAT numbers, Gregorian and Hijri issue date) is rendered through the docgen sidecar and attached to
  the new `invoice.document` field, then emailed to the invoice's contact, which moves it to `sent`;
  sending waits for e-invoicing clearance when there is one. New settings `billing.seller_name` and
  `billing.seller_vat_number`. Emails can now carry attachments (`EmailMessage.attachments`), and
  other engines can render their own HTML to a file field (`attome_docgen::generate`).
- Billing agent actions: `billing.find_invoices`, `billing.account_balance` and `billing.explain_tax`
  read as the person (the tax facts come from the tax engine), and `billing.draft_invoice` and
  `billing.draft_credit_note` file drafts after a person confirms. No action issues, cancels, issues
  a credit note or writes off.
- Invoicing permission tests: a Billing Clerk cannot issue, credit or write off; a user scoped to
  their own accounts sees only those in the ageing and statements and cannot recompute; a new tax
  rate never changes an issued invoice. Statements and ageing now apply the same account scope as
  record reads (the owner arm and conditional grants were missing).
- `POST /api/v1/billing/invoices/{id}/write-off` (`billing.write_off`) writes off part or all of
  an issued invoice's open amount with a reason, posting a `write_off` ledger row; above
  `billing.write_off_approval_threshold` it waits for a `billing.write_off` approval. The amount is
  kept in the new `invoice.written_off_total`, off the open total, statements and ageing.
- `GET /api/v1/billing/accounts/{id}/statement?from=&to=` (opening balance, issued documents and
  payment allocations in the period, closing balance, per currency), `GET /api/v1/billing/ageing`
  (open amounts per account and currency in current, 1-30, 31-60, 61-90 and over-90-day buckets,
  paginated) and `GET /api/v1/billing/ageing/totals`; all need `invoice.read` and follow the
  caller's record scope on accounts.
- An issued invoice's `payment_status`, `paid_total` and `open_total` follow its payment
  allocations and due date: a nightly sweep marks past-due open invoices `overdue`, and the billing
  pack refuses hand edits of those fields (no manual "mark paid").
- `POST /api/v1/billing/invoice-requests` (`billing.issue`) stores an invoice another feature asks
  for, once per `source_kind` and `idempotency_key`; a five-minute sweep turns pending requests
  into draft invoices as their requester (one per currency and day for accounts with
  `billing_group_invoices`), and a daily run copies due `invoice_schedule` templates into drafts
  once per period. Migration `0104` records who asked.
- `POST /api/v1/billing/invoices/{id}/apply-deposit` deducts an issued deposit invoice from a final
  draft (one negative line per VAT category, `Deposit DEP-…`), once: a second deduction is `409`,
  and issuing re-checks it under a per-deposit lock. `POST …/{id}/convert-pro-forma` copies a pro
  forma invoice into a new priced draft; a pro forma itself is never issued.
- `POST /api/v1/billing/invoices/{id}/credit-notes`, `/debit-notes` and `/cancel` (`billing.credit`)
  correct an issued invoice: a credit note copies chosen lines negated (never beyond what is left
  uncredited, checked again under the series lock on issue), a debit note adds charges, and
  cancelling issues a full credit note at once. Each note links the original and carries a reason.
  The finance invoice's `amount` is no longer required and follows the billing grand total.
- `POST /api/v1/billing/invoices/{id}/issue` issues a draft invoice: the next gap-free number of
  its series and year (`INV-2026-000001`; credit notes `CRN`, debit notes `DBN`, deposits `DEP`)
  under a series lock, issue and due dates, locked lines and a ledger posting; above
  `billing.issue_approval_threshold` it waits for a `billing.issue` approval. The billing pack
  adds the `issued` status, lets drafts go unnumbered and locks issued invoices and their lines.
- `POST /api/v1/billing/invoices/{id}/recompute` prices a draft invoice's lines with VAT from the
  regions pack's rates and stores line and invoice totals (sums of rounded lines); an issued invoice
  answers `409`. The `billing.seller_country` setting (default `SA`) is the seller side of VAT.
- Invoicing records in the billing pack (`0005`): invoice kinds, payment status, buyer, VAT number,
  currency, number series, stored totals and e-invoice status on `invoice`; `invoice_line` with VAT
  category, rate and amount; `invoice_schedule`; the `billing.issue`, `billing.credit` and
  `billing.write_off` privileges and four billing roles.
- When a user is disabled while still owning open deals, the active users holding the position
  above theirs (administrators when there is none) get one notification listing the deals to
  reassign; deals, teams and splits are unchanged (migration `0102`).
- `docs/agents.md` describes the follow-up agent: what each rule reason finds, the three modes, the
  daily cap and `GET /api/v1/ai/follow-ups`, `POST /api/v1/ai/follow-ups/{id}/dismiss` and
  `POST /api/v1/admin/ai/follow-up-rules/{id}/run`.
- A "My follow-ups" screen (`/ai/follow-ups`, English and Arabic): the caller's open follow-up items
  with their reason, age and status, a link to each record and a dismiss button.
- Follow-up items now run: each hourly scan queues one `AiFollowupItem` job per open item. A rule in
  `remind_owner` mode reminds the owner; `draft_message` and `send_message` start a session of the
  `followup_agent` definition for the record's owner (once an administrator activates it; until then
  the owner is reminded), whose drafts and sends wait for the owner's confirmation or approval. A run
  claims its item, so a repeated job does nothing; nothing runs while AI chat is switched off.
- Agent actions `followup.remind_owner` (reversible) and `followup.send_message` (consequential)
  for follow-up items, under the rule's daily cap; each records an `agent_task` outcome with its
  agent session. The communication writer behind the compose route moved to
  `attome_notification::communication` so engines send through the same path.
- A battle card panel on the opportunity form: a tab per competitor on the deal with its strengths,
  weaknesses, price position and knowledge article, the competitors proposed from emails and notes
  with confirm and reject, and a link to a closed deal's unfinished win-loss review; hidden when the
  deal has none. `GET /api/v1/sales/competitors/{id}/card` returns a competitor's readable fields and
  its battle card article.
- Agent actions `sales.competitors.on_deal`, `sales.battlecard.get`, `sales.winloss.draft_review`
  and `sales.battlecard.draft_update`: read only, as the person; the review and battle card drafts are
  returned for a person to save or publish.
- Win and loss reports in the sales pack (`0017`): overall win rate, win rate and reasons by
  competitor, reasons by segment, region and size, discount and sales cycle by competitor, losses on
  price by discount band, and win rate by quarter, run through `query/execute`.
- Competitor routes: `POST /api/v1/sales/competitor-mentions/{id}/confirm` and `/reject`
  (`If-Match`; confirm puts the competitor on the deal as `suspected`),
  `GET /api/v1/sales/opportunities/{id}/battlecards` (a `PaginatedResponse`, all on one page) and
  `GET /api/v1/sales/competitors/{id}/head-to-head` (over the deals the caller may read).
- Competitor mentions: a minute job reads new emails and notes about a deal (or its account)
  and proposes each tracked competitor they name as a `competitor_mention` (status `proposed`),
  matched as a whole word after Arabic normalisation, written as the deal owner only when the
  owner can read the source; nothing is linked until a person confirms.
- `POST /api/v1/hr/offers/{id}/hire` (`employee.create`): an accepted job offer becomes an
  employee (name, start date, salary, posting title), linked to the user account with the
  candidate's email when one exists; a second hire of the same offer is refused.
- Table health: `GET /api/v1/admin/entities/{entity_id}/health` and `GET /api/v1/admin/table-health` report
  each entity table's size, live and dead rows, last autovacuum, unused indexes, lookups with no index
  and seven-day growth, from the statistics views only; a daily job keeps the size samples (migration
  `0101`).
- Follow-up routes: `GET /api/v1/ai/follow-ups` (the caller's open follow-ups),
  `POST /api/v1/ai/follow-ups/{id}/dismiss` (`If-Match`, owner only) and
  `POST /api/v1/admin/ai/follow-up-rules/{id}/run` (queues one rule's scan, audited as configuration).
- Event registration: `POST /api/v1/marketing/events/{id}/registrations` registers up to capacity and
  waitlists the rest with a random ticket code for the QR; `.../registrations/{registration_id}/cancel`
  gives the freed seat to the first waiting person; `POST .../check-in {ticket_code}` checks a person in
  once.
- `GET /api/v1/{entity}/{id}/ancestors` and `.../descendants` take `?field=` to choose which
  self-referencing lookup to walk (a contact's `reports_to` or its dotted-line manager); without it an
  entity with two such lookups answers 422 asking for it.
- Bulk edits above the new `records.bulk_edit_approval_count` setting (0, the default, never asks)
  answer `202` with an `approval_request_id` and run as their requester once approved
  (`records.bulk_edit`).
- Marketing list insight: `GET /api/v1/marketing/lists/{id}/count` (estimate or `exact`, and the people
  reachable for a `purpose_key`), `.../sample`, `.../explain/{person_id}` (which step put them in or left
  them out) and `.../members-as-of?at=`, all as the caller and never naming people they cannot read.
- Win/loss reviews: a deal closing at or above its stage's `review_amount_threshold` gets a draft
  `win_loss_review` with a snapshot of its competitors and a task for its owner due in seven days, made
  after the close and once per outcome.
- Follower notifications: a change, deletion or restore of a record tells its followers and its owner in
  the app (never the person who made it, never someone who can no longer read it), under the new
  `record_followed` notification preference category.
- `POST /api/v1/sales/call-lists/{id}/build` fills a call list as the caller from its saved query, the
  caller's phone calls due today, or named records (each read-checked), skipping records without a
  phone; a rebuild keeps existing members and adds only new ones (up to 10,000).
- `POST /api/v1/sales/call-list-members/{id}/outcome` saves a call attempt for the member the caller
  claimed, finishes or re-queues the member, and queues the list's outcome rules (lead status, deal stage,
  a callback task, the wrong-number flag), applied after commit as the caller and never twice.
- Commission into payroll: locking a period emits `commission.period_accrued`;
  `POST /api/v1/hr/payroll-handoff` returns the payroll CSV and moves its approved commission payouts to
  `exported`; `POST /api/v1/hr/payroll-handoff/confirm` marks them `paid` with `commission.payout_paid`.
- Human resources engine `attome-hr`: `POST /api/v1/hr/leave-requests/{id}/submit` counts the working days
  on the default calendar, checks the balance and opens the approval (`hr.leave_decide`), which moves
  the days to taken; `GET /api/v1/hr/availability` lists a user's days on approved leave; and
  `GET /api/v1/hr/payroll-export?from=&to=&template=generic|wps` hands the period's salaries, unpaid
  leave days and approved commission to payroll as CSV (salary and national id grants required,
  each export audited).
- Undo of bulk line changes: a deal discount or quote sync answers with a `snapshot_id`;
  `POST /api/v1/sales/undo/{snapshot_id}` restores the lines and reprices, for its author within
  30 minutes and only while the lines are untouched since (migration `0100`). Snapshots are removed
  after a day.
- Agent actions `sales.team.add`, `sales.team.remove` and `sales.splits.propose` (confirmed writes through
  the team and split routes' own functions; a won deal's split change opens its approval) and
  `sales.team.suggest` (people on won deals with the same account, as a draft).
- `POST /api/v1/sales/opportunities/{id}/sync {direction: from_quote, force}` replaces a deal's lines
  with copies of its primary quote's and reprices it; when both changed since the last sync it answers
  `409 sync_both_changed` with both line sets. `to_quote` is refused (quotes change through CPQ).
  Behind `sales.quote_sync`.
- Agent actions `sales.opportunity_line.add`, `.update` and `.remove` (confirmed writes through the line
  routes' own functions: priced, locked and version-checked) and `sales.products.suggest` (products
  most often won together with the deal's, as a draft).
- Revenue and quantity schedules: `POST /api/v1/sales/opportunity-lines/{line_id}/schedule` spreads a
  line evenly, by a percentage pattern (totalling 100) or by hand (totalling the line);
  `POST /api/v1/sales/opportunities/{id}/schedules/shift` moves a deal's rows by whole months when the
  user agrees, by a job past 500 rows. Behind `sales.schedules`.
- `GET /api/v1/sales/price-lists/{id}/products?q=&sku=&on=` lists the products a line can use on a
  date with their list price and quantity breaks, searched by name or SKU, filtered by the caller's
  product record rules.
- Opportunity lines: `GET/POST /api/v1/sales/opportunities/{id}/lines`, `PATCH`/`DELETE .../lines/{line_id}`
  and `POST .../deal-discount` (`If-Match` with the deal's row version) price every line together in one
  transaction, store each line total and the deal's one-time, recurring and contract totals and amount,
  and recalculate the stored split amounts. A product must be on the deal's price list in its currency
  (`product_not_on_price_list`). `opportunity_line` and the deal totals are now engine-managed.
- Commission recalculation previews (`comp_recalc_preview`, commission pack `0003`): publishing a plan
  or crediting an open period recomputes it into per-participant previews (current and recalculated
  amount) without touching statements; `POST /api/v1/commission/periods/{id}/recalc/apply` starts the
  calculation runs and marks the previews applied. Closed periods are never previewed.
- `POST /api/v1/commission/plans/{id}/publish` compiles a plan's draft version and publishes it with the
  hash of what compiled; overlapping or unreadable rate tables are refused with the component named.
- Commission credits from won deals: each revenue split of a deal at `closed_won` credits its member's
  plan participation once (keyed by the split), dated on the close date; a credit dated in a closed
  period lands in the next open one with an adjustment naming the closed period.
- `POST /api/v1/sales/opportunities/{id}/change-owner` moves a deal to a new owner in one transaction:
  the new owner's share and team membership, the old owner kept with a role or removed, and their
  splits moved or kept, with an owner-change Access event.
- Default deal teams: a new deal gets its owner's default team members (each with their share and
  Access event; a member whose roles do not allow the access is skipped).
  `POST /api/v1/sales/opportunities/{id}/team/copy-account-team` copies account team members with the
  given roles onto a deal on request; `POST /api/v1/sales/default-team/preview` lists the caller's open
  deals their default team would change and `.../apply` queues a job that adds the missing members.
- Deal teams: `POST /api/v1/sales/opportunities/{id}/team`, `PATCH` and `DELETE .../team/{member_id}`
  add, change and remove members; a user member gets a view or act share of the deal in the same
  transaction (refused above what their own roles allow, `access_above_role`), the owner cannot be
  removed, and each change writes an Access event. `opportunity_team_member` is now written only
  through these routes.
- Deal splits: `PUT /api/v1/sales/opportunities/{id}/splits` replaces a deal's splits under its lock,
  checks that each revenue split type totals 100% and that members are on the deal's team, and stores
  each split's amount (rounded once, remainder to the owner). On a won deal the change needs a reason
  and waits on approval (`sales.split_change`), applied only if the deal has not changed since.
  `opportunity_split` is now written only through this route.
- Agent actions `commission.explain_line` (a statement line's stored explanation, under the caller's
  record rules and field grants) and `commission.draft_plan_from_policy` (checks a plan drafted from a
  policy document compiles and returns the normalised draft; writes nothing).
- Commission period close: `POST /api/v1/commission/periods/{id}/submit` (`If-Match`) puts an open
  period in review and opens a finance approval (`commission.period_close`) regarding it; approval
  locks the period and approves its calculated payouts, rejection reopens it with the comment. A
  calculation run never recalculates an approved or locked period.
- Commission disputes and adjustments: `POST /api/v1/commission/disputes` (the line's owner),
  `POST /api/v1/commission/disputes/{id}/decision` (accept, reject or adjust) and
  `POST /api/v1/commission/adjustments` (reason required); an adjustment above the new
  `commission.adjustment_approval_amount` setting (default 1000) answers `202` with an approval
  request and is written only when that approval executes (`commission.adjustment_apply`).
- Commission statements: `GET /api/v1/commission/statements/me?period_id=` and
  `GET /api/v1/commission/statements?period_id=&participant_id=` list statement lines, adjustments and
  clawbacks under the commission roles' record rules, amounts hidden without the amount field grant;
  `POST /api/v1/commission/estimate` prices one of the caller's opportunities in the open period and
  writes nothing. Calculation runs now stamp lines and payouts with the participant's user as owner.
- Commission calculation runs: `POST /api/v1/commission/periods/{id}/runs` (privilege `comp_run.create`,
  `409` on an approved or locked period) queues a run that computes statement lines and payouts per
  participant in batches, resuming from its cursor after a restart.
- A/B variants for feature flags: a subject's variant comes from a stable hash of the flag and the
  subject, split by the variants' weights, and outcomes are recorded per variant for comparison
  (migration `0099`).
- Role grants can end: `POST /api/v1/admin/security/users/{id}/roles` takes `valid_until` (in the
  future) and `reason` (migration `0098`); an hourly job removes grants past their end exactly as an
  administrator removing the role would, with its audit event and the user's sessions ended.
- Nurture programmes with tracks move people to the best-fitting track (stage, then interest, then
  language) when those change, keeping what they have already seen; acquisition-only programmes let
  go of anyone who becomes a customer.
- The marketing-to-sales hand-off SLA: a hand-off is due after the programme's business hours (8 by
  default, Sunday to Thursday 09:00 to 17:00 Riyadh time); every five minutes the overdue ones are
  marked and the assignee's manager notified once, for programmes with the SLA on.
- Marketing lists refresh: a segment's people come from its stored query as the list's owner sees
  them, combinations include, intersect or exclude other lists in order (five deep, cycles refused),
  account lists expand to contacts or decision makers, and each refresh writes the joins and leaves
  as membership events; scheduled lists refresh hourly or daily on their own.
- Bounces and complaints reach the person: a nightly pass marks the email of a contact or lead whose
  address hard-bounced `invalid`, and withdraws marketing consent on email for each complaint, once.
- Target account lists (migration `0097`): each account on a list is rescored nightly from its
  contacts' activity of the last 90 days, with the buying roles covered and missing, and moves from
  identified to aware to engaged on its own.
- Referrals (migration `0096`): each contact gets a readable referral code; a lead arriving with it is
  attributed once (self-referrals by the same email or phone are refused), and when the lead converts
  the referrer earns 500 loyalty points, once.
- Loyalty points (migration `0095`): an insert-only ledger per member; a fulfilled order earns a point
  per whole unit of its total once, valid 12 months; redemption checks the balance; due points expire
  first in, first out; tiers come from the points earned in the last year.
- Timers (migration `0094`): one `timer` table for every point in time the platform waits for, with a
  sweep every 15 seconds that claims due timers once (`SKIP LOCKED`) and runs each as its own job.
- Consent ledger (migration `0093`): every marketing consent grant and withdrawal is an insert-only
  event with its proof, and the current state per person or account, purpose and channel is kept in
  the same transaction; the send gate allows a message only with a grant in force and no account-wide
  opt-out, failing closed otherwise. `POST /api/v1/consents/withdraw` takes an optional `channel`
  and writes the ledger; anonymous form captures wait for confirmation before they count.
- Workflows have an "Assign Owner" node: it sets a record's owner from a team, queue or role by round
  robin (remembered per node, migration `0092`), fewest records, skills, territory owner or rules,
  falling back to a queue when nobody fits.
- Watch-only website sources import nothing (the import route refuses them) and report each page
  whose text changed as a `webcrawl.page_changed` change event with the added and removed lines.
- Website crawls are scope-aware and polite: include and exclude patterns (exclude wins), sitemap
  seeding limited to pages changed since the last crawl, `If-None-Match`/`If-Modified-Since` with
  304 or an unchanged text hash leaving the stored page alone, the site's `Crawl-delay` or one
  second between requests, an `AttomeCrawler/<version>` user agent, and a stop after 20 errors in a row.
- Website sources on a `daily` or `weekly` schedule recrawl by themselves: an hourly job queues one
  crawl per due source, never one already queued or running, and nothing while webcrawl is off.
- Recurring revenue: a nightly snapshot of each account's MRR per currency (migration `0091`) and
  `GET /api/v1/billing/metrics/recurring?as_of=&period_days=` (privilege `subscription_metrics.read`)
  with MRR, ARR, new, expansion, contraction, churn and net retention per currency.
- `POST /api/v1/sales/call-lists/{id}/claim` (privilege `call_list.call`) gives a caller the next
  pending member of a call list, never the same one to two callers; members with do-not-call, no
  `sales_calls` consent (when that purpose exists) or too many attempts are skipped, and those outside
  their country's calling hours or over the daily limit are snoozed, each with a stored reason.
- Forecast cells fill themselves: deals carry a forecast category (on the deal or from its stage, sales
  pack 0015), and a nightly job sums each open period's deals per owner and category, rolls them up
  through the position tree, keeps adjusted amounts, and snapshots every cell once a week.
- Deal risk: every open opportunity is scored nightly from 0 to 100 (quiet for 14 days, close date
  pushed, no decision maker or economic buyer, stalled past 1.5 times its stage's median, close date
  passed), with the reasons on the deal and an "At Risk" deals query (sales pack 0014).
- Points scoring runs: `points_model` and `points_rule` define fit rules (rule-language conditions on
  the lead or contact) and behaviour rules (activities of a type, fading with the model's half-life);
  a nightly job stores each record's score and its reasons in `points_score`.
- Supplier SLAs: setting a ticket's `supplier_vendor_id` (with `supplier_target_minutes`) starts a
  supplier clock; it stops when the work comes back or the ticket resolves, and is met or breached
  against the supplier's own target, reported per supplier apart from the customer's SLA.
- Tasks have checklists (`task_checklist_item`) and repeat: a completed task with a
  `recurrence_rule` (`weekly`, `monthly`, `FREQ=...;INTERVAL=n`) gets its next task, with a fresh copy
  of its checklist, within 15 minutes.
- Approved contract amendments take effect on their date: the nightly key-date run folds their changed
  terms into the contract's current terms (and end date) and marks them effective.
- Counterparty matching for contracts: `POST /api/v1/contract/counterparty-match/run` (administrators)
  queues a job that proposes an account for each contract naming its counterparty only as text
  (Arabic spelling variants folded, exact name then whole-word prefix); `POST
  /api/v1/contract/counterparty-proposals/{id}/decide` confirms (setting the contract's account) or
  dismisses a proposal, with the new `contract.counterparty_confirm` privilege.
- Contract key dates run nightly: each active contract's notice deadline is kept current, a
  "Renew, renegotiate or terminate" task opens for its owner 30 days before it, obligation owners
  are reminded 7 days before a due date, overdue obligations go to the contract owner, and a
  completed recurring obligation (`monthly`, `quarterly`, `FREQ=...;INTERVAL=n`) creates the next.
- Staged imports with a mapping match choice cells to their stored values or labels, folding Arabic
  spelling variants, case and separators; text matching nothing is reported on its row.
- Price resolution for sales lines (account price, then contracted price, then the price list with
  quantity breaks and unit conversion) and the CPQ pricing waterfall that records each step.
- Rule language V2 functions: `normalize_ar`, `concat`, `substr`, `replace`, `abs`, `floor`,
  `ceil`, `power`, `clamp`, the currency functions `round_currency`, `convert` (rates supplied by
  the caller's context) and `minor_units`, and `matches(text, pattern)` with a literal,
  size-limited, linear-time pattern; V1 expressions are unchanged.
- Procurement engine and pack (`procurement` module): requisitions, purchase orders, goods
  receipts and vendor bills, a budget check (warn or block) and monthly vendor scorecards.
- GRC regulatory changes linked to the controls, requirements and policies they touch; metric
  governance (scorecards, commentary, certification, dimensions, cascading targets) and a
  notification when a metric crosses into a worse status; call-analysis entities with tracker
  matching; scan-action bindings.
- Database tables for nurture state and hand-offs, list membership, property layers,
  deliverability rollups and DMARC reports, website events (monthly partitions), metric snapshot
  dimensions, calendar v2 and the lineage graph (migrations 0082 to 0090). New migrations must be
  expand-only; removals go to the contract set (`crates/apps/attome/contract/README.md`).
- Metered usage: `POST /api/v1/billing/usage` takes up to 1000 usage records per call with an
  idempotency key each; a repeated key is counted as a duplicate and not stored again
  (privilege `subscription_usage.write`, migration 0088).
- Website crawl sources take settings: include and exclude path patterns, languages, audience,
  import mode, schedule, sitemap URL, watch-only and one allowed intranet host, on
  `POST /api/v1/webcrawl/targets` and in every target read; pages keep their ETag, last-modified
  date, content hash, missing count, alias and language (migration 0081).
- Approval out-of-office: `PUT /api/v1/approvals/out-of-office` hands the signed-in user's approval
  standing to another user for a window (an overlapping earlier one is replaced) and
  `DELETE /api/v1/approvals/out-of-office` ends it; leave approvals use the same delegation with
  source `leave`. Approval requests can be recalled while pending and resubmitted, linked to the
  recalled one (`parent_request_id`).
- Deal teams and splits (`sales.deal_teams`, `sales.splits`, `sales.line_splits`,
  `sales.partner_members`, `sales.team_suggestions`, all off by default): team members with roles,
  revenue splits that total 100% and overlay splits, rounding remainder to the owner; see
  `docs/deal-teams.md`.
- Packs: `field-service` (stock and serials, returns), HR positions, leave and labelled documents,
  service entitlements with a usage ledger.
- Packs: `privacy` (processing activities, DPIA, breaches), `internal-audit`, `bcm` (impact
  analysis, plans, exercises) and `recruiting`.
- Packs: `fulfilment`, `partner` and `workforce`; marketing campaigns and lists; sales opportunity
  lines and competitors with win-loss reviews.
- Packs: `commission` (plans, credits, runs, payouts, masked amounts), `marketing` (deliverability
  policy, email status on contacts and leads), `offline` (offline profiles) and the sales dialer
  (`call_list`, members, attempts, outcome rules, calling hours, caller ids).
- Billing pack (`packs/billing`): subscriptions with lines, dated segments and planned charges;
  payments, allocations, refunds, disputes, saved methods, payment links and payouts.
- Sales pack: account plans with goals, a products-by-department whitespace grid and actions
  (`packs/sales/changesets/0005-sales-account-plans.json`), labelled in Arabic.
- Rate-limit bans screen (`/admin/rate-limit-bans`) on `GET /api/v1/admin/rate-limits/bans` and
  `DELETE /api/v1/admin/rate-limits/bans/{bucket}` (audited).
- Security policy schema: per-operation entity access levels and child-unit flags on role grants
  (0076), per-role second-factor policy with grace periods and remembered devices (0077), and
  per-role session limits with device and activity on sessions (0078).
- Rule language versions: `attome_rules::compile_versioned` and `upgrade`; `endswith` is the
  first V2 function (V1 text keeps rejecting it). A QuerySpec JSON model (`attome_records::query_spec`).
- Mentions: `POST /api/v1/{entity}/{id}/mentions` notifies everyone a text names as
  `@[user:<id>]` or `@[team:<id>]` who may read the record; nobody else hears of it.
- Profiler probes keep a latency histogram; stats carry `p50_ms`/`p95_ms`/`p99_ms`, and
  `attome_profiler::budget_findings` names probes over their p95 budget.
- One-time codes (`attome_auth::otp`): six digits, peppered hash, 60 seconds, single use, five
  tries, Arabic-Indic digits accepted; table `one_time_code` (migration 0075).
- `GET /api/v1/{entity}/{id}?expand=<lookups>` returns up to five lookups' target records inline
  under `expanded`, each only when the caller may read it.
- `GET` / `PATCH /api/v1/{entity}/key/{keyspec}` address a record by its business key (or an
  external id, or a key an upsert indexed), e.g. `/api/v1/account/key/accountnumber=A-100`.
- `POST /api/v1/composite`: up to 25 record creates, updates and deletes in one request, each on
  its own (a failure is reported, the rest run), later ones using earlier results through
  `${ref.field}`. Entities can no longer be named `composite`, `query`, `search`, `graph` or
  `schema`.
- `POST /api/v1/query/execute` takes `select`: the attributes to return, in order (`id` always);
  a name the caller may not read is the same 422 as one that does not exist.
- Billing and sales logic, pure and tested: subscription segments read as of a date, charge models
  (flat, per unit, tiered, volume, setup fee, minimum commitment), billing periods with proration,
  payment allocation (oldest first or as the payer says, overpayment to credit), opportunity
  line pricing; `sales.*` feature flags for opportunity lines and what builds on them (all off).
- Website tracking feature flags, all off by default: `marketing.tracking` and its parts
  (external sites, identify, company, custom events, alerts).
- Engine crates for the business modules, each behind its own module switch: `attome-sales`
  (dialer, org charts, enrichment, competitors), `attome-callintel`, `attome-marketing`,
  `attome-billing`, `attome-commission`, `attome-partner`, `attome-fulfilment`,
  `attome-workforce`, `attome-contract` and `attome-offline`; modules `sales` … `offline` (ids 32-41).
- Events monitor (`/admin/events-monitor`): every change-feed consumer with unread events, how far
  behind it is and when it last read; the built-in `ChangeFeedConsumerLagging` alert fires past
  five minutes.
- `POST /api/v1/admin/change-feed/consumers/{name}/rewind` moves a change-feed consumer back to a
  sequence number or a time within retention (audited); consumers record applied events
  (`change_consumer_applied`) so a re-read event is never applied twice.
- The change-event outbox carries what changed: `changed_attributes`, `before` / `after` values
  (a sensitive field as `{"ref": true}`) and a global `seq`, written by create, update, delete and
  restore. Workflows can start on `delete`, `restore` and `merge`, and an `update` trigger may list
  `attributes` so it starts only when one of them changed.
- Workflow step payloads are cleared `jobs.workflow_payload_retention_days` (default 30) after the
  step finished, by the daily prune; the step summary stays. Erasing a record clears the inline
  step payloads that mention it.
- Workflow run control: `POST /api/v1/workflow/instances/{id}/retry` (a failed run again from its
  failed step), `/pause`, `/resume`, `/move` to a newer published version, and
  `GET .../move-preview` showing where each waiting step lands. Runs gain the `paused` status.
- Workflow node runs keep one row per node and loop round (`round`) with the node's `input` and
  `output` (a pair over 64 KiB goes to object storage, `payload_ref`); the instance detail
  returns them.
- A create or update with `Attome-Duplicate-Check: skip` bypasses the write-time duplicate
  check; it needs the new `duplicate.bypass` privilege (403 without) and leaves a
  `duplicate_check_skipped` audit event in the write's transaction.
- Workflows cannot loop: a flow started by another flow's write carries a chain depth, and a
  chain stops at depth 8 (`workflow_chain_depth_stops_total`). A flow's graph may set
  `settings.max_concurrent_runs`; extra runs wait as `queued` and start as runs finish.
- Schedule-triggered workflows now start on their own: a trigger with `trigger_type: "schedule"`
  takes `schedule: {every_minutes | daily_at + weekdays | cron}` in the deployment's time zone and
  starts once per slot (`workflow_schedule_slot`); unpublishing stops it.
- The OpenAPI document carries an `ErrorCode` enum: every `error` code the API answers with, each
  described and marked when a retry may succeed (`attome_types::error_codes`).
- `GET /api/v1/admin/security/mfa/coverage` (with `role_id` and `missing_only`) lists each active
  account's second factors and flags administrators without a phishing-resistant factor;
  `…/coverage/summary` counts per role.
- Environment variables: a new `environment_variable` metadata kind (type text, number, boolean, url
  or secret; required; default; descriptions) travels with configuration, while each deployment sets
  its own values at `/api/v1/admin/env-variables` (set, clear, history; a secret is encrypted and never
  read back). Agents edit definitions through `model.environment_variable.*` (migration `0067`).
- `GET /api/v1/admin/sbom`: the release's CycloneDX bill of materials (the release gate's, embedded at
  build time with `ATTOME_EMBED_SBOM`; other builds derive one from `Cargo.lock`) and the configuration
  packs installed.
- `GET /api/v1/admin/slo`: every SLO class with its status and 30-day error budget, computed by the
  server from its built-in metrics store (no Prometheus needed), its reference latency targets and
  any target the deployment set. `PUT /api/v1/admin/slo/targets/{class_id}` sets the deployment's own
  p95/p99 within half to three times the reference (row-version checked); `DELETE` goes back to the
  reference. Both audited (migration `0066`).
- The `ops.slo_health` agent action (administrators): each SLO class's status and budget left.
- Email test mode: `email.test_mode_catch_all` sends every email to one address instead of its
  recipients (an `X-Attome-Original-To` header names them), so a development or copied deployment
  never mails a real person; the server warns at boot while it is on.
- Built-in alerting with no Prometheus: the rules in `observability/builtin-alerts.json` (error rate,
  database pool timeouts, dead-letter jobs, job backlog, audit chain lag, file store down, changes
  paused, a node that stopped reporting) are evaluated every minute on the built-in metrics store;
  state in `ops_alert`, firings and resolutions in `ops_alert_event` (migration `0065`). Stored
  metric samples now carry a `node` label. Each firing and resolution goes to
  `observability.alert_emails` (queued email) and `observability.alert_webhooks` (`{"text": ...}`
  for Slack or Teams).
- Log a call in one step from a record's Activities tab: direction, minutes, notes and (when the crm
  pack adds it) outcome, saved as a completed call, with an optional next step created as a task.
- Kanban views take `sum_field`, `weighted_field`, `state_entered_field`, `stalled_after_days` and
  `flag_field`: columns show totals, cards past their state's day limit are marked stalled, and a
  positive flag field shows on the card. The sales pack's `Sales Pipeline` board uses them (amount
  and weighted totals, stalled deals, pushed close dates; changeset `0004-sales-board`).
- A date field can hold when another field last changed: `options.stamps_changes: {"field": ...}`
  (a deal's `stage_entered_at`).
- File check-out: `POST /api/v1/{entity}/{id}/files/{field}/checkout` locks a record's file for the
  caller; while it is held nobody else may upload or store a new version of it (409). `DELETE` checks
  it in; an administrator breaks someone else's lock with `?force=true`. All audited (migration
  `0064`).
- File share links: `POST /api/v1/{entity}/{id}/files/{field}/share-links` makes an expiring link
  (at most 30 days) to a stored file, with an optional password and download limit; `GET` lists a
  field's links and `DELETE …/share-links/{link_id}` revokes one. Anyone with the link opens it at
  `GET /api/v1/shared-files/{token}` (or `POST` with the password); every download is counted and
  audited (migration `0063`).
- The crm pack (changeset `0002-crm-customers-activities`): business and person accounts,
  communication preferences and sensitive personal-data fields on contacts, contact roles across
  accounts over time, account teams, typed addresses on any record; visits, outcomes, attendees,
  next steps and a consented check-in location on activities.
- The sales pack (changeset `0003-sales-catalogue`): Arabic product names, product families,
  units of measure with conversions, price list validity, list price and cost per unit, price
  breaks, account prices, related products, revenue recognition and return policy.
- Sales pipelines in the sales pack (changeset `0002-sales-pipeline`): stages as records with order,
  default probability and a stalled limit per pipeline (new business, renewal, upsell);
  probability, weighted amount, pipeline, won and lost reasons, main competitor and a close-date
  push counter on the opportunity; contact roles on deals; Arabic labels.
- A number field can count changes of another field: `options.counts_changes: {"field": ...,
  "when": "any" | "later" | "earlier"}` adds one on every update that makes such a change.
- `?select=a,b` on `GET /api/v1/{entity}/{id}` and on the answers of create, update and upsert:
  `data` carries only the named attributes; a name the caller cannot read is a `422`, refused
  before anything is written.
- Boot queues an index build for every lookup column that has none, and new text and JSON columns
  are compressed with lz4 when PostgreSQL offers it.
- Duplicate rules compare `phone`, `email`, `id`, `name` and `phonetic` keys (Arabic names meet their
  Latin spellings), keep each candidate's per-field scores, and scan a whole table in the background:
  `POST /api/v1/admin/data/match-rules/{id}/scan`, on save, and on `scan_schedule` (`hourly`, `daily`,
  `weekly`; migration `0062`).
- A duplicate rule's `on_save` checks a create or update before it is saved: `warn` saves it and lists
  the matches (`duplicate_warnings`), `allow_with_reason` needs an `Attome-Duplicate-Reason` header
  (kept in the audit), `block` refuses it with `409 duplicate_detected`; matches the caller cannot
  read are only counted.
- A merge is logged (both records as they were, every moved row) and its response carries
  `merge_log_id`; an entity set to keep merged records keeps the merged one live with `merged_into` on
  read instead of deleting it.
- Duplicate routes: `POST /api/v1/data/duplicates/check` (what a save would meet, without saving),
  `POST /api/v1/{entity}/{id}/merge/preview`, `POST /api/v1/{entity}/merges/{merge_id}/undo` (needs
  update and delete; refused once the survivor changed), `GET /api/v1/admin/data/duplicates/{id}/explain`
  (per-field scores and keys), `POST /api/v1/admin/data/match-rules/preview` (pairs a draft rule would
  flag in a 5,000-row sample) and `GET /api/v1/admin/data/duplicates/stats`.
- Agents get `duplicates.check`, `duplicates.list`, `duplicates.merge` (approved by a person first)
  and `duplicates.propose_rules` (a rule draft with its preview counts; never saved).
- Autonumber rules gain a `sequence_key` (`{branch}`: one counter per branch, per period), a
  `hijri_yearly` reset, `{field}` and `{lookup.field}` tokens in the format, and `assign_when`
  (`status = issued`): the number is given when a create or an update first meets it
  (migration `0056`).
- An autonumber rule may run in `fast_mode`: its number is committed on its own, so creates never
  wait on each other, and a failed create leaves a gap (for ticket ids, not invoices).
- `GET /api/v1/admin/autonumber/{entity}/{attribute}/gaps` lists each rule's counters and, per counter,
  the numbers missing or given twice among the stored records (deleted ones keep their numbers).
- A text or number field may be an external id: `options.external_id: {"system": "<name>"}` makes
  its value unique among the entity's live records (a unique index built online); an entity may hold
  ids for several systems.
- `options.unique: true` makes a text, number, date or lookup field unique among live records (an
  online unique index). A number or currency field's `min`/`max`, and a required field with
  `options.strict: true`, are also CHECK constraints in the database, validated against existing rows
  when the table is small and otherwise held for new writes.
- `POST /api/v1/{entity}/upsert?key=<attribute>` matches on an external id (or a business-key
  attribute) read from `data`; with neither `match` nor `key` it matches on the business key. A lookup
  value in a create, update or upsert may be `{"by": "<external id of the target>", "value": ...}`;
  ids no record holds are refused together with a 422 naming each.
- External ids survive a merge: the merged record's ids link to the survivor (migration `0055`), so a
  lookup by either id finds it. `options.editable_by: "integrations_only"` locks a field against
  people signed in to the app (`403`); API keys and service-to-service callers still set it.
- A bulk operation or staged import reports a row with a stale `expected_row_version` as a conflict
  (`outcome: "conflict"` and the record's `current_version` and changes) and applies the other rows
  (migration `0047`); `GET /api/v1/admin/conflicts?days=N` counts version conflicts per entity and
  source (migration `0048`).
- A user whose locale is Arabic gets text columns sorted by the ICU Arabic collation (`ar-x-icu`,
  when PostgreSQL has ICU). CSV exports and report CSVs start with a UTF-8 byte-order mark, so Excel
  shows Arabic correctly.
- `query/execute` filters take dynamic values resolved for the caller and the day: `@me`, `@my_team`,
  `@my_unit`, `@today`, `@this_month` and `@last_n_days(n)`, so one saved view such as "my open deals
  this month" works for everyone.
- A `409 version_conflict` on `PATCH /api/v1/{entity}/{id}` now says what changed since the caller's
  `If-Match`: `current_version`, and `current_state.changed_attributes` (name, the other writer's
  value, who and when) with `hidden_changes` counting changes to fields the caller cannot read.
- `POST /api/v1/{entity}/{id}/actions/{name}` invokes a record-bound action (one whose arguments
  take `entity` and `record_id`) on that record, through the same gate as `/api/v1/actions/{id}/invoke`.
- `POST /api/v1/{entity}/bulk-edit` changes the same attributes on up to 500 records, picked by id or
  by list filters: `set`, `clear`, `add`/`remove` (multi-select choices) and `increment`. Each record's
  new values are computed from its current ones and applied by the bulk engine through the normal
  update path with the record's row version, so a record changed in between is reported, not
  overwritten.
- `POST /api/v1/{entity}/bulk-edit/preview` shows what a bulk edit would do without doing it: how
  many records match, change and stay as they are, and the first 20 before and after.
- A bulk edit returns an `undo` list; `POST /api/v1/{entity}/bulk-edit/undo` puts the records back,
  skipping (and reporting) any record changed since the edit.
- `query/execute` takes `seek`: a keyset page that starts at a sort value ("jump to M"), bound and
  type-checked like a filter, with a `next_cursor`; not together with `after_id` (422).
- While the AI model is confirmed down, a conversation turn is refused up front with
  `503 capability_unavailable` (`ai_model`) before anything is written; every `capability_unavailable`
  response now carries `Retry-After: 30` and `retry_after_sec`.
- Five more capabilities are probed and reported: `ai_model`, `search_index`, `virus_scanner`,
  `cache` and `connectors`, each naming the features it affects; the status banner explains each in
  English and Arabic. Every period a capability is unavailable is kept in `degraded_period`
  (migration `0039`) and `/health/dependencies` lists the last 90 days as `degraded_history`.
- Statement classes: `attome_db::tx::begin_class` opens a transaction with the class's statement,
  lock and idle-in-transaction timeouts (fast, standard, report, admin), set transaction-locally with
  bound values; `database.statement_classes` overrides any class.
- Every DDL statement the provisioning engine runs is kept in `ddl_log` (kind, table, duration, lock
  retries, outcome; DDL text only, never values), listed per entity by
  `GET /api/v1/admin/entities/{entity_id}/ddl-log`. Migration `0038_schema_evolution_ledger` also
  adds `attribute_alias` and the `paused`/`cancelled` data-step-run states with `rows_total`.
- `GET /api/v1/admin/change-feed/consumers` lists every change-feed consumer (the platform's own and
  subscriptions) with its status, unread events, lag and last read; the governance Change Feed page
  shows them, and `change_feed_consumer_lag_seconds{consumer}` exports the lag.
- Deploy history: each node records a `start` row (process start to ready) and a `drain` row
  (shutdown signal to exit) with its version and who started it (`ATTOME_DEPLOYED_BY`);
  `GET /api/v1/admin/deploys` lists the last 100 for administrators. Migration `0037_deploy_event`.
- `database.node_count` (default 1) and `database.max_server_connections`: with more than one node,
  or the server limit stated, each pool without a `database.pools` entry is sized from 80% of the
  server's connections split across the nodes (runtime 60%, read-only 20%, read-only-primary 10%,
  migrator 2) instead of `connection_number`; the boot capacity log says which sizing applied.
- A response replayed for a repeated `Idempotency-Key` carries `Idempotency-Replayed: true` and
  `X-Original-Request-Id` (the request that ran), beside the original status, body, `Location` and
  `ETag`; both headers are readable cross-origin.
- Scanning (behind the `scan.enabled` flag, off by default): a text or number field takes
  `options.scan` (formats, GS1 batch and expiry fields, what an unknown code does), the web library
  reads GS1 element strings and checks GTIN check digits, and `GET /api/v1/scan/find?value=` returns
  the records the caller may read whose scan-enabled field holds the value (at most 50).
- A query that runs past its time limit answers `504 query_timeout` with a hint to narrow it or run
  it as an export (was a masked 500).
- `query.timeouts_ms.interactive` (default 500) and `query.timeouts_ms.report` (default 5000) set how
  long a query may run; they were fixed values.
- The web app shows any number of languages. `provideAttomeBase({ languages })` lists them with their
  direction and catalogue; a key a language lacks falls back through its chain (`ar-SA`, then `ar`,
  then English), and the profile menu offers every configured language.
- A business-rule check (`error`, `required`, `allowed_values`) can be rolled out in stages: `stage`
  `report` logs failures, `warn` saves with a warning, `enforce` refuses, from `enforce_from` when set
  (warning before then). A user holding `record.override_rules` (or an administrator) saves past a
  refusing check by sending `X-Override-Reason`; each override is a security event.
- A record form says when the record changed on the server while it was open (who and when, or that
  it was deleted), from the live channel, with a button to load the newer version.
- The web app reports page speed (LCP and INP, `POST /api/v1/telemetry/web-vitals`) to the metrics
  store as `attome_web_vital_ms`, and loads the signed-in app's code while the sign-in page is idle.
- New notifications reach the bell over the live channel (`notifications` frames on
  `GET /api/v1/live`) instead of waiting for its 30-second poll, which stays as the fallback.
- Read-only mode: while the `ops.read_only` setting is on, or the database reaches
  `deployment.read_only_at_database_bytes`, every write answers 503 `read_only`; reading, signing in and
  the switch itself still work, and `/api/v1/system/status` gives the reason.
- A production configuration refuses a secret written into the file: every password, key and
  client secret must come from a `${VAR}` placeholder (the variable or `VAR_FILE`). Preflight checks
  each `VAR_FILE` a placeholder reads, naming the variable only.
- The command palette offers a question (three words or more, or ending in a question mark) to the
  copilot, which answers it from the data through the query planner.
- Simple mode (`core.simple_mode`, a personal setting) hides advanced actions such as duplicating,
  sharing and changesets; the metadata explorer lists a menu's items nobody opened in 60 days.
- `attome release tag` writes the version's notes in English and Arabic (`release-notes/v<version>.en.md`
  and `.ar.md`), breaking changes first; Arabic entries are marked until their translation is reviewed.
- `document.extract` reads business cards (`doc_type: business_card`): name, job title, company,
  email, phone and website, a contact draft, and the email and phone to match an existing contact on.
- Reply templates (`reply_template` model kind): a folder, who sees it (everyone, a user, team, role
  or queue), a body with `{{field}}` merge fields, and short SMS and WhatsApp variants.
- The standard `Idempotency-Key` header is accepted beside `x-idempotency-key`; both with different
  keys answer 422. On signed S2S requests only `x-idempotency-key` counts.
- Record create, update and upsert honour `Prefer: return=minimal`: the answer is only `{id, row_version}`
  (plus any warnings or approval id), with `Preference-Applied: return=minimal` and the row version as `ETag`.
- Sign-in has a per-address budget beside the per-account one: 20 failed sign-ins from one address
  (an IPv6 address by its prefix) in 15 minutes, across accounts, answer 429 until the window ends.
- The OpenAPI document's `info.version` is the release version (it said 1.0.0).
- `attome migrate` and a migrate-on-boot node refuse to run migrations when connected as another role or
  database than configured; preflight reports it as `database.identity`.
- The OpenAPI document declares every accepted credential: `s2s_hmac` (the signed system-to-system
  headers and how to sign) and `portal_session` beside `session_cookie` and `api_key`.
- Security headers are chosen per surface: `/api/` responses carry no CSP (so a brand asset keeps its
  own sandbox policy) and `X-Frame-Options: DENY`; pages keep the CSP.
- The release gate refuses new hard-coded interface text: `npm run check:i18n` counts the text in each
  template that does not come from the catalogue and fails when a template holds more than its baseline.
  A pseudo-language (`pseudoCatalog`) shows text that skips the catalogue and layouts that break.
- `FeatureFlags::is_on_for_deployment` lets a background job read a feature flag without a signed-in
  user: the deployment-wide value, with a partial rollout counting as off.
- A stopping worker returns the jobs it still holds to the queue at once, so another worker picks them
  up within seconds instead of after the orphan timeout. Workers are named per process
  (`platform-job-worker@{host}:{pid}`).
- While a server drains for a restart, MCP calls answer a retryable 503 with `Retry-After: 2` and
  JSON-RPC error -32000, so an agent retries on the next process.
- On Windows, Ctrl+Break, closing the console and a system shutdown start the same graceful drain as
  SIGTERM on Linux; the log names which stop started it.
- A write that reaches a database leader the failover manager just demoted (SQLSTATE 25006) answers the
  retryable 503 `db_unavailable`, like a lost connection, instead of a 500.
- Outbound calls through the guarded client (webhooks, connectors) carry the current `traceparent` and
  the `x-request-id` of the request that caused them.
- A change-feed consumer that falls too far behind (a week for webhook subscriptions, a month for the
  platform's own) is marked expired, logged and counted (`change_feed_consumer_expired_total`), and the
  prune moves past it instead of keeping the whole feed.
- An attribute's `options.scan` (formats, GS1 batch and expiry fields, what an unknown code does) is
  validated: only on text, number and lookup fields, with known formats, else 422.
- `parseGs1` reads a GS1 code's GTIN, batch, expiry and serial, and `isValidGtinCheckDigit` checks a
  GTIN, in `@attome/base`.
- Feature flags `scan.enabled`, `scan.actions_enabled` and `scan.continuous_enabled` (off by default)
  keep scanning hidden until a deployment switches it on.
- Every password, key and client secret in the configuration is a `Secret`: it never prints, never
  serializes, and has no `Display`, so code reads it with `expose()` where it is handed on.
- Interface wording: a deployment rewords built-in text per language (`PUT`/`DELETE
  /api/v1/admin/i18n/overrides`, a `ui_text` label, migration 0034); the app lays
  `GET /api/v1/i18n/overrides` over its catalogue.
- Menus count each item's opens per day (migration 0033, `POST /api/v1/model/navigation/{id}/opened`);
  `GET /api/v1/admin/model/navigation/{id}/usage` lists each item's opens and flags the ones nobody
  opened in 60 days.
- Isolation: a deployment makes its own id on first boot (migration 0032); on the production profile
  each server claims the cache with it and refuses to start when another deployment already has
  that Redis database.
- Translations: a label keeps a hash of the text it translated and whether it is reviewed
  (migration 0031); `GET /api/v1/admin/entities/labels/workbench?locale=` lists every entity,
  attribute and choice label as untranslated, stale (its source changed), draft or reviewed.
- Metadata: an `option_set` kind, a shared list of values with stable codes, English and Arabic
  labels, colours, order and retirement, for choice fields on several entities.
  A choice field whose options name a set (`{"option_set": "<name>"}`) takes the set's published,
  not retired codes; publishing the set refreshes every entity that uses it.
- Every API response carries `Attome-Metadata-Version`, the last metadata change the answering node
  has applied (exposed to browsers through CORS), so clients notice a new model.
- Status banner: `GET /api/v1/system/status` tells any signed-in person which features are down or
  slow (as message keys) and whether changes are paused; the shell shows it in English and Arabic.
- Trees: `GET /api/v1/{entity}/{id}/move-preview?parent=` says how many records a move would carry
  and whether it would be refused (a cycle, or the depth cap).
- Record forms show where a record sits in its entity's tree (a breadcrumb of its ancestors, each a
  link), for entities with a self-referencing lookup.
- Honest totals: `query/execute` with `include_total` counts a matching set only when the planner
  expects fewer than 100,000 rows; past that it returns the planner's estimate with
  `total_estimated: true`.
- Aggregation: `POST /api/v1/search/aggregate` takes `then_by`, a second field to group by within
  each `group_by` bucket; buckets then carry `label_2`.
- Business rules: `add_tag` and `remove_tag` outcomes tag or untag the record written while the
  condition holds (migration 0030).
- Business rules: two outcomes, `required` (a field is required while the condition holds) and
  `allowed_values` (a field takes only the listed codes while it holds), enforced on every server
  write (migration 0029). A default value is the existing `set_value` with `mode: default`.
- Tags: `POST /api/v1/admin/tags/{tag_id}/merge` moves a shared tag's links into another (its
  name then finds the other tag) and `/unmerge` undoes it (migration 0028); an hourly job removes
  tag links past their expiry.
- Request trail: a job queued while serving a request stores its id (`request_id` in the job
  envelope), and `GET /api/v1/admin/ops/requests/{request_id}` lists the request's jobs and audit
  events.
- Operations overview page: every node by health from a once-a-minute heartbeat
  (`attome_node_up`, `GET /api/v1/admin/ops/nodes`), and a page of charts per area (requests,
  database, cache, jobs, storage, email, AI models) from the built-in metrics store.
- Live lists: `GET /api/v1/live?entities=` also sends `records` frames, the changes to records of
  those entities the caller can read; an open list reloads changed rows in place and offers new
  ones behind a "N new records" banner.
- Record history: each change names its change set (`group_id`: an import or bulk batch, an agent
  session, a flow run or one save), who made it (`actor`) and through what (`source`).
- Record history: `POST /api/v1/{entity}/{id}/history/restore` puts back the values one change
  (`audit_id`) or a whole change set (`group_id`) replaced, through the ordinary update with
  `If-Match`.
- Record history: `GET /api/v1/history/search` finds the changes to one field whose old and new
  values meet conditions in a period (for example, the amount went above 20 last month), among the
  live records the caller can read.
- Clone with children: `POST /api/v1/{entity}/{id}/clone` takes `children` (entity and lookup
  field) and copies each readable child record under the new record, up to 200.
- Clone: the result lists every record made (`undo`); `POST /api/v1/{entity}/{id}/clone/undo`
  moves them to the recycle bin while none has changed, and `POST /api/v1/{entity}/clone` copies
  up to 50 records with the same overrides.
- Recycle bin: every delete records who, when, why and its operation (migration 0024);
  `DELETE /api/v1/{entity}/{id}?reason=` and the `Attome-Operation-Id` header,
  `POST /api/v1/{entity}/delete-impact`, `POST /api/v1/bin/restore`,
  `POST /api/v1/bin/operations/{operation_id}/restore` and `/api/v1/admin/bin-settings`; a list
  delete offers Undo; see docs/recycle-bin.md.
- Recycle bin: a restore refused because a parent record is deleted names that record
  (`parent`), and the bin page offers to restore both; the entity metadata screen edits the
  entity's bin rules.
- Workflows: a **Restore Record** node (`restore_record`) brings a deleted record back.
- Command palette: Ctrl+K (or Shift twice) finds records, pages and commands in one box; `>`
  lists commands only and `acc:` searches one entity's records; the open record's actions come
  first, then what the person picks most.
- Backups copy the file store beside the database, `attome restore` puts files back, an erasure
  ledger in object storage re-applies erasures after a restore, and a monthly restore drill
  (`attome backup drill`) records evidence; `GET /api/v1/admin/backup` reports it all.
- Tags in lists: select records and add or remove a tag at once (`POST /api/v1/{entity}/tags/bulk`,
  up to 500 records, each checked on its own); a tag chip opens a page of every record carrying it,
  grouped by entity, and each group opens its list filtered by the tag (`?tag=`).
- Brand assets and email branding: logo, favicon and fonts per theme version
  (`/api/v1/admin/themes/{id}/assets`, public `GET /api/v1/branding/asset`); password-reset,
  verification and invitation emails show the logo or `app_name` and use the brand colour.
- `GET /api/v1/branding/me` gives a signed-in person the brand for their app and business unit;
  both branding routes send an ETag and answer `304` while no published theme changes. Admins
  roll a theme back (`POST /api/v1/admin/themes/rollback`), see what a version changes
  (`GET .../{id}/diff`) and edit the theme on the Branding page.
- Brand themes (migration 0023): `/api/v1/admin/themes` drafts, edits (If-Match) and publishes
  them behind the contrast check, `POST .../preview-check` measures colours, and the public
  `GET /api/v1/branding/public` gives the sign-in page and the app their colours.
- A Duplicate button on a saved record copies it and opens the copy.
- `POST /api/v1/{entity}/{id}/clone` copies a record through the ordinary create (system,
  autonumbered, file, formula and engine-owned fields left out; `overrides` and `preview`).
- Brand theme tokens with a WCAG 2.2 contrast check (`attome_core::theme_tokens`): text 4.5:1,
  brand and status colours 3:1, status colours kept visibly apart.
- Label translation through XLIFF 2.0: `GET /api/v1/admin/entities/labels/xliff?locale=ar-SA`
  exports every entity, attribute and choice label; `POST` the translated file back (placeholders
  checked, all or nothing).
- `GET /api/v1/{entity}/new` returns a new record's defaults, and the new-record form shows them.
- Attribute defaults: `options.default` is `{"kind": "fixed", "value": ...}`, `today`, `now` or
  `current_user`, filled on every create path when the attribute is empty.
- `GET /api/v1/{entity}/deleted` lists the deleted records the caller may see, newest first;
  agents get `record.deleted` to find them and `record.restore` to bring one back.
- `GET /api/v1/{entity}/{id}/timeline/export?kinds=` downloads a record's timeline as CSV (up
  to 2000 entries, the same permissions as the timeline).
- A `tagged` filter operator (`{"field": "id", "op": "tagged", "value": "<tag id>"}`) for
  `query/execute`: the records carrying a tag, personal tags only for their owner.
- `attome restore <archive|latest> --yes` puts the database back to a backup, after writing a
  backup of the current one, in one transaction.
- Tags under a record's title: suggestions while typing, a new tag on Enter, personal tags marked.
- Tags on any record (migration 0022): shared or personal, matched ignoring case and Arabic
  diacritics; `GET/POST /api/v1/{entity}/{id}/tags`, `DELETE .../tags/{tag_id}`,
  `GET /api/v1/tags/suggest?q=`, `GET /api/v1/tags/{tag_id}/records` (across entities, readable
  records only) and tag groups with a create policy (`/api/v1/admin/tag-groups`).
- A history clock beside each field on a saved record lists that field's past values and puts one
  back into the form (saved through the normal update, with its row version);
  `GET /api/v1/{entity}/{id}/history?field=` returns one field's changes.
- CSV and XLSX exports write date columns in the exporting person's calendar and digits
  (`core.calendar`, `core.digits`); JSON exports keep ISO dates.
- Reports and dashboards group dates by `hijri_month` and `hijri_year` (Umm al-Qura, with the
  deployment's sighting corrections), labelled `1447-09` and `1447`.
- Calendar holidays by Hijri date: `hijri_date` on a holiday (alternative to `holiday_date`, and
  returned with it), and `POST /api/v1/admin/calendars/{id}/holidays/hijri-recurring` for one holiday
  per Hijri year (up to 30), such as Eid.
- Hijri dates in the browser use the same Umm al-Qura table as the server (not the browser's
  own, which differs by a day outside 1420-1450 AH); a date field set to Hijri, or a person who chose
  Hijri, gets Hijri day, month and year entry.
- A Settings page (profile menu): language, time zone, calendar, digits, date order, start page,
  theme, text size and motion, applied at once. Dates show in Hijri (Umm al-Qura), Gregorian or both,
  with Western or Arabic-Indic digits.
- Personal settings in `/api/v1/settings/me`: `core.time_zone`, `core.calendar` (gregorian, hijri,
  both), `core.digits`, `core.date_format`, `core.start_page`, `core.theme`, `core.text_size` and
  `core.reduced_motion`, with organization and deployment defaults. A date attribute takes a
  `display_calendar` option (gregorian, hijri, both).
- Autonumber formats take Hijri tokens: `{hyyyy}`, `{hmm}` and `{hdd}` (for example
  `INV-{hyyyy}-{####}`).
- Moon-sighting corrections to the Hijri calendar: `GET /api/v1/admin/hijri-months?year=` and
  `PUT /api/v1/admin/hijri-months/{year}/{month}` (one day at most, audited); every node uses the
  corrected calendar within 20 seconds.
- The Umm al-Qura Hijri calendar, 1356 to 1500 AH: `attome_calendar::hijri` converts both ways and
  names the months in Arabic and English; migration 0021 adds the same table as `hijri_month` for
  grouping in SQL.
- A star in the header keeps pages and records at hand: lists you reorder by dragging, up to nine
  pinned items opened with Ctrl+1..9, team lists, and the records you opened lately (also shown in
  quick search before you type).
- Recent records and favourites: `GET/POST/DELETE /api/v1/me/recent`, `GET /api/v1/me/favourites`,
  personal lists under `/api/v1/me/favourites/lists` and team lists under
  `/api/v1/teams/{team_id}/favourites/lists` (audited), each saved whole with up to nine pins.
- Agents get `system.status`, and a tool call refused because a service is down says which one and
  whether to retry (`degraded`, `retryable`).
- Responses prefer Brotli, fall back to gzip, and are sent raw when under 1 KB or already
  compressed (images, video, zip, PDF, octet-stream).
- A schema change blocked by a table lock retries after 1, 2, 4 and 8 seconds; a queued one then
  waits five minutes and tries again, up to 12 times, before failing with `lock_timeout`.
- Solo backs up its database every day (`backup`, on by default; `attome backup now`); see
  `docs/backup.md`. `POST /api/v1/{entity}/validate` checks a record without saving it.
- `under` and `above` filter operators for lookups into a tree; choice-value usage counts
  (`GET .../fields/{field_id}/choice-usage`); every lookup column is indexed.
- `cache.metadata_poll_interval_secs` (default 5) and readiness that reports a node whose metadata
  lags the change log.
- Record values are normalised before validation: text trimmed, phone fields in E.164 shape,
  email fields lower-cased, Arabic digits made Western in masked fields and numbers sent as text.
- Autonumber formats take `{LUHN}` and `{MOD11}` check digits; their dates and resets follow
  `app.time_zone`. A create may no longer supply an autonumbered value (except a data migration).
- `attome doctor` (the preflight checks, with what to do about each failure) and `attome status`
  (each node's version, schema, start and readiness).
- `/health/startup` (200 once boot is done); readiness answers from a two-second cache and records
  `attome_readiness_check{check}`.
- A usage page (`/xrm/admin/license/usage`, `GET /api/v1/admin/usage`): modules on, active users and
  `app.contract_reference`.
- Knowledge retrieval fuses keyword and vector results and reranks with `inference.rerank`.

### Changed
- `GET /api/v1/openapi.json` is filtered per caller (S2-T14): only the operations of the modules
  switched on (`x-module`), none under `/api/v1/admin` for a caller who is not an administrator,
  and only the component schemas still referred to. It carries an `ETag` (the release, the module
  set and the admin flag) and answers `If-None-Match` with 304. The full document is still what
  `attome serve --print-openapi` and the committed `openapi.json` hold.
- Idempotency keys on consequential operations (custom actions, bulk jobs, billing and payment
  changes, messages sent) always use the durable Postgres tier, and on a deployment without Redis
  every key does (S9-T2); a bulk job's record is kept for `idempotency.bulk_retention_hours`
  (seven days by default) instead of the general window.
- A single-valued choice field may be part of a business key (the sales pack keys its stages by
  pipeline and stage); multi-valued fields still may not.
- The sales, commission, marketing, vendor-supplier, contract-management and finance packs install
  again: report queries that join tables are multi-entity queries, two calling-metric queries had an
  unfilled `{J}` placeholder, pay amounts are classified `personal`, and `vendor.contract_ref` moved
  to the contract-management pack, which already builds on vendors (install crm, vendor-supplier,
  then contract-management).
- A record write with bad fields answers with every failing field at once: one 422 whose `details`
  lists each field with a code (`unknown_field`, `required`, `invalid`, `too_long`). The dry run
  (`POST /api/v1/{entity}/validate`) returns the same list as `failures`.
- `/health/dependencies` needs an administrator and no longer lists the modules on.
- `document.extract`: invoice and receipt fields (VAT number, invoice number, date, total, VAT) from
  text with a confidence each, the exact fields of a ZATCA QR code, and the fields to review.
- Local OCR (`inference.ocr`, a vision model) and speech to text (`inference.speech`) in
  `attome-inference`, both inside the deployment only.
- `attome init --ai <profile>` verifies a local model pack's weights against its checksums.
- Agents and prompts publish only while their eval suites' newest runs pass every safety case;
  `PublishResponse.warnings` reports a score that fell.
- `GET /api/v1/admin/knowledge/explain`: why a question retrieves the passages it does.
- Chat answers show tool results as live tables, charts and record cards; "Do this every time" saves
  the request as a workflow draft that runs the same agent. Bulk changes above 20 records run only
  after their own preview (`preview_token`).
- Pinned AI models (platform changeset 0049): `pinned_version`, `base_model` and a drift eval suite on
  the AI Model catalogue; the nightly quality job re-runs the suite and alerts on drift.
- An evidence export on the AI governance screen: one JSON file per period and kind.
- The AI governance screen (`/ai/governance`): per-write approval policies and approval figures with
  rubber-stamp warnings.
- The outside-tools screen (`/ai/mcp`): register MCP servers, import their tools, set each tier.
- Outside MCP servers for agents (`/api/v1/admin/mcp-servers`, migration 0019): imported tools arrive
  disabled; an administrator sets each tier; agents list them with `mcp.tools` and call them with
  `mcp.call.read|reversible|consequential` through the dial guard.
- Per-task model routing: `inference.task_models` sends an action (or `agent.turn`) to an approved
  catalogue model through its provider; unlisted tasks keep `inference.generation`.
- Optional local model servers: `deploy/model-servers/docker-compose.yml` (TEI embeddings, llama.cpp
  on CPU, vLLM on GPU) and `docs/model-servers.md`.
- `GET /api/v1/admin/agents/sessions/{id}/run`: a session's run as one tree (parent, children,
  turns with model and prompt version, each tool call with the gate decision and ledger outcome).
- `GET /api/v1/admin/ai/evidence`: every agent action and model-written suggestion in a period, by
  agent or model, keyset-paged, for audits.
- Automatic trip: when an AI action's acceptance falls by 30 points or more, the nightly quality
  monitor switches it off (cause `quality`) until an administrator turns it back on.
- `GET /api/v1/admin/approvals/metrics`: per-approver decisions, approval share and median time,
  backlog by action, common rejection words, and rubber-stamp warnings.
- `POST /api/v1/admin/approvals/batch-decide`: decide up to 100 similar requests at once, each through
  the single-decision path, with each request's outcome returned.
- The agent designer runs the agent's eval suites and shows each case's result.
- The prompt editor (`/model/prompts`): each shipped prompt, your override sections after its locked
  text, a rollout share, and for record summaries a try-on showing exactly what the model receives.
- Chat modes: `POST /api/v1/ai/conversations` takes `mode` — `develop` (metadata tools and reads, so
  changes are drafts) or `run` (everything but the metadata edit tools).
- AI attributes: an attribute with `options.ai.prompt` gets suggestions from `record.ai_field`, the
  prompt as the instruction and the fields it names as data, with provenance stored.
- `GET /api/v1/admin/model/health`: broken references, duplicate-looking attributes, entities and
  attributes nobody uses, and index proposals, from the registry and PostgreSQL statistics.
- `knowledge.answer` checks each sentence against its cited passages (content words and every
  number) and returns `claims` with the unsupported sentences flagged and a checked answer.
- A local prompt-injection classifier (English, Arabic, Arabizi) marks untrusted text that reads like
  instructions with a warning before the model sees it; strict channels can withhold it.
- Per-write approval policies for agents (`/api/v1/admin/ai/write-policies`, migration 0018), off by
  default: a matching confirmed agent write waits for a second person's approval.
- Agent-to-agent: `GET /api/v1/a2a/agents` (agent cards with their contracts) and
  `POST /api/v1/a2a/agents/{agent}/tasks` (one read-only task through the contract).
- An MCP connection can run as an agent: `initialize` with `params.agent` narrows the session to
  the agent's tools and applies its daily limits.
- Eval suite runs: `POST /api/v1/admin/ai/eval-suites/{suite}/runs` runs each case as a turn of
  the suite's agent and grades it; `GET /api/v1/admin/ai/eval-runs/{id}` reads it (migration 0017).
- `POST /api/v1/model/agents/{agent}/sessions`: a session starts from a published agent object (its
  `policy`, `persona.model`, tools and daily limits), with no `ai_agent` definition (V2-D487 step 3).
- Each chat or agent turn recalls the person's matching memories (at most 5, 4,000 characters) as
  untrusted context.
- An agent's approval request records its target record's row version and the before and after of
  the fields it changes; if the record changes before the approved action runs, the approval is void.
- `article.draft` never drafts twice: an article already drafted from the same record is returned,
  and one with the same title (Arabic letter forms normalised) is reported unless `force` is set.
- `GET /api/v1/admin/ai/status` and the AI status screen (`/ai/status`): the model in use and its card,
  what is switched off, how turns ended over the last day, and the switch timeline.
- `POST /api/v1/admin/ai/eval-suites/{suite}/cases/from-message`: an answer that went wrong becomes
  a case in the suite's draft, its input taken from the question it answered.
- `POST /api/v1/admin/ai/preview/summary`: exactly what a model would receive for a record summary,
  built by the same code, without generating.
- A Translate button under notes and replies translates them into the viewer's language.
- `text.translate` with a deployment glossary (`inference.translation.glossary`) and a 30-day cache
  keyed by the text, languages, glossary and model.
- `record.transitions` and `record.transition`: agents move a record through its state model on the
  ordinary update path, approvals included.
- `agent.delegate`: a supervisor agent hands a subtask to a specialist through the specialist's
  typed `handoff` contract; the specialist runs read-only in a child session (migration 0016,
  `agent_session.parent_session_ref`).
- Agent bulk actions: `record.bulk.preview`, `record.bulk.update`, `record.bulk.delete` and
  `record.bulk.status`, over the bulk engine (`attome_records::bulk::submit_bulk`, `bulk_status`).
- `GET /api/v1/admin/ai/spend` and the AI spend screen (`/ai/spend`): this month's spend per
  deployment, feature and agent against each cap, with the month forecast.
- Money budgets for AI (`inference.spend`): prices per model and monthly caps per deployment, person,
  agent and feature; near a cap generations are shortened, at a cap refused (429) before any spend.
- `record.summarize` sees the related records and the recent timeline (within a budget, every part
  filtered by the caller's grants) and reuses a summary of identical facts from a 24-hour cache.
- `query.plan`: a question becomes a query model checked against the metadata (fields, operators,
  value types, sensitive-field grants) before `query.execute` runs it.
- The `library-core` pack: party, person (four-part Arabic name, national id, iqama, Emirates ID),
  organisation, Saudi national address, work item and agreement.
- Attome v2: one `attome` binary (`attome init`, `attome serve` and the operator commands) on
  PostgreSQL alone for a single server; Redis is optional.
- The release gate (`attome-release --check`, also `attome release --check`) writes a per-OS report
  to `target/release-gate/` and checks the API contract against the previous release.
- The metadata model: forms and other metadata kinds are stored as versioned drafts, edited with
  `add`/`remove`/`move`/`set` commands (the same for people and agents), validated in three steps
  and cooked into content-hashed artefacts; administrators reach it under `/api/v1/admin/model`.
- Metadata as files: `GET /api/v1/admin/model/export` and `POST /api/v1/admin/model/import`, with
  `attome model export --out <dir>` and `attome model import --dir <dir>`, move objects as one
  readable JSON file each; import saves drafts and never publishes.
- Agents as metadata: the `agent` kind (role, instructions, tools, identity, limits, triggers,
  channels) with an agent designer at `/model/agents`, a metadata explorer at `/model/explorer`,
  and `model.<kind>.edit|describe|list` agent tools generated from the kind registry.
- One-command install: `scripts/install.sh` (Linux, installing PostgreSQL 18 with pgvector when no
  database is given) and `scripts/install.ps1` (Windows), release archives with the web app, which
  `attome serve` now serves itself, and `attome init --admin <email> --service`.
- Form render plans carry a content ETag; the web app loads each plan once per version.
- Agent daily limits: an agent's `limits.daily` caps record changes, deletes, messages and outside
  calls per day across all its sessions; a session started with `agent` (a published agent object)
  is held to them and to the agent's tools, and `GET /api/v1/admin/ai/agents/{agent}/usage` reports
  today's use.
- MCP: `tools/list` returns a core set plus `tools.search`; `initialize` carries a playbook.
- The live channel `GET /api/v1/live` tells the web app when published metadata changes.
- Install and operations: `attome service install`, `attome bundle offline`, `attome sovereignty
  report`, a sizing check in `attome init`, and the `deployment.sovereign` preset.
- Testing and release tooling: `attome test` (tiers, a Docker test stack, flaky-test reruns,
  quarantine, coverage, the coverage map), the SLO catalogue with `attome slo generate`, and gate
  steps for waivers, `cargo deny`, npm licences, SBOMs, dependency intake, install time and a boot
  smoke test.

### Breaking
- `POST /api/v1/admin/content/pages/{id}/publish` (K5-T1): in a space with `require_approval` it
  answers 202 with `status: "pending_approval"`, `published_at: null` and `approval_request_id`;
  every publish result also carries `version_number`.
- Document templates (K3-T1): a docgen template is compiled before it renders, so `{% endif %}`
  must become `{% end %}`, and a field the entity does not have is refused at render (422 naming the
  line and column) instead of rendering empty. A field the user may not read still renders empty.
- `GET /api/v1/{entity}/bulk/{id}?include_items=true` reports its items in the standard batch shape
  (Z14-T6, `attome_types::BatchResult`): each item is `{index, ok?, problem?}`, where `ok` is
  `{record_id, attempts}` for an applied item and `problem` is `{code, message, detail?}` for one that
  did not (`version_conflict`, with the record's current version and state in `detail`, or
  `item_failed`); a pending item has neither. The previous per-item `item_index`, `status`,
  `outcome`, `error`, `conflict` and `attempts` fields are gone. List responses
  (`PaginatedResponse`) gain an optional `warnings: [{code, message}]`, sent only when there is one.
- Stored secrets are write-only (Q18-T6): `POST /api/v1/admin/ai/providers/{id}/credential` and
  `POST /api/v1/admin/integrations/systems/{id}/credential` answer `is_set` and `updated_at`
  instead of `secret_last4`; no part of a user-supplied secret is returned. The AI provider form
  says the key is stored. A test now refuses any secret-looking response property without a listed
  reason (generated secrets shown once at creation, presence flags, references).
- Error bodies are RFC 9457 problem details (Z14-T1): served as `application/problem+json`, with
  `type`, `title`, `status`, `detail`, `code`, `retryable`, `instance` and, for field failures,
  `errors` beside the existing `error`, `message`, `request_id` and `details`, which keep their
  values. A client that checked for exactly `application/json` on an error must accept
  `application/problem+json`; the SDK does.
- `GET /api/v1/billing/disputes/{id}/evidence` answers a `PaginatedResponse` (`items`, page 1 holds
  every document) and `POST /api/v1/billing/accounts/{id}/apply-credit` answers
  `{account_id, payments}` instead of bare arrays (the contract shape guard).
- A request past a limit answers `limit_exceeded` naming the `limit`, its `value` and the `next` step
  (`split`, `run_as_job`, `export`, `retry_after` with `Retry-After`, `contact_admin`): a bulk request
  of more than 500 records and an upload past a storage quota are now `413 limit_exceeded` instead of
  `422 validation_error`.
- A write that sets an attribute the caller may not write (no field-security write grant, a field
  locked to integrations, or a new `options.create_only: true` field on update) answers
  `403 attribute_not_writable` with the attribute in `field`, instead of `403 forbidden` or, for
  create-only, being saved.
- `POST /api/v1/{entity}/{id}/clone` now needs the create privilege on the entity (and on every
  child entity it copies); it used to need only read access.
- `DELETE /api/v1/{entity}/{id}/hard-delete` needs the new `{entity}.hard_delete` privilege besides
  `delete`; an entity whose bin setting requires a reason answers `422` to a delete without one.
- Boot refuses an `inference.generation.base_url` outside the deployment unless
  `inference.allow_external_provider` is true (it used to fail at the first request).
- v2 renames every table, entity and API path segment that carried v1's `xrm_` or `core_` prefix
  (`/api/v1/xrm_service_ticket` is `/api/v1/service_ticket`); see `docs/roadmap-paths.md`.
- Licences are gone: `/api/v1/admin/system-health` reports `modules` instead of `license`.
