# Changelog

Every release lists what changed for administrators, users and developers. A breaking change to
`/api/v1` (a removed or renamed route, a removed response status or field, a newly required request
field, a changed type) is named under `### Breaking` in the `[Unreleased]` section in the same change
that makes it; the release gate's contract step refuses a release that breaks the API silently.

## [Unreleased]

### Security
- HTTPS without a proxy (Z5-T6): with `app.tls.enabled` the server terminates TLS itself (HTTP/2 and
  HTTP/1.1 by ALPN; `app.tls.min_version = "1.3"` refuses TLS 1.2) from `app.tls.cert_path` and
  `key_path`, reloading the files every 12 hours and on SIGHUP. Boot names the file that is missing
  or unreadable. Behind nginx, leave it off.
- OAuth 2.0 client credentials for server-to-server clients (S11-T1): `POST /api/v1/oauth/token`
  issues a ten-minute access token for the client's service user, typed `s2s_access` so no session
  validator accepts it. Clients authenticate with private_key_jwt (RS256, ES256 or EdDSA; each
  assertion's `jti` is accepted once) or client_secret_basic; every issued token writes a
  `s2s_token_issued` credential event. A bearer request gets the signed path's checks (status, idle
  limit, IP allow-list, rate, concurrency and payload limits, entity ceiling) and cannot act as a
  user. The admin client API gains `oauth_public_key_pem` and `oauth_scopes` (migration 0205).
- Content-Security-Policy nonces and reports (Q21-T2): each web app page is served with a fresh
  128-bit nonce, on Angular's `ngCspNonce` and the page's scripts, and its `script-src` names it;
  every page policy adds `object-src 'none'` and reports violations to the new public, rate-limited
  `POST /api/v1/security/csp-report` (counted as `csp_violations_total{directive}`, nothing
  stored). `style-src` still allows inline styles while Angular needs them.
- Keyset cursors are signed (Z14-T5). **Breaking:** every `next_cursor` a list returns is now an opaque
  signed value; send it back verbatim. A cursor the deployment did not issue, a tampered one or a bare
  row id (what the entity list, AI evidence and others sent before) is `400 invalid_cursor`; start
  again from the first page. The key derives from `auth.jwt_secret`, so all nodes agree and a key
  rotation keeps lists paging.
- Trial mode and earned autonomy (AH6, AH8-T8, AH8-T9): an agent definition in `testing` runs on
  real triggers but records its writes instead of making them; an hourly job compares each with what
  a person did, `GET /api/v1/admin/ai/agents/{agent}/trial-report` shows the agreement and
  `POST .../go-live` sets the agent active above a threshold (Trial tab on the agent form). Strong
  trial agreement proposes raising an action's autonomy level one step
  (`/api/v1/admin/ai/autonomy/proposals/{id}/accept|reject`), and each person gets a daily summary of
  what their agents ran automatically. Migrations 0193 and 0194.
- Act on review (AH8-T13, V2-D702): a new autonomy level, `act_on_review`, stages an agent's action
  instead of running it; the person applies or discards an agent session's staged actions together
  (`POST /api/v1/ai/deferred-actions/apply|discard`), and they run in order, each re-checked. New
  outcome `awaiting_review`. Migration 0192.
- Agent autonomy levels (AH8, V2-D693): an administrator can now let an agent run an action on its
  own, per agent and per action (`/api/v1/admin/ai/agents/{agent}/autonomy`), including a
  consequential one, which until now always waited for a second person's approval. With no level set
  nothing changes. Limits (daily count, money cap, owned records only, hours) ask first when
  exceeded, untrusted text in the agent's context lowers the level by one, and every change is a
  security event. New: the undo window, which holds any action (`act_with_undo`, the invoke API's
  `undo_window_seconds`, or an agent's `_undo_window_seconds`) so it can be cancelled before it runs
  (`/api/v1/ai/deferred-actions`), and the `email.send` agent action. `ActionOutcome` gains
  `scheduled`. Migration 0190.
- Integration secrets stay sealed (Z1-T10): a decrypted credential is now an
  `attome_integration::credential::Credential` that only sets itself on a request (header, bearer,
  basic, HMAC signature) or is lent to one closure; it never prints and is zeroed on drop. The
  `Connector` trait, the webhook check, mail, SMS, voice, social, video, reputation, billing gateways,
  push and marketing posting take it sealed, and the helpers that returned a plaintext secret are
  private to the integration crate. Callers name a connection (`connection::Connection::resolve`)
  and authenticate through `apply_auth` without seeing the secret. New REST auth types:
  `api_key_header` (header named by `config.auth_header`), `bearer` and `client_certificate` (a PEM
  certificate and key as the TLS client identity). Push and the adapters now read the live key ring,
  so a rotated `integration.credential_encryption_key` applies without a restart.
- Every outbound HTTP call goes through one guarded client (Q21-T1, `attome_outbound::http`): private
  addresses are refused unless the call's purpose lists the host from configuration (a model server,
  an identity provider, the render sidecar, an Asterisk PBX, an SES endpoint, alert webhooks), cloud
  metadata addresses are refused always, and each redirect hop is checked. Vendor APIs (Twilio, SMS,
  push, Gmail, Microsoft Graph, Meta, Google, ZATCA) reach public addresses only. Server-initiated calls
  no longer use `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY`; a network that needs a proxy sets
  `deployment.outbound_proxy`, used for public hosts only. See `docs/security/outbound-calls.md`; the
  `outbound_client_guard` test fails when code builds an HTTP client another way.
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
  and carry `Cross-Origin-Resource-Policy: same-origin`, except the two that other sites embed (the
  tracking script and the email open pixel), which carry `cross-origin`.

### Added
- Export-to-stream handover (L7-T5): a completed export's status carries `stream_token`, a
  change-stream cursor built from the export statement's own snapshot. Reading a subscription
  from it yields exactly the changes the export did not see: nothing is lost or doubled.
- Erasure and schema events on the change stream (L7-T6): an erasure writes a `purge` change event
  named `record.erased` (entity and id only), and a schema change made by an admin request or a
  changeset apply is a `schema.<op>` event (entity and attribute names) for the entity's
  subscribers. `POST /api/v1/change-stream/{subscription}/erasure-confirmations` records that a
  subscriber erased its copies, as evidence.
- Agent lineage tools (L5-T8): `lineage.downstream`, `lineage.upstream` and `lineage.impact` read
  the lineage graph and the impact engine as the person the agent acts for; an agent proposing a
  schema change is told to call `lineage.impact` first.
- Lineage graph routes (L5-T4): `GET /api/v1/lineage/{kind}/{ref}` walks up or down from an
  entity, attribute or definition, by depth and definition kind, as of a graph version, and flags
  definitions that use personal attributes; nodes the caller may not see are counted, not listed.
  `GET /api/v1/lineage/compare?from=&to=` and `GET /api/v1/lineage/cleanup` (administrators). A
  replaced edge is now kept in `lineage_edge_history`.
- Change-stream subscriptions (L7-T3): an administrator subscribes an S2S client to entities
  (`/api/v1/change-stream/subscriptions`) with operation, changed-attribute and rule-condition
  filters and a payload level (`id`, `changes`, `record`). The client reads its events in commit
  order with its own cursor at `GET /api/v1/change-stream/{subscription}/events`, or as
  server-sent events at `.../sse`, through its service user's record and field permissions
  (sensitive attributes never, personal ones only when allowed). A cursor older than the feed
  keeps answers `410 resync_needed`.
- Governance roles, policies, exceptions and certifications (L3-T2) under
  `/api/v1/admin/governance/`: `domains/{id}/roles` (GET, PUT, DELETE), `policies` (CRUD; every edit
  raises the version, with enforcement links), `policies/{id}/exceptions` (a request goes to the
  domain's owners and stewards for approval) and `certifications` (an entity's definition hash;
  read back as `stale` once it changes). A domain's owner or steward edits without
  `system.admin`; any role holder reads.
- One lineage impact engine (L5-T3): `attome_core::lineage::impact` walks the lineage graph
  downstream of a draft change (up to 10 edges, through metrics to the dashboards that show
  them). Deleting or retyping a field that a dashboard, metric or model definition reads is now
  refused with those definitions listed (`field_in_use`); stored queries and workflows keep their
  field hooks. `GET /api/v1/admin/lineage/impact` previews it.
- Personal data detection in data profiles (L6-T4). A profile checks the sampled values of every
  unlabelled text attribute for Saudi national IDs and Iqamas (with the ID checksum), IBANs
  (mod 97), phones and email addresses. Above 5% it proposes the `personal` label, listed at
  `GET /api/v1/admin/data/label-proposals` with counts only; a builder decides.
- Inbound hook handlers route and upsert (M14-T4). A record handler with a `key` attribute updates
  the record holding the event's value for it (an external id) and creates one only when none
  does. An `events` handler picks a record or flow handler by the event type at a JSON pointer,
  with an optional default; an event of an unrouted type is acknowledged and ignored.
- Quote submission under a discount policy (F2-T1): `POST /api/v1/sales/quotes/{id}/submit`. The
  setting `sales.discount_policy` holds thresholds by product family, role and deal size. A quote
  within all of them is sent; one over a threshold goes to the approval process the strictest
  names and stays a draft, and once that process approves it at no lower discounts, submitting
  sends it.
- Lineage edges captured at publish (L5-T2). `attome_core::lineage` has an `EdgeSource` trait and
  parsers for expressions (the fields a formula, rollup or rule reads), structured query trees
  (select, filter, sort, group), view and form attribute lists, and agent triggers; flows implement
  it in `attome-workflow`. Each edge says whether the definition triggers on, reads, derives from
  or writes its target. A definition that cannot be parsed, such as raw SQL, gets `entity_only`
  edges; attributes are never guessed. Flow publishes and stored queries now write their edges in
  the publish's transaction under a new `lineage_version`.
- Data profile drift, schedules and retention (L6-T5). Each completed profile is compared with the
  entity's previous one: a null share up 10 points or more, a new most-frequent value, or a
  changed top pattern shape. Any drift is stored on the profile (`drift`) and sent once per run to
  the data stewards; system administrators receive it until stewards exist. The new
  `data_profile.schedule` setting profiles entities on a cron in the deployment's time zone; none
  by default. Snapshots older than `data_profile.retention_days` (365) are deleted. Migration 0220.
- Data profile patterns (L6-T3). Each text field also reports its ten most common value shapes
  with their share (digits `9`, Latin `A`, Arabic `ع`), the share matching its declared format
  (`options.pattern`), and Arabic-aware counts: Arabic, Latin or mixed script; Eastern or Western
  digits; values with diacritics; Hijri or Gregorian dates; and name parts (1 to 5 or more) for
  name fields.
- Agent permission test runs (AH7-T2). `attome_ai::permission_test::run` resolves an agent
  definition as a session start does and puts every generated case through the gate, executing
  nothing; entity cases also check the owner's read of the entity. A case fails when the gate
  lets through what must be refused or executes what needs approval. Runs are stored in
  `ai_permission_test_run` (migration 0219).
- Inbound hooks acknowledge fast (M14-T3). A verified call is written to the hook's inbox
  (`inbound_hook_event`, unique by event id) with a processing job, and answered 202 with its
  `event_id`. A duplicate delivery is acknowledged with `duplicate: true` and processed once. With
  the hook's new `ordering_key` (a JSON pointer), events of one key are processed in arrival
  order. A failing event is retried five times, then marked failed and left in the dead-letter
  inbox; a replay from there starts it again. Migration 0218.
- Builder-defined inbound endpoints (M14-T1). Administrators define hooks under
  `/api/v1/admin/inbound-hooks`; each change is audited and the secret is sealed and never
  returned. Providers call the public `POST /api/v1/hooks/{name}`. Authentication is HMAC, with
  GitHub, Stripe and Standard Webhooks presets or a custom header, encoding, prefix and timestamp
  header, or a bearer secret. A hook can also have an IP allow-list and require mTLS at the TLS
  edge. Signed timestamps must fall in a 5-minute window. Each event id is accepted once (Redis,
  or Postgres on Solo), and the check fails closed. A bad signature is 401, a replay 409, and a
  missing required body field 422. The handler creates a record from JSON pointers or starts a
  flow, as the hook's service user. Migration 0217.
- `flow_template.adapt` agent tool (M6-T2). It proposes how a published flow template's parameters
  map to this deployment: an entity per entity parameter (by shared words in names and labels), an
  attribute of it per attribute parameter (numbers and currency preferred for amount-like ones),
  and defaults for text and number parameters. Users are left unresolved. It returns the proposed
  `args`, alternatives, the unresolved parameters, and the instantiate route to confirm with. It
  writes nothing.
- Record passages for retrieval (N15-T2). A second change-feed consumer
  (`attome-search/record-chunks`) runs on the search drain's tick. It chunks long text and
  rich-text fields (400 characters or more), timeline items (notes, communications, activities)
  and documents' extracted text into `record_chunk` (migration 0216), splitting by headings, then
  paragraphs, then sentences, with each field as a heading. Changed chunks lose their vector,
  and the embedding loop refills it. Sensitive fields are never chunked, and a timeline item's
  passages keep both their own record and the record they are attached to.
- Stage bar and stage metrics (M7-T2, M7-T3). `GET /api/v1/stage-processes/for/{entity}` returns an
  entity's published stage process. Record forms of an entity with a `stage` show a stage bar: the
  stages, the current one, its checklist, and a button per allowed next stage that names the
  required fields still empty. `GET /api/v1/stage-processes/{id}/metrics` (administrators) gives,
  per stage, records entered, left and current, mean and p90 time in stage, and drop-off. A new
  record's first stage is now recorded as a move.
- Stage processes (M7-T1): a new `stage_process` metadata kind holds an entity's ordered stages,
  each with required attributes, a checklist and allowed next stages. Publishing the first one
  gives the entity `stage` and `stage_entered_at` (stamped on every change). A new record starts
  in the first stage. A write that moves to a stage the current one does not allow is refused
  (`transition_not_allowed`), and so is a move into a stage with empty required attributes (422,
  one `required_for_stage` failure per attribute). Every move is recorded in `stage_move`
  (migration 0215), with the reason from the optional `Attome-Stage-Reason` header.
- One schedules screen (M12-T3). `GET /api/v1/admin/schedules` lists flow schedule triggers, report
  deliveries and the platform's own schedulers (read-only) with next and last run, owner and
  paused state. `POST /api/v1/admin/schedules/{kind}/{id}/pause|resume` pauses a flow or report
  schedule; both write a Configuration event (migration 0214, `schedule_pause`). The new
  `jobs.quiet_windows` setting holds heavy scheduled work (a flow over a view's records, a report
  delivery) until a window closes. The web app has the screen at `/xrm/jobs/schedules`.
- Fix: `notification.*`, `i18n.*` and `approval.*` settings now have a console area.
- Approve or reject from email (M9-T3). Every minute, the approvers of each pending request step
  (eligible as for My Work) are emailed a one-time link to `/approval-link`, with the token in the
  URL fragment. The token is single-use, per approver and step, stored only as a peppered HMAC,
  and expires in 72 hours or with the request. A request whose action type is in the
  `approval.email_decide_actions` setting (by default approval processes) is decided on that page
  through the public `POST /api/v1/approvals/email-link/decide`. Any other request's link only
  opens the signed-in request page. `POST /api/v1/approvals/email-link` reads the request without
  using the link. A reused link is 409; a wrong or expired one is 401. The `approval.email_links`
  setting turns the emails off. Migration 0213.
- Approval request page (M9-T4): `GET /api/v1/approvals/{id}` returns what is asked, by whom, why
  (the new optional `reason` on `POST /api/v1/approval-processes/{id}/submit`), the attribute
  changes as from → to, every decision, and whether the caller may decide. It is visible to an
  administrator, the requester, anyone who decided it, an eligible approver, and anyone who may
  read the record. `GET /api/v1/approvals/regarding/{entity}/{record_id}` lists a record's
  requests. The web app has the page at `/approvals/requests/:id` and an Approvals tab on every
  record form.
- Approval on change (M9-T2): an approval process may start on `change` with `watched_attributes`.
  An update that changes a watched attribute, on a record meeting the entry condition (judged on
  the record as the update leaves it, e.g. `discount > 20`), keeps the stored value, writes the
  rest, and opens an `approval_process.change` request; the response carries `approval_request_id`
  and `held_attributes`. Approval writes the held values as the requester; rejection leaves the
  record unchanged; a second change while one is pending is refused (409). Migration 0212.
- Crawl one intranet host per source (K6-T8): a website source's `allow_host` (exact host name,
  audited when set) may resolve to a private address through the same guarded resolver; a
  metadata address and every other private host stay refused, and each redirect hop is checked
  again. `credential_ref` names an integration connection whose stored credential (basic, header,
  bearer or OAuth) signs the crawl's requests to the source's own host only; credentials never
  follow a redirect off it and are never logged.
- Data profiles in one sampled scan (L6-T2): `POST /api/v1/admin/data/profile` reads every attribute
  in one query, sampling a table of more than 100,000 rows (`TABLESAMPLE SYSTEM`, about 100,000
  rows) unless `full_scan` is set, under a 120 s statement timeout. Each field now reports nulls,
  blanks, distinct count (exact up to 100,000), top values, and by type: number min, max, mean,
  median, percentiles, a ten-bucket histogram and outliers; date range; text length spread. The
  profile states `sample_size` and `full_scan` (migration 0211). Personal and masked fields keep
  only value shapes, as before.
- Approval processes (M9-T1): administrators define processes
  (`/api/v1/admin/approval-processes`: entity, optional entry condition in rule text, the approval
  plan, `lock_record`, `editable_attributes`). A person who may update a record submits it
  (`POST /api/v1/approval-processes/{id}/submit {record_id}`): the record must meet the entry
  condition and have no other pending request of the process; the request is an ordinary approval
  request decided through the usual routes. While it is pending, a locking process refuses every
  update of the record except its editable attributes (403 `attribute_not_writable`). The requester
  recalls it while undecided (`POST /api/v1/approval-processes/requests/{request_id}/recall`).
  Migration 0210.
- Flow template gallery (M6-T4) at `/xrm/workflow/templates`: search the published `flow_template`
  objects, fill in a template's parameters and create a draft flow from it (opened in the editor),
  or save an existing flow's newest version as a template. New
  `POST /api/v1/admin/model/flow_template/{id}/instantiate {args}` answers the filled graph or the
  arguments' issues and writes nothing. English and Arabic.
- Replay a flow version over recent runs (M4-T3):
  `POST /api/v1/workflow/definitions/{id}/versions/{version_id}/replay {last}` (1–50, default 10)
  runs each of the flow's latest finished runs' trigger input and approval decisions through the
  simulation of that version and lists, per run, every node whose outcome differs from what really
  happened. Nothing is written.
- Webhook subscriptions screen (M13-T4) at `/xrm/webhooks`: create (the signing secret shown once,
  also in Standard Webhooks form) and edit subscriptions (target, payload shape, ordered, on/off),
  see a paused subscription's reason, read the delivery log, send a test event
  (`POST /api/v1/admin/events/subscriptions/{id}/test`) and send everything again from a time
  (`POST /api/v1/admin/events/subscriptions/{id}/replay`, at most 10,000 deliveries, each keeping its
  event id). English and Arabic.
- Ordered webhooks and auto-pause (M13-T3): a subscription with `ordered: true` sends one record's
  events one at a time, in the order they happened (a delivery waits while an earlier one of the
  same record is still pending or retrying). When fewer than half of a subscription's last 100
  attempted deliveries succeeded, it is turned off (`paused_at`, `paused_reason`), the change is
  audited and its owner is notified in-app and by email; turning it back on clears the pause.
  Metric `events_subscriptions_auto_paused_total`. Migration 0209.
- Standard Webhooks signatures and target auth headers (M13-T2): every webhook delivery also carries
  `webhook-id` (the event id), `webhook-timestamp` and `webhook-signature` (`v1,` + base64
  HMAC-SHA256 of `id.timestamp.body`), so a receiver can verify with any Standard Webhooks library;
  creating a subscription or rotating its secret returns the secret in that form too
  (`webhook_secret_standard`, `whsec_…`). A subscription may name `target_auth_header` and
  `target_auth_value` (write-only, encrypted, bound to its row; migration 0208) to send on every
  delivery. `X-Attome-Signature` stays as before.
- Notification delivery settings on the Notifications page (M15-T3): beside the grid of kinds by
  channels, a person chooses how low-priority notifications arrive (each on its own, hourly or daily
  summary) and their quiet hours. English and Arabic.
- One notify API with digests and quiet hours (M15-T1, M15-T2):
  `attome_notification::notify::notify(state, Notify {recipient, kind, data, priority, route})` sends
  the template `kind` with `data` as its variables through the dispatch engine (mutes and channel
  outcomes as before). Personal settings `notification.quiet_hours` (`{"start": "22:00", "end":
  "07:00"}` in the person's own time zone): low and normal priority notifications sent then wait
  until they end; and `notification.digest` (`off`, `hourly`, `daily` at 08:00): low-priority ones
  are collected into one in-app and email message. Held notifications live in
  `notification_queue_item` (migration 0207) until the five-minute `notification_queue_sweep` sends
  them. A high or urgent push without email falls back to email when unread after 5 minutes.
- Scheduled flows over records (M12-T1): a schedule trigger with `for_each_record_of: "<view id>"`
  starts, per slot, a batch job (`workflow_record_schedule`) that pages the view 100 ids at a time
  (read as the flow's publisher) and starts one run per record, with the record as the run's
  correlated record. A replayed chunk starts nothing twice. `overlap: "skip"` (default) skips a slot
  while the previous slot's batch still runs; `"queue"` starts it anyway. Missed slots still run once.
- Business-time waits and event-wait timeouts (M10-T3): `wait` and `wait_for_event` nodes take
  `business_time` (count only the working hours of `calendar_id`, else the deployment's default
  calendar, skipping its holidays) and `relative_to` (count from a date field of the wired record
  instead of now). `wait_for_event` takes `timeout_seconds` and gains a `timeout` port: when the time
  passes before the event, the sweep resumes it with `{"timed_out": true}` and the run goes down
  `timeout` instead of `event`.
- Flow simulation reads real data (M4-T1): `POST /api/v1/workflow/definitions/{id}/versions/{version_id}/simulate`
  takes `read_record: {entity, id}`, read as the person simulating (record access and field grants
  apply) and handed to the trigger as `{entity, record_id, record}`. Each update step's trace now
  shows `values` (what it would write), `record_id` and `before` (the record's current values of
  those fields, or `before_error` when the record cannot be read). Nothing is written.
- Flow loops, error branches and run limits (M1-T4): node type `for_each` runs the flow named by
  `definition_logicalname` once per batch of its `items` (`batch_size` 1–100, default 100), each
  batch with `{items, batch_index, batch_count}` as input, and waits for every batch run; its output
  counts the runs that completed, failed or were cancelled. Every node except a trigger may wire an
  `on_error` port: a node that fails for good takes it with `{error_kind, message, node_id}` instead
  of failing the run, and a node that succeeds skips what only that port feeds. New runtime limits
  `limits.workflow.max_steps_per_run` (1,000), `max_loop_items` (10,000), `max_nesting` (20, which
  replaces the fixed sub-flow depth) and `max_run_minutes` (30 days); a run past one fails with the
  reason in `node_data.limit_exceeded`.
- Dead-letter alerts and retention (M5-T4): an hourly `dead_letter_sweep` job discards items that
  first failed more than `jobs.dead_letter_retention_days` ago (through their source, as the system
  user, with the reason on the audit event), and counts groups that are new or gained ten or more
  items since the last sweep (`dead_letter_groups_new_total`, `dead_letter_groups_growing_total`;
  gauges `dead_letter_items`, `dead_letter_oldest_age_seconds`). Built-in alerts
  `DeadLetterGroupNew`, `DeadLetterGroupGrowing` and `DeadLetterOldItem`, each with a runbook.
  Migration 0206 (`dead_letter_group_watch`).
- Dead-letter inbox screen (M5-T3) at `/xrm/jobs/dead-letters`: groups with their count, last
  failure, a sample message and a "new today" / "still failing" marker; replay a group at a chosen
  number of items a minute; open a group to replay one item or discard it with a reason. English
  and Arabic.
- Dead-letter inbox (M5-T2): `GET /api/v1/admin/dead-letters/groups` (dead letters of every source
  grouped by cause, largest first), `GET /api/v1/admin/dead-letters?source=&group=`,
  `POST /api/v1/admin/dead-letters/{source}/{id}/replay`, `POST .../{source}/{id}/discard` (a reason
  is required and kept on the audit event) and `POST /api/v1/admin/dead-letters/groups/replay`,
  which replays the group's oldest item at once as a preview and, when it goes through, queues the
  rest as a batch job (`dead_letter_group_replay`) at `rate_per_minute` (default 60, at most 600).
  Its progress and cancel are `GET /api/v1/jobs/{id}` and `POST /api/v1/jobs/{id}/cancel`.
- One dead-letter shape for every source (M5-T1): `attome_core::dead_letter::DeadLetterSource`
  (list, count, get, replay, discard with a reason) over `DeadLetter {source, id, step, error_kind,
  cause_group, message, first_seen, attempts, payload_ref}`, implemented for background jobs (fast
  and batch queues, `attome-api`), flow triggers and failed flow runs (`attome-workflow`) and webhook
  deliveries (`attome-events`). `cause_group` is source + step + a coarse error kind (`timeout`,
  `connect`, `http_5xx`, …), so items that failed the same way group together. A discarded flow run
  is cancelled; a discarded webhook delivery is deleted; each replay and discard is audited.
- Webhook subscriptions choose their body (M13-T1): `payload_shape` on
  `/api/v1/admin/events/subscriptions` is `id` (entity, record, operation, event name), `changes`
  (plus `changes`: each changed attribute the owner may read with its `old` and `new` value, copied
  from the outbox row when the event is matched) or `full` (the default and the old behaviour: plus
  the record as the owner may read it now). Every body now also carries `event_name` and
  `changed_attributes`, so a subscription to a business event (`filter_event_names`) sees which one
  fired. Migration 0204.
- Change events say where a change came from (L7-T2): `entity_change_event` gains `channel`
  (`flow` for a workflow pass, `job` for a bulk job, NULL for an ordinary request) and `flow_run_id` (migration 0203). Every write a
  workflow pass makes carries `channel = 'flow'` and the instance id, so a subscriber can skip a
  flow's echo of its own update.
- Model fallback (Z9-T4): `attome_inference::fallback::call_with_fallback` runs a routed AI call on
  the best catalogue model and moves to the next one the data rules allow when a model fails, times
  out, is busy or has its breaker open (one `ai_route` breaker per model id). A refused request is
  returned at once. The answer names the model that gave it and every model passed over, and why.
- A weekly file integrity sample (Z6-T3): one stored file in a hundred (at most 1,000) is read back
  and its size and SHA-256 compared with what was recorded at upload; a changed or missing file is
  logged by version id and key, counted in `file_integrity_failures_total{kind}` and raises the
  built-in `FileIntegrityFailures` alert (runbook included). Nothing is changed automatically.
- A queue per self-hosted model (Z9-T6): `inference.catalogue[].max_concurrent` (default 4) calls
  run at once on a self-hosted model; a chat call waits up to 10 s for a slot and then is passed
  over as busy (a retryable error), a batch call waits as long as needed and batch calls never hold
  the last slot.
- Allocation budgets for the key requests (AA14-T4, `tests/request_allocs.rs`): bytes allocated and
  peak live bytes per request, measured on the request's own task, against
  `tests/request_allocs.json`; more than 20% above a baseline fails.
- Admin > Dependencies (AB6-T9): each gated capability's state and each outbound service's breaker
  (red when open), error rate and retries over the last hour, in English and Arabic; the webhook
  row links to the dead letters. `GET /health/dependencies` gains an `outbound` array.
- `POST /api/v1/query/changes` (AA7-T4): the records of one entity added, changed or removed since
  a signed cursor, as the caller may read them now. A record the caller can no longer read is
  listed in `removed` by id only.
- Outbound metrics and breaker state (AB6-T8): `outbound_calls_total{service,outcome}`,
  `outbound_latency_seconds{service}`, `outbound_retries_total{service}` and
  `outbound_breaker_state{service}` (0 closed, 1 half open, 2 open). While the `ai_model`,
  `object_storage` or `smtp` breaker is open, the capability probe counts that capability as failed;
  each open and close writes a `dependency_breaker_changed` audit event attributed to the system.
- A census test fails when a crate builds its own HTTP client outside `attome_outbound::http`
  (AB6-T11, `tests/outbound_single_layer.rs`).
- Background jobs that run in chunks slow down while the node is busy (AA10-T6): every five seconds
  the server reads the p95 latency of the requests it served since the last look and the read
  replica's lag, and the batch runner waits 0 ms, 200 ms or 1 s before each chunk (p95 under
  100 ms and lag under 5 s; up to 300 ms and 30 s; above). Gauge `background_chunk_delay_ms`.
- OAuth 2.0 for integration systems (Z1-T11): `auth_type` `oauth2_client_credentials` (credential
  `{"client_id", "client_secret"}`) and `oauth2_refresh_token` (plus a first `refresh_token`), with
  the provider's `token_url` and optional `scope` in the system's config. Tokens are stored
  encrypted in `integration_oauth_token` (migration 0202), used while they have more than a minute
  left, and renewed every five minutes when under ten minutes remain; a failed renewal records a
  masked reason, counts `integration_oauth_refresh_failures_total` and logs
  `integration.oauth.refresh_failed`.
- Bulk reassign and bulk share (Q14-T5): `POST /api/v1/admin/security/record-shares/bulk` reassigns
  records to a user or team, or shares them, selected by id (up to 10,000) or by current owner.
  `preview: true` answers the count and the first 50 records; otherwise it starts a background
  batch (progress at `GET /api/v1/jobs/{id}`, cancel at `POST /api/v1/jobs/{id}/cancel`) that works
  500 records at a time, each chunk with one security event naming its records.
- `POST /api/v1/query/execute` answers in MessagePack when the request sends
  `Accept: application/msgpack` (AA7-T7): the same page, with each row an array in the order
  `data.fields` names, so attribute names travel once. JSON stays the default; responses carry
  `Vary: Accept`.
- `docs/metadata-versions.md` (Y8-T13): how a metadata publish reaches every node (the Postgres
  doorbell, the `cache.metadata_poll_interval_secs` safety-net poll, the `registry` readiness flag),
  the `Attome-Metadata-Version` header the web app reloads on, builder pins, and rollback.
- Model catalogue and routing (Z9-T3): `inference.catalogue` lists models with their capabilities,
  context size, price, whether they are self-hosted and the data labels they may receive; the
  router picks the cheapest model that fits a task and may see its content, keeps `secret` content
  on self-hosted models and refuses rather than breaking a rule. Empty by default, which changes
  nothing. `docs/model-servers.md` has the settings.
- File storage backends (Z6-T1): `storage.backend` is `s3` (the default, unchanged), `local` (a
  folder on this machine), `azure` (Azure Blob Storage) or `gcs` (Google Cloud Storage), all through
  the same client. On local disk, upload and download links point at the server's own signed
  `GET/PUT /api/v1/storage/local` route instead of a bucket. The `s3_*` settings are now optional
  when another backend is chosen. `docs/storage.md` has the settings.
- A record read with a matching `If-None-Match` answers `304` from a cached row version instead of a
  database probe (AA7-T8); a write drops the cached version on every node.
- `GET /api/v1/schema/{logicalname}` answers from in-memory metadata and sends an `ETag`; a request
  with a matching `If-None-Match` gets `304 Not Modified` with no body (AA7-T2).
- Users share their own records without admin rights (Q14-T1): `GET/POST /api/v1/{entity}/{id}/shares`
  and `DELETE .../shares/{share_id}`, with the new per-entity `{entity}.share` privilege. A view share
  needs read access to the record and an action share update access, so nobody gives more than they
  hold; every change is a security event.
- Job kinds can cap how many of their jobs run at once across all workers (Z7-T3, migration 0191);
  validation clean-up scans run at most two at a time.
- A flow run replayed after a crash no longer repeats an action step (S9-T5): each module step claims
  its run-and-step key in the idempotency ledger and a replay returns the step's stored result. Jobs and
  flow steps carry that key to outbound calls, and the REST connector sends it as `Idempotency-Key` to
  a system whose configuration sets `"supports_idempotency": true`.
- Rejections and validity per entity (A3-T8): every write a check refuses is logged, in batches
  off the request path, with its rule, field, channel and user (migration 0183); a nightly sweep scores
  each entity by the share of its stored records passing every active check.
  `GET /api/v1/admin/validation/stats` returns both.
- Simulate a check before publishing it (A3-T5): `POST /api/v1/admin/business-rules/{id}/simulate`
  runs the rule over the entity's stored records (up to 10,000) and returns how many it would refuse
  and the first 50 of them. Publishing a rule now queues a full scan that fills its clean-up queue,
  `GET /api/v1/admin/business-rules/{id}/cleanup`: each refused record with its message and owner
  (migration 0182).
- Metric lineage and impact (P10-T1): the lineage graph can point at metrics, not only entities
  (migration 0181). A metric records what it reads (its stored query's entities and the metrics its
  formula uses) and a dashboard widget the metrics it shows, kept current by the catalog lineage
  sweep and backfilled for existing metrics and widgets. `GET /api/v1/metrics/{id}/impact` lists a
  metric's inputs and consumers with counts per kind, a preview of what changing it reaches.
- Master-data settings on entities (L1-T1): `PATCH /api/v1/admin/entities/{id}` takes
  `master_data: {is_master, hub_style}` (hub style `registry`, `consolidation` or `coexistence`) and
  `GET` returns it. A master entity needs a data domain (422 naming `is_master`). The settings are
  stored on `entity_info` (migration 0180) and travel in changesets as the new
  `set_entity_master_data` operation.
- Settings from the command line and for agents (U10-T2): `attome settings list|get <key>|set <key>
  <json> --url <server>` reads and changes settings with the administrator API key in `ATTOME_API_KEY`;
  the agent tools `settings.list` and `settings.set` do the same for administrators, a change waiting
  for a person's approval and written through the settings API itself. A build test fails when a
  registered setting is missing from the console, the API, the CLI or the agent tool.
- Report schedules on the job scheduler (M12-T2): job schedules gain a recurrence-rule kind (an
  RFC 5545 RRULE without `COUNT`, counted from a start time), and each report schedule is now one
  entry of the job schedule ledger (`report-schedule:{id}`), counted from the schedule's creation, so an
  occurrence runs once across all workers and restarts. A rule such as `FREQ=WEEKLY` no longer drifts
  to the time of the last run. The report sweep's own claim is gone.
- Timers that follow a date (M10-T2): a timer whose payload carries `follow` (an attribute, an offset
  in minutes and an optional rule condition) moves when the record's date changes and is cancelled
  when the record is deleted, clears the date or leaves the condition. The `attome-workflow/timer-follow`
  change-feed consumer applies it at the start of every timer sweep.
- Assignment simulation (M11-T2): `attome_workflow::assign::simulate_assignments` replays past records
  with any assignment strategy and reports how they would have been spread, against who got them.
- Component manifests (T3-T3): a `component` metadata kind holds a custom element's tag, its module
  inside a published package, typed properties set by the builder or bound by the host, and its events.
- Record templates (B8-T1): a `record_template` kind holds fixed, expression or prompted values, child
  templates and a condition. Saving and publishing now check a value against its attribute's field type.
- Pages (T2-T1): a `page` kind holds a component tree with view, query or record bindings and events that
  start a flow, run an action or navigate inside the app.
- MFA done at the identity provider counts (Q2-T2): an `oidc.providers` entry gains `mfa_acr_values`
  (the `amr` entries or `acr` value that mean MFA, as the provider presets list them) and
  `trust_idp_mfa` (default `true`). When a verified ID token carries one of the values, the session
  records `mfa` after `fed` in its `amr`, so a policy that requires MFA can accept it without
  Attome's own factor. A provider with no values configured, or `trust_idp_mfa: false`, never counts.
- Flow templates (M6-T1): a `flow_template` metadata kind holds a workflow graph with typed
  parameters (`entity`, `attribute` of an entity parameter, `user`, `users`, `text`, `number`) written
  as `{{name}}` placeholders; `attome_model::kinds::flow_template::instantiate` checks the arguments
  and returns the graph to save as a new flow's draft.
- Recorded model answers for tests (Z9-T7): `FakeModelServer::recorded` answers by the hash of a
  request's messages from a fixture file (`Recordings::load`), tool calls and streamed chunks
  included; an unrecorded request gets a 404 naming its hash. With `ATTOME_TEST_NO_NETWORK=1`, every
  inference call to a host other than loopback is refused, so no test reaches a real model.
- Metadata switch timing (Y8-T10): each node records `metadata_switch_seconds`, the time from a
  metadata version becoming current (a publish, switch or rollback) to the node serving it, on the
  database clock. `GET /api/v1/admin/metadata/versions/{version}/nodes` lists which nodes serve a
  version and when they switched; the `MetadataSwitchSlow` alert fires when the p95 stays above 30 s
  for 10 minutes.
- Publish crash points (Y8-T11): a node that cannot load the current metadata version now reports not
  ready on `/health/ready` until a retry loads it, proven with three publish crash tests in
  `metadata_chaos`.
- Server-rendered pages and sites (E12-T1, E12-T2, E13-T6): publishing a page renders its HTML
  once (Open Graph and X cards, hreflang for its translations, JSON-LD for articles), served by
  `GET /api/v1/content/html` (ETag, 304) and, by host, `GET /api/v1/content/site`; a content space
  can be a site with a domain, theme (`GET /api/v1/content/theme.css`), menu and blog
  (`GET /api/v1/content/rss`), set through `PATCH /api/v1/admin/content/spaces/{id}`.
- Contract comparison (W1-T7): `POST /api/v1/contract/contracts/{id}/compare` queues a word-level,
  section-by-section diff of two versions and flags clauses unlike the library's standard and
  fallbacks; the result is stored on the `contract_comparison` record.
- Org chart drafts (D23-T10): `POST /api/v1/sales/accounts/{id}/org-chart/propose` and
  `POST /api/v1/sales/orgchart-drafts/{id}/decide`, and the agent tools `sales.orgchart.read`,
  `sales.committee.read`, `sales.coverage.gaps`, `sales.orgchart.propose`.
- Journeys (E8-T5, E8-T8): entry sources (list joins, events, dates including Hijri, list at a
  time) start live journeys; publishing a journey version can move waiting people to it.
- Metric members (P9-T5): a query metric with dimensions stores a snapshot per member beside the
  total; `GET /api/v1/metrics/{id}/snapshots?dimension_attribute=` lists them.

- Power dialer documented (D21-T14, `docs/dialer.md`): the call list routes
  `POST /api/v1/sales/call-lists/{id}/build`, `/claim`, `/dial` and `/voicemail`, and
  `POST /api/v1/sales/call-list-members/{id}/outcome` and `/skip`; what is off until set up, and that
  no calling hours ship (a country without a `calling_hours` row cannot be called). The per-person
  calling metrics now count each call for the person who made it (sales pack changeset 0022).
- Deal committee and org chart export (D23-T7, D23-T9): `GET /api/v1/sales/opportunities/{id}/committee-map`
  answers a deal's contacts with their roles (influence and attitude only through the Deal Attitude
  profile), influence links, the stage's required roles and the coverage gaps;
  `POST /api/v1/sales/accounts/{id}/org-chart/export` queues a PDF of the account's people (202, the
  docgen render id).
- Email deliverability (E6-T10, E6-T13): `POST /api/v1/marketing/precheck` scores a message before it
  is sent; `GET /api/v1/marketing/deliverability/overview` gives the dashboard's figures; the daily
  alerts notify the marketing owner role and administrators. Marketing > Deliverability shows the
  dashboard.
- Page redirects and Arabic paths (E13-T5): changing a page's `url_path` keeps the old path working —
  `GET /api/v1/content/view`, `/content/delivery` and `/content/internal` answer an old path with 301 and a
  `Location` naming the page's current path (percent-encoded), only for a published page the caller's
  audience may read. With `content.seo_arabic_paths` on, an Arabic page or translation may use Arabic
  letters in its path.
- Tracking collection (E14-T5, E14-T6): `POST /api/v1/track/collect` takes the script's batches
  (`text/plain` JSON, at most 50 events and 32 KB), rate-limits per visitor and per truncated
  address, drops unknown or disabled sites and foreign origins with the same 204, and answers 202
  after queuing one `marketing_web_event_batch` job; it writes no event on the request path and never
  queues a full IP (IPv4 /24, IPv6 /48) or the user agent (only its class). The job drops crawlers,
  staff sessions and office networks, writes each event once (re-running a batch changes nothing) and
  keeps a session's first landing page, UTM values and click ids.
- Website tracking script (E14-T4): `GET /api/v1/track/script.js?site=` serves the script (under 10 KB
  gzipped, cached a day) for an enabled tracked site when `marketing.tracking` is on. It sends nothing
  before analytics consent, stays anonymous under Global Privacy Control, uses only first-party
  cookies (`atm_vid`, `atm_sid`), batches page views (with UTM and click ids) and, when custom events
  are on, `window.attome.track` events to the deployment, and never fingerprints.
- Page search settings and structured data (E13-T4): `attome_content::seo` reads and writes a page's
  title, description, canonical, robots flags and Open Graph card at its row version (409 on a stale
  one), fills empty ones from the page (title, first paragraph, base URL plus path), and builds and
  checks schema.org JSON-LD for organizations, breadcrumbs, articles, FAQs, events, products, job
  postings and local businesses.
- Dynamic email blocks (E25-T1): an email design's `dynamic` block holds variants (a rule condition over
  the recipient and/or a list they must be in) and a default; `attome_marketing::dynamic_blocks::resolve`
  picks the first match per recipient and reports the choice, the renderer refuses an unresolved block,
  and `POST /api/v1/marketing/emails/preview` shows a design as one contact or lead.
- Live segments (E7-T6): a segment list with `refresh_mode = live` is re-checked every five seconds for
  only the people a change-feed batch touched (the record, or the target records whose lookup points
  at it), as its owner, with one membership event per change (reason `live`). Its query may read only
  its target, consent and entities one lookup away (from the published version's relations); others
  stay on the scheduled refresh.
- Journey storage (E8-T3): `workflow_definition.kind` (`flow`, `journey`, `nurture`; existing ones are
  flows) and the journey enrolment, node-count, message-log and block tables (migration 0168); the
  marketing pack's `marketing_journey` settings entity (pack changeset 0007), whose status only the
  journey engine moves.
- Workflow step seam (E8-T1): engines register workflow step handlers and kind guards on the
  `EngineSystem` builder (`attome_core::workflow_step`).
- Profile events (E23-T1): `profile_event` (migration 0167), monthly partitions kept ahead by the
  partition job, indexed by contact and by anonymous id; the daily `profile_event_retention` job drops
  months older than `marketing.profile_event_retention_months` (default 13).
- Marketing forms (E10-T1): the marketing pack's `marketing_form` (target lead or contact, field map,
  consent purposes, UTM capture, publishing) and `marketing_form_submission` (pack changeset 0006);
  the public `POST /api/v1/marketing/forms/{id}/submit` maps the fields, finds the person by email or
  creates them, records each ticked consent in the ledger with the form as proof, and keeps the UTM
  tags — filed as `marketing.form_intake.user` (empty: no submissions), rate-limited, with the
  deployment's challenge.
- Deliverability agent tools (E6-T12): `deliverability.explain` and `deliverability.propose_segment`,
  read-only, marketing module, `marketing_deliverability_policy.read`.
- Static list operations (E7-T5): `POST /api/v1/marketing/lists/{id}/members` and `/members/remove`
  (at most 1,000 readable people, membership events and audit), `POST /api/v1/marketing/lists/{id}/imports`
  (a CSV document of emails or ids, run by the `marketing_list_import` job with its progress at
  `GET .../imports/{import_id}`) and `POST .../imports/{import_id}/undo` (removes exactly that import's
  members within seven days). Segment lists refuse all of them. Migration 0166.
- Deliverability routes (E6-T11): `GET /api/v1/marketing/deliverability/daily` (paged rollup),
  `GET /api/v1/marketing/deliverability/sends/{send_id}`, `GET /api/v1/marketing/deliverability/dmarc`
  and `POST /api/v1/marketing/deliverability/dmarc/upload` (administrators; the report file as the
  body, 20 MB), and `POST /api/v1/marketing/address-check` (60 a minute per person).
- Deliverability rollup (E6-T4): the hourly `deliverability_rollup` job recomputes today's and
  yesterday's `marketing_deliverability_daily` (migration 0165) — sent, delivered, bounced, opened,
  clicked and complaints per sending domain, mailbox provider and campaign — from email
  `communication_event` rows and complaint suppressions, replacing the day's rows in one transaction.
- DMARC reports (E6-T7): `attome_marketing::dmarc` parses aggregate reports from XML, `.gz` or `.zip`
  (20 MB cap, no document type declarations), stores each reporter's report once
  (`marketing_dmarc_report`/`marketing_dmarc_record`, migration 0164) and summarises SPF and DKIM per
  sending source, naming the sources that fail both. Reading reports from a mailbox waits for
  attachment fetching in the mail readers.
- SMS campaigns (E16-T1): `POST /api/v1/marketing/lists/{id}/sms/estimate` answers who can be texted
  (a phone and SMS consent for the purpose), the encoding, segments and cost
  (`marketing.sms_price_per_segment`); `POST /api/v1/marketing/lists/{id}/sms/send` fixes the
  recipients (refusing an estimate grown past `expected_cost`) and the `sms_campaign` job sends them
  in batches, holding each until `marketing.sms_quiet_hours` end in the recipient's country, and
  re-checking consent before each message. Migration 0163.
- Marketing calendar (E29-T1): `/xrm/marketing/calendar` shows a month of campaign starts and ends and
  marketing events, and each running campaign's budget against actual (its own budget, finance
  budget lines naming it in `campaign_code` as planned, and their actuals).
- Note replies are records (C1-T1): a reply is a `note_reply` on the note's parent record (read only
  by someone who can read that record), with its own files, so replying no longer rewrites the note
  and two people replying at once both land. At boot, replies still held in a note's `replies` JSON
  move to `note_reply` records (text, author, time and attachments kept; a list that is not JSON
  stays on the note). `note.replies` is no longer written and goes in a later release.
- Case summaries (G1-T3): two minutes after a case's thread goes quiet, the `case_summary` job runs
  `record.summarize` for the case as its assignee (through the AI gate, read ceiling, the assignee's
  own grants and budget), so the workspace's new Summary panel opens on a ready summary.
- Shared mailboxes (J2-T2): every two minutes the `inbound_mail` job reads each active
  `kind = "mailbox"` integration system and routes each message once: onto the case it threads to,
  else by the mailbox's `config.routing` (`create`: `case`, `lead` or `none`; `unknown_sender`:
  `create` or `ignore`), as the system's service principal. Automatic, bulk and our own mail is
  skipped and each sender is limited to 20 routed messages an hour. Migration 0162 adds
  `inbound_mail_state` and `inbound_mail_message` (where each message went, or why not).
- Service desk presence (G5-T3): each person sets `service.presence` (available, busy, away) from the
  workspace header; round-robin and least-loaded queues route new work only to available members.
  `POST /api/v1/service/viewing` records that the caller has a record open (a two-minute Redis
  heartbeat) and answers who else is viewing it; the workspace shows them on each case.
- Case email threading (G1-T2): `attome_service::email_threading` joins an inbound email to its case by
  the `[Case #N]` subject token (merged numbers included), its reply headers, or its sender's open case
  updated within `service.email_thread_days` days (default 7).
- Email address checks (E6-T6): contacts and leads refuse an email address with a syntax error;
  internationalised addresses are accepted.
- Subscriptions (F3-T5, F3-T6): `/api/v1/billing/subscriptions` creates a subscription by hand or from
  an accepted quote, reads it as of a date (`?as_of=`), amends it from a date (closing and opening
  dated segments, with a planned proration charge or credit for the rest of the period), reverses an
  amendment nothing has invoiced, cancels (at term end or on a date; `subscription.cancel`), pauses
  and resumes. A new price needs `subscription.amend_price`. Each change holds a per-subscription
  lock (409 for a second one at the same time) and emits `billing.subscription.*` change events.
- Reporting lines (D23-T4): a contact's `reports_to` and `dotted_line_ref` change only through
  `PUT /api/v1/sales/contacts/{id}/manager` (If-Match), which keeps the manager in the contact's
  account or group and refuses loops; the answer names the previous manager for undo.
- Plays (D26-T2): `GET /api/v1/sales/opportunities/{id}/plays` lists the playbooks whose condition
  holds for the deal, and the opportunity form shows them.
- Dialer (D21-T7): `POST /api/v1/sales/call-list-members/{id}/skip` passes over a claimed member.
- Contract drafting (W1-T6): `POST /api/v1/contract/contracts/{id}/draft` adds the contract's next
  version and queues a render of its type's draft template (`contract_type.draft_template_ref`, a
  document template) as the caller, in the contract's `language`, with the clauses chosen for it
  (`contract_clause`); the document is attached to the new version. A document render may now name
  the record its document is attached to (migration 0160).
- Contracts from the business (W1-T13): an accepted quote or a confirmed order drafts one sales
  contract, and each contract type gets an intake offering whose requests draft a contract of that
  type (`ContractLinkSweep`, every quarter hour; `contract.source_kind` and `source_id`).
- Contract security (W1-T14): Contract Manager, Legal, Contract Requester and Contract Viewer roles;
  confidential contracts are read by Legal only; contract value, terms and clause text sit behind
  the Contract terms field profile; a review retention rule starts at each contract's end date.
- Browser push and sharing into Attome (B19-T2): a person turns on browser notifications from the
  notification panel; a push opens its record when tapped, and the installed app's icon shows the
  unread count. Files shared from another app on the device land on `/xrm/share` and are saved as
  documents in the Shared folder of the person's own record. A push to a browser is now sent in the
  shape the app's service worker shows.
- My timesheet (V3-T1, `/xrm/project/timesheet/week`): the person's week as a grid of work items by
  day, with days on approved leave marked and closed, totals, and Submit for approval.
- Admin console (U10-T3, `/xrm/admin/console`): settings and admin screens by area, one search over
  both (setting descriptions in English and Arabic), and each setting's change history.
  `GET /api/v1/admin/settings` items gain `id`, the stored row a value comes from (`null` while the
  default applies), whose audit trail is the setting's history.
- Identity provider presets (Q2-T1, `attome_auth::oidc_presets`): Entra ID, Okta, AD FS and Keycloak
  reached through an OpenID Connect broker, each with its issuer URL shape, email and groups claims,
  the claim values that mean MFA was done, and whether a forced sign-in reaches the provider.
- Metadata versions (Y8-T4): every publish records the deployment's next metadata version (its cooked
  manifest kept as an artefact), and `POST /api/v1/admin/metadata/versions/{version}/switch` and
  `POST /api/v1/admin/metadata/rollback` move the current version without cooking anything. Every node
  follows the move on its next metadata catch-up and records it in `metadata_node_switch`.
- Save conflicts on the record form (A16-T3): a save that someone else's change overtook opens a dialog
  listing each attribute they changed, with your value and theirs, to keep or take per attribute;
  nothing typed is lost. The form now sends only the attributes it changed, with
  `If-Match-Merge: attributes`, so a save merges over other people's changes to other attributes and
  says which. `If-Match-Merge` is allowed through CORS and ignored on server-to-server requests.
- Cache numbers and purge (Z3-T9): `GET /api/v1/admin/caches` lists each declared cache on this node
  with entries, hits, misses, evictions and hit rate; `POST /api/v1/admin/caches/{name}/purge` drops one
  key or everything on every node (audited). Metrics `cache_requests_total`, `cache_evictions_total`
  and `cache_entries`.
- Admin > Caches (Z3-T10, `/xrm/admin/caches`): each cache's entries, hit rate and evictions on the
  server that answered, and a purge of one key or the whole cache after a confirmation, in English
  and Arabic. No cached value is shown.
- Record types on the New button (A27-T4): `GET /api/v1/{entity}/record-types` lists the types the
  caller may create, their default first; with several, the New button offers each, and the form opens
  with the chosen type.
- Option set merge (A5-T2): `POST /api/v1/admin/model/option_set/{id}/merge` retires one value,
  publishes the set and moves every record holding it to another value in a background job, through
  the ordinary update path (audited, in each record's history).
- Secret inventory and configuration history screens (Z1-T14), in English and Arabic, at
  `/xrm/admin/secrets` and `/xrm/admin/config-starts`, with their sidebar entries.
- My background work (M12-T4): `GET /api/v1/jobs` lists the batch jobs a person started, newest
  first, and the profile menu opens a page showing their progress with Cancel for a running one.
- Pending timers (M10-T4): `GET /api/v1/{entity}/{id}/timers` lists what is waiting to happen to a
  record and when (shown on the record form), and `GET /api/v1/admin/timers` every pending timer for
  administrators (`/xrm/admin/timers`).
- Installable app (B19-T1): a web manifest and a service worker cache the app shell and the
  hash-named render plans; a new version downloads in the background and a notice offers to reload.
- Every failing field under its field (A3-T7, part): when a save is refused with several field
  failures at once, the record form shows each under its field, in Arabic or English by the failure's
  code.
- Offline search (B18-T11): the records on a device can be searched without a network, by prefix
  and with light fuzzy matching; Arabic matches however it was typed (diacritics ignored, alef forms,
  ta marbuta and alef maqsura unified). The index is rebuilt after each sync pull (MiniSearch 7.2.0).
- Opportunity lines are documented for builders and administrators (D6-T14, `docs/opportunity-lines.md`):
  the flags, pricing order, how the deal's amount follows its lines, schedules, quote sync and undo.
- Share an attachment by link (B3-T3): the K1 expiring, password-protected file links cover record
  attachments, proven end to end.
- Developer tooling: per-request SQL and Redis call budgets for key requests
  (`crates/apps/attome/tests/request_counts.json`, AA14-T3); `attome_testkit::jobs` runs a job at
  once and moves schedule time with a fake clock (Z7-T7); `attome_inference::adapter::ModelAdapter`
  puts model providers behind one trait (Z9-T1).
- The developer guide explains concurrent edits (A16-T8), in English and Arabic: the
  `409 version_conflict` body (`current_version`, and `current_state` with `changed_attributes` and
  `hidden_changes`) and the `If-Match-Merge: attributes` header with its `merged_over` answer, with
  an example request and response.
- Territory realignment (D13-T3): `POST /api/v1/sales/territories/realign/preview` lists the accounts
  whose rule-made territory would change. `POST /api/v1/sales/territories/realign` queues the
  `territory_realign` job, which applies the changes in batches through the generic write path,
  leaving manual links alone.
- Dialer calls through J6 (D21-T6): `POST /api/v1/sales/call-lists/{id}/dial` rings the agent's
  phone and then the customer through the voice system. The customer sees the caller ID the
  caller ID rules choose for their country, and only ever a number the system owns.
  `POST /api/v1/sales/call-lists/{id}/voicemail` drops a recorded message into the agent's call when
  the list allows voicemail (Twilio). Migration 0148 records the chosen caller ID on the call.
- Online quote acceptance (D9-T3): a sent quote's guest link
  (`POST /api/v1/sales/quotes/{id}/guest-link`) opens `/quote/{token}`, where the customer reviews
  the quote and accepts or rejects it with their name. The link is bound to the quote's version and
  expires (30 days by default, never after the quote does). A decided quote is locked by the sales
  pack's new `quote_locked_after_decision` rule (pack changeset 0019).
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
- Stock ledger (I6-T2, field-service pack `0005`): `POST /api/v1/service/stock/movements`, `POST
  /api/v1/service/stock/reservations` and `POST /api/v1/service/stock/reservations/{id}/release` write an
  append-only `stock_movement` (signed quantity) and the `stock_balance` together under a row lock, so
  concurrent movers never oversell; stock leaves only from what is available unless the balance has
  `allow_negative`. The `stock_ledger` job reserves part lines of scheduled work orders, issues them on
  completion and releases them on cancellation.
- Static status page (H8-T2): when a status record changes, the status notice job writes the public
  status page as one static bilingual `status-page/index.html` (and `status-page/status.json`) to the
  object store, for a bucket or static host. `attome status-page --url <server> --out <dir>` writes the
  same files from a server's public `GET /api/v1/status` into a directory on another host.
- Work order invoicing (I1-T2, field-service pack `0004`): when a work order is completed, each line is
  split into what its entitlement covers and what is billable (a warranty by its term's parts and labour
  percent, an hours entitlement from the hours left, a cases entitlement with one case; contracts never
  cover parts), kept on the line as `covered_pct` and `billable_amount`, and the billable lines go to
  billing as an invoice request keyed `work_order:{id}` by the `work_order_invoicing` job. The request id
  is kept in the work order's `invoice_reference`.
- Warranty coverage per line (I10-T2, field-service pack `0006`): work order lines gain the `travel`
  kind, covered by a warranty's `travel_covered_pct` (parts and labour by theirs); an entitlement's own
  percentages win over its warranty term's. The nightly `warranty_expiry_reminder` job tells a warranty
  entitlement's owner 30 days before it ends, once per end date (`entitlement.expiry_reminded_on`).
- Maintenance generation (I5-T2, field-service pack `0007`): a maintenance plan on an asset makes its
  work order (with one task per task template) `lead_days` before `next_due_on` through an M10 timer
  of kind `service.maintenance` that follows the date, or when the asset's latest meter reading rises
  `meter_threshold` above the reading at the last generation (daily `maintenance_generation` job).
  Each due date makes one work order (`maintenance_plan_ref`, `maintenance_due_on`); none is made
  while another of the plan is open; repeating plans skip missed periods instead of catching up.
- Return dispositions (I11-T2, field-service pack `0008`): `POST /api/v1/service/returns/{id}/dispositions`
  acts once on each inspected line of a received or inspected return: `refund` makes a draft credit note
  on the line's `invoice_line_ref`, `restock` a `return` stock movement into the return's
  `restock_location`, `replace` a draft no-charge replacement order; repair, scrap and return to vendor
  are recorded. Each line keeps what it made in `disposition_reference`; a repeat answers `already_done`.
- Technician candidates (I2-T1, field-service pack `0009`): `GET /api/v1/service/work-orders/{id}/candidates`
  ranks the technicians (`technician_profile`) who have the job's `required_skills` (`skill` or
  `skill:level`, else the incident type's), belong to the account's territory, are on shift and not on
  leave in its window, and carry its parts in their van stock (`include_without_parts=true` relaxes the
  last); on-time first, then by straight-line travel estimate and slack to `scheduled_end`. It assigns
  nothing.
- Major incidents (H1-T2, itsm pack `0003`): `POST /api/v1/service/tickets/{id}/major-incident` declares
  one: sets the commander and `declared_at`, pages whoever is on call on the chosen `oncall_schedule`
  (layers, members and overrides are now stored) and the commander, opens a bridge on the named video
  provider, and posts a status page incident with a first update to subscribers. `.../children` links
  tickets (`parent_ticket_id`); `.../resolve` sets `restored_at` and resolves the status incident.
- Vendor compliance reminders (W2-T1, vendor-supplier pack `0003`): each compliance document with an
  expiry date gets an M10 timer (`procurement.compliance_expiry`) 30 days before it, following the date;
  when it fires the vendor's owner and the document's owner are told once per expiry date
  (`reminded_for`), and again after the document is renewed to a new date.
- Requisition to purchase order (W3-T2, procurement pack `0002`, needs the finance pack's budget lines):
  `POST /api/v1/procurement/requisitions/{id}/submit` checks the requisition's `budget_line_ref` (block
  unless the line's `overspend` is `warn`) and opens a `procurement.requisition_approve` approval whose
  approvers come from the `procurement_doa_rule` matching its amount, category and cost centre;
  approval commits the amount on the budget line. `.../order` makes a draft purchase order (not for a
  vendor on hold) and moves the commitment to it; `.../cancel` and
  `POST /api/v1/procurement/purchase-orders/{id}/cancel` release it; `.../change` applies a new total
  within the rule's tolerance (10% by default) or opens a `procurement.po_change` re-approval.
  Approving a requisition by hand now needs `purchase_requisition.approve`.
- Sealed RFQs (W3-T4, procurement pack `0003`): an `rfq_bid`'s price, lead time and notes are sensitive
  fields no field profile grants, so staff other than administrators cannot read them; the `rfq_open`
  job copies them into readable `opened_*` fields at `deadline_at`, marks later bids `late` and closes
  the RFQ. `POST /api/v1/procurement/rfqs/{id}/award` awards an opened RFQ to one of its on-time bids
  with a reason. Vendors bid through a portal role granted `rfq_bid` create on their own rows.
- Survey kind (G14-T1): a `survey` metadata object lists questions (text, long text, number, rating,
  yes/no, date, choice, multiple choice); publishing it applies a changeset (layer `project`, scope
  `survey_<entity>`) that creates its `response_entity` with one attribute per question plus respondent,
  regarding record and submitted time. Republishing the same survey applies nothing; a new question
  only adds its field.
- Project budgets and invoices (V1-T2, finance pack `0003`): `POST /api/v1/projects/{id}/spend-check`
  checks a spend against the budget line linked to the project; `POST /api/v1/projects/{id}/invoice-proposals`
  sends billing an invoice request for the project's `account_ref`: `milestone` for one accepted
  deliverable's `invoice_amount`, `time_and_materials` for billable hours on approved timesheets at each
  person's billable rate. Deliverables and time entries keep the request in `invoice_request_ref`, so
  nothing is proposed twice; people without a rate are left out and named.
- Customer sign-off of change requests (V5-T1, platform changeset `0063`):
  `POST /api/v1/project/change-request/{id}/send-for-signoff` sends a pending, customer-facing change
  request's document to the customer's signer in a K4 envelope; when it is signed, the `change_signoff`
  job approves the change request as the sender (impact applied, project rebaselined), and a declined
  or voided envelope rejects it. `signoff_status` shows where it stands.
- Schedule builds (G17-T6, workforce pack `0002`): the `workforce_build_schedule` job
  (`attome_workforce::build_job::enqueue`) reads a planning group's members (`wfm_group_member`), stored
  forecast (`wfm_forecast_interval`), shift templates and leave, solves each day on a blocking thread
  under a deadline (300 s by default; at most 2,000 people and 31 days), and writes one draft
  `wfm_schedule` per run id with its assignments and `coverage_json` (requirement, coverage before and
  after) under the group's build lock. A retry of the same run replaces its own draft.
- Schedule routes (G17-T7): `POST /api/v1/workforce/groups/{id}/schedules/build` queues a build (202 with
  its run id); `GET /api/v1/workforce/schedules` and `GET /api/v1/workforce/schedules/{id}` read
  schedules with assignments and coverage; `PATCH /api/v1/workforce/assignments/{id}` (`If-Match`)
  checks the person's week against their rule set (422 `rule_breach: <codes>`) and needs a `reason` on a
  published shift, which the person is told; `POST /api/v1/workforce/schedules/{id}/publish`
  (`If-Match`) books every shift on the person's time (`resource_allocation`), supersedes the group's
  overlapping published schedule and tells everyone scheduled.
- Surveys on events (G14-T2): a survey's `send_on` (entity, field, value, recipient lookup; for example
  `service_ticket.status = closed`, `requester_id`) makes the `survey_send` job email the recipient a
  signed 30-day link when a record reaches the value, one per record. The link opens
  `GET /api/v1/surveys/form` (a public bilingual form; `/api/v1/surveys/respond` is its JSON twin), and
  the answers are checked against each question and stored once on the survey's response row.
- Day plan proposals (I2-T2): `POST /api/v1/service/day-plans/propose` answers ghost assignments for a
  day's unassigned work orders (or the ones named): each job goes to a technician the I2-T1 hard rules
  allow, by cheapest insertion into their route within their shift (08:00-17:00 without one), then moves
  that cut total travel, within a 10-second budget. Nothing is written.
- General ledger (W5-T1, new `attome-ledger` crate on the `ledger` module, `ledger` pack):
  `POST /api/v1/ledger/entries` posts a balanced journal entry in exact decimals into an open period
  (append-only; an unbalanced entry, a closed period or a heading account is 422);
  `POST /api/v1/ledger/source-postings` posts a source document through its `gl_posting_rule`, once per
  source; `POST /api/v1/ledger/periods/{id}/close` and `/reopen` are audited.
- Schedule what-if and hiring view (G17-T11): `POST /api/v1/workforce/schedules/{id}/what-if` recomputes a
  schedule's requirement, coverage and service level with a forecast multiplier, target or handling-time
  overrides and a headcount change, writing nothing; `GET /api/v1/workforce/groups/{id}/hiring-plan?months=6`
  answers required full-time people per month from the stored forecast against current members.
- Workforce self-service (G17-T8): `GET /api/v1/workforce/me/schedule` (the caller's own published
  shifts), `PUT /api/v1/workforce/me/preferences`, `POST /api/v1/workforce/swaps` (approved and applied at
  once when the colleague's rules hold and they are free then, else waiting), `POST
  /api/v1/workforce/swaps/{id}/decide` for planners, and `GET /api/v1/workforce/coverage-impact` listing
  the intervals a person's leave would leave short.
- Workforce agent tools (G17-T15): `workforce.coverage`, `workforce.explain_gap`, `workforce.my_next_day_off`
  and `workforce.propose_fix` (free members who could cover each short interval, as a proposal). They read
  only, work on draft schedules and refuse a published one.
- Project Gantt (V1-T1): `GET /api/v1/project/{id}/gantt` answers the work items with dates, critical-path
  flag and float, their dependencies and the latest baseline's planned dates; the work plan tab's
  Timeline view draws them as bars over a day scale, critical items marked, the baseline under each bar
  and dependencies as links (English and Arabic labels).
- Intraday management (G17-T9, workforce pack `0003`): for planning groups with `intraday_enabled`, the
  `workforce_intraday` job (every 15 minutes) scales the rest of today's forecast by actual volume so far
  (service tickets on the group's channel) and proposes an overtime offer for each run short by more than
  one person, and time off for each run over. `POST /api/v1/workforce/offers/{id}/send` tells the people
  who could take it; `POST /api/v1/workforce/offers/{id}/accept` lets the first one take it, adding or
  trimming their shift. Both are audited.
- Collections follow-ups (AI5-T2, migration `0195`): the follow-up scan also runs each active
  `ai_collection_rule`, writing invoices coming due, overdue invoices and subscriptions coming up for
  renewal to the follow-up ledger (new reasons `invoice_due`, `invoice_overdue`, `renewal_due`), at most
  once a day per record, skipping invoices with an open payment promise and records at the rule's
  `max_reminders`.
- Scheduled report delivery (P3-T1): a report schedule's `recipients` (user ids or addresses) each get
  their own run under their own access instead of one run as `run_as`; each completed run is sent to its
  recipient in the app, or also by email with `delivery = email_link`, unless it is empty and the
  schedule says `skip_if_empty`; a failed scheduled run alerts the schedule's owner.
- Meeting briefs (AI6-T2): the `meeting.brief` AI action writes a one-page brief for a meeting activity
  from its account, up to 10 open deals and 10 open cases, the 5 latest activities and 10 open tasks,
  read as the meeting owner (and the asker) so it holds nothing either cannot read. It is written in the
  meeting's language, else the owner's locale, within the AI budget, into the meeting's one
  `ai_meeting_brief` row (refreshed on a rerun; `failed` with no text when generation fails). The prompt
  is `meeting.brief/v1`; agent policies can list the action.
- Meeting briefs made unasked (AI6-T3): the `ai_meeting_brief_scan` job (every 15 minutes) queues one
  `ai_meeting_brief` job for each meeting starting 60 to 75 minutes ahead that is not cancelled and has
  no brief; the job runs `meeting.brief` as the meeting owner through the AI gate and sends them an
  in-app notice. The new setting `ai.meeting_briefs` (user or deployment, on by default) turns it off.
- Meeting notes (AI6-T4): the `meeting.notes` AI action reads a recording's transcript (`transcript_ref`
  is the recording document; its N22 transcript, under the document's access) and writes draft
  `ai_meeting_notes`: summary, decisions, action items and proposed record updates in the transcript's
  language. Long transcripts are summarised in parts and merged (`meeting.notes_merge`). A proposed update
  is kept only for the meeting's record or account, a real non-system attribute, a quote found in the
  transcript, and a record the caller may update; nothing is applied. `action_items_json` holds
  `{action_items, record_updates}`; confirmed notes are never rewritten.
- Confirming meeting notes (AI6-T5): the `meeting.confirm_notes` AI action marks draft notes confirmed
  under the `row_version` the person read, makes each chosen action item an open task on the meeting,
  and proposes each chosen record update through `record.update_field` (its allow-list, approval and
  daily cap decide). Each task and proposal records an `agent_task` outcome row.
- Meeting routes (AI6-T6): `GET /api/v1/ai/meetings/{id}/brief` (anyone who may read the meeting),
  `POST /api/v1/ai/meetings/{id}/brief/regenerate`, `POST /api/v1/ai/meetings/{id}/notes` with
  `{transcript_ref}` (202; queues the `ai_meeting_notes` job, one per meeting, transcript and person) and
  `POST /api/v1/ai/meetings/{id}/notes/confirm` with `If-Match` and the chosen item indexes. The POSTs
  invoke the meeting actions through the gate as the caller.
- Meeting-notes evaluation (AI6-T8): `crates/engine/attome-ai/tests/fixtures/meeting_notes.json` holds five
  Arabic and five English made-up meetings with their expected decisions and action items and a recorded
  model output; `ai6_eval_notes_recall` replays them through the notes parser and fails under 80% recall.
- Meeting panels (AI6-T7, `@attome/xrm/ai`): `xrm-ai-meeting-brief` shows a meeting's brief in its own
  language's direction with a "make again" button; `xrm-ai-meeting-notes` asks for notes from a recording,
  shows the summary and decisions, and lists action items and proposed record updates (each with its
  transcript quote) as checkboxes; confirm sends only the checked ones under `If-Match`. English and
  Arabic labels (`aiMeeting.*`).
- Collections actions (AI5-T3): `collections.send_reminder` (Consequential: an agent's call waits for
  approval) emails a collections item's reminder from its rule's template in the customer's language, every
  amount, number and date filled from the invoice or subscription; `collections.record_promise`
  (Reversible) records an `ai_payment_promise` with the customer's own words. Rules on `whatsapp` or `sms`
  are refused until those channels are sent. Both record `agent_task` outcomes.
- Hand-off card and list (AI7-T6, `@attome/xrm/service`): the ticket form shows the ticket's newest hand-off
  (summary, reasoning, from and to with an agent, person or queue icon, status) with Accept and Hand back to
  agent (a note is required; If-Match); `/service/handoffs` lists what waits for me or my queues. English
  and Arabic (`serviceHandoff.*`).
- Hand-off routes (AI7-T5): `GET /api/v1/service/handoffs` (waiting for me or my queues),
  `POST /api/v1/service/handoffs/{id}/accept` and `.../return` (`{note}`), both with `If-Match`, and
  `POST /api/v1/service/tickets/{id}/handoff` (`{to_kind, to_ref, summary, reasoning}`) for a person handing a
  ticket to a person, a queue or an agent; `GET /api/v1/service/tickets/{id}/handoffs` lists a ticket's hand-offs.
- Hand-back to the agent (AI7-T4): the `ai_handback` job resumes the agent session that handed the ticket off
  with the person's note as its next turn when that session is still live, or starts a new session of the
  same agent for the person who returned it, its first turn carrying the ticket, the summary, the reasoning
  and the note. A revoked or paused session is never resumed; a retried job does nothing.
- Agent hand-off to a person (AI7-T3): the `handoff.to_person` AI action (Reversible) hands a ticket the
  caller can see to a person, queue or agent the caller can see, with a structured summary and required
  reasoning, through the service hand-off ledger; it records an `agent_task` outcome under rule
  `ai.handoff`, which agent performance counts. `bot.handoff` is unchanged for web chat.
- Service resolver agent (AI2-T1, platform changeset `0065`): the `service_resolver` agent (a draft until an administrator
  activates it) with its Service Resolver policy: read the case and the knowledge base, answer from it, update the case,
  translate, draft a reply and hand the case to a person, capped at Reversible with session and daily limits, so refunds and
  credits wait for a person. Its Arabic and English evaluation cases are `tests/fixtures/service_resolver.json`.
- Agent behaviour tests (AH5-T6): `tests/agent_behaviour.rs` covers a burst that pauses and suspends an agent and
  notifies its owner, an agent in its learning week left alone, and no job switching a stopped agent back on.
- Work done by agents (AK3, migration `0201`): a change-feed consumer counts, each minute, the completions of
  every active work measure (`ai_work_measure`) by agents and by people, from each event's initiator, with the
  day's ticket hand-offs. Counts are kept in `ai_work_share_daily` and rebuildable through
  `POST /api/v1/admin/ai/work-share/rebuild`. `GET /api/v1/admin/ai/work-share` and `.../{process_key}/events`
  read them, and the new page `/ai/agents/work-share` is linked from agent performance.
- Bulk edit dialog (B5-T4): the entity list's bulk edit now runs through `/bulk-edit`. It edits the selection or every
  record matching the current filters, with several operations (set, clear, add or remove an option, increase a
  number) and a preview. Results list each record not changed, linked, with the reason in the user's language. The
  edit can be undone, run without automation, and saved by name (new per-user setting `records.bulk_actions`) to run
  again. `POST /api/v1/{entity}/bulk-edit` and its undo now return `record_ids`, the records in item order.
- Roll an agent back to a time (AH2): `GET /api/v1/admin/ai/agents/{id}/rollback-preview?since=` and
  `POST /api/v1/admin/ai/agents/{id}/rollback` (admin or `ai_agent.supervise`; `since` in the past and inside
  `retention.audit_days`) revoke the agent's live sessions, then undo every session of the agent since then in one
  `agent_since` undo run, newest first, with the session undo's checks. The agent sessions screen gains "Roll back agent
  since…" with a time picker, the session count and the preview. `tests/agent_run_undo.rs` covers single-session undo
  (AH1-T7) and the rollback.
- Bulk edit without automation (B5-T3, migration `0200`): `POST /api/v1/{entity}/bulk-edit`, its `/undo` and
  `POST /api/v1/{entity}/bulk` accept `quiet: true` with the new `records.bulk_quiet` privilege (platform changeset
  `0070`); the records change through the normal path but their change events are marked `quiet`, so they start no
  workflow entry trigger (nor an agent a flow runs) and notify no follower. Change events gain a `quiet` column, and a
  quiet edit waiting on its approval runs quiet once approved.
- Agent-drafted label translations (A20-T2): with languages named in the new setting `i18n.draft_locales` (none by
  default), an hourly job (`label_translation_drafts`) translates up to 100 untranslated entity, attribute and choice
  labels per language through `text.translate` (glossary, cache, model approval and budget as usual) and stores them as
  `draft` for the workbench's review; a person's reviewed translation is never replaced.
- Model usage rows (Z9-T5, migration `0199`): every budgeted model call writes an `ai_usage_event` row with the person,
  the agent session when an agent made it, the feature, the model that answered, its prompt, completion and cached tokens,
  its cost when the model has a configured price, and its latency.
- Agent discount limit (AH4-T1): an agent object may set `limits.max_discount_percent` (0–100); an agent's step whose
  `discount_percent` is above it is refused with `discount_above_agent_limit` before it runs, so a person gives that
  discount.
- Agent attribution on engine writes (AK3-T1, migration `0198`): every agent action now runs inside
  `attome_core::agent_scope`, so the record audit headers and change events its engine writes name the agent's session
  (`initiator` 1) instead of reading as the person's own; `entity_change_event` gains `initiator` and `agent_session_id`.
  Agent run undo and agent baselines read exactly these.
- Agent behaviour on the performance page (AH5-T5): `GET /api/v1/admin/ai/agents/{id}/behaviour` (administrators) gives an
  agent's status, baseline, last 24 hours and last automatic stop; the agent performance page shows them for the chosen
  agent with an hourly writes chart, and a stopped agent's reason with a Switch back on button (the agent's ordinary
  update with If-Match). English and Arabic.
- Agent activity rules (AH5-T4): the four built-in departure rules are `behaviour::RULES`, and `behaviour::stop_agent`
  stops the agent an activity event names through the same trip as the check, ready for owner-added watcher rules.
- Agent stop on a departure (AH5-T3): when the five-minute check finds a departure, the agent's live sessions are paused
  (`automatic: <kind>`), the agent is set `suspended` (which new sessions already refuse) with a Configuration audit
  event, and its owner and the administrators are alerted with what departed; only a person sets it back to active.
- Agent departure check (AH5-T2): every five minutes (job `ai_agent_behaviour_check`) each agent with seven days of
  history has its current hour compared with its baseline: writes or deletes above the mean plus four standard deviations
  (and at least 20 writes or 5 deletes), an entity it never wrote, or writes in an hour it does not usually work.
  Departures are logged; stopping the agent follows in AH5-T3.
- Agent activity baselines (AH5-T1, migration `0197`): the hourly job `ai_agent_behaviour_rollup` writes each agent's
  completed record writes, deletes and outside calls or messages per hour, with the entities it wrote
  (`ai_agent_activity_hourly`), and at 03:00 UTC its 28-day baseline (`ai_agent_baseline`: mean and spread per hour with
  quiet hours as zero, usual entities and usual hours of the day), which AH5-T2's departure check compares with.
- Undo run on the agent sessions screen (AH1-T6, `@attome/xrm/ai`): each session row has Undo run, which previews the plan
  in three groups (will be put back; skipped because a person changed it, with the attribute names; cannot be undone,
  with why), then Undo now starts it and follows the run every two seconds until it ends. English and Arabic.
- Agent run undo routes (AH1-T5): `GET /api/v1/ai/agent-sessions/{id}/undo-preview` lists the planned steps,
  `POST /api/v1/ai/agent-sessions/{id}/undo` (202) starts the undo with an `Ai` audit event, and
  `GET /api/v1/ai/undo-runs/{id}` gives the run's status, counts and items; the session's owner or a holder of
  `ai_agent.supervise` only.
- Agent run undo execution (AH1-T4, migration `0196`): `attome_ai::undo::start_undo` stores the plan as an `ai_undo_run`
  with one `ai_undo_item` per step (the step kept in the new `step` column) and queues the `ai_undo_run` job, which applies
  each pending item as the person who asked with the planned `row_version` (a record changed meanwhile is skipped, never
  overwritten), commits each outcome on its own so a restart resumes, and ends the run `done` or `failed` with counts.
- Agent run undo plan (AH1-T3, `attome_ai::undo::plan_undo`): from a session's changes, per record and newest first, plans
  setting back each attribute still as the agent left it, skips (and names) the attributes a person changed since,
  soft-deletes what the agent created unless someone edited it, restores what it soft-deleted, and lists hard deletes and
  every message sent or outside call as not undoable. Writes nothing.
- Agent run changes (AH1-T2, `attome_ai::undo`): `collect_session_changes` returns every record change one agent session
  made, newest first, with each field's old and new value (opened with the record's audit key when crypto-shredding is
  on; sensitive and credential fields, and records whose key was destroyed, are marked not restorable), and
  `collect_external_effects` the completed calls that reached outside or sent a message, which cannot be undone.
- Agent message limits now count `followup.send_message`, `collections.send_reminder` and `lead.send_message` as
  messages sent (`max_messages_per_day`): the message-send rule also matches `*.send_message` and `*.send_reminder`.
- Agent permission cases (AH7-T1, `attome_ai::permission_test`): `negative_cases` lists, from an agent's policy, its
  capability packs' actions, its owner's privileges and the entities, every call the gate must stop (outside the
  allow-list, above the ceiling, a privilege the owner lacks, an entity the owner cannot read) and every Consequential
  call that needs approval; `positive_cases` lists the calls that must go through.
- Decision outcomes (O10-T1, platform changeset `0069`, `attome-dashboard`): executing a decision records `executed_at` and
  its outcome metric's latest value as `outcome_before`; the daily job `dashboard_decision_measure` takes each executed
  decision whose `measure_at` has passed, reads the metric's first value since then as `outcome_after`, and writes
  `actual_delta`, `effectiveness` (actual ÷ expected delta) and status `measured` with a business event.
- Metadata versions page (Y8-T12, `@attome/xrm/core/admin/metadata-versions`, `/xrm/admin/metadata-versions`): the
  published configuration versions newest first with the current one marked, each version's node switch times, and a
  Roll back button that asks first and then points every node at the version before the current one. New route
  `GET /api/v1/admin/metadata/versions` (administrators) lists the versions with how many nodes serve each.
- Sales orders from quotes and won deals (D10-T2, `attome-sales`, sales pack `0026`):
  `POST /api/v1/sales/quotes/{id}/order` and `POST /api/v1/sales/opportunities/{id}/order` make a draft order, once per
  source, with the quote's or deal's lines; `POST /api/v1/sales/orders/{id}/confirm` runs the account's credit check for
  the grand total, locks the lines' prices, files a billing invoice request keyed on the order and moves the order to
  `confirmed`, which the pack's new rules then lock. Orders gain `opportunity_ref`; order lines gain `description` and
  `is_locked`. `attome-sales` now depends on `attome-billing`.
- Credit limits and credit hold (F5-T12, `attome-billing`): `payment::credit::credit_check` refuses a sale on credit to an
  account on hold, over its credit limit (open balance from its invoices' stored open totals plus the new amount) or,
  with `billing.credit.block_overdue`, with an overdue invoice; `GET /api/v1/billing/accounts/{id}/credit` shows it. With
  `billing.credit.auto_hold`, the nightly job `billing_credit_hold` puts accounts with invoices more than
  `billing.credit.hold_after_days` (30) past due on hold. Three new settings.
- Operations agent (AK2-T1, platform changeset `0068`): `ops.report` (administrators, reads only) gives the nodes and their
  versions, the services this node depends on, the backups in `backup.dir` with the last restore drill, the database and
  backup sizes, each SLO class's status, and the routine actions they call for (a stale or missing backup, backups off, no
  passing drill in 35 days, a service down, writes paused, a silent node, mixed versions, an SLO over budget), each naming
  its fix. Every Monday from 06:00 UTC the same report and proposals go to every administrator as a weekly digest (job
  `ai_ops_weekly_digest`). The `ops_agent` (a draft) reads only, through its Operations policy.
- HR case access (W8-T1, human-resources pack `0004`): the HR Specialist role reads and works every HR case, confidential
  ones included, and manages the HR offerings; a new Employee role raises cases and sees only its own; a new case is not
  confidential unless set. Other ticket roles are kept off confidential cases by a grant condition the deployment adds
  (packs README).
- Inbox-to-record agent (AI3-T1, platform changeset `0067`): the `inbox_to_record` agent (a draft until an administrator
  activates it) with its Inbox to Record policy: read an inbound email and its attachments, classify it, extract its
  fields, find, create or update the lead, case or order, file the email on that record with the new Reversible action
  `inbox.file_message` (a `communication_link` row, so the email and its attachments show on the record too) and
  acknowledge the sender with `email.send`, which waits for approval or its undo window. `email.send` and
  `inbox.file_message` join the policy choices. Its Arabic and English evaluation cases are
  `tests/fixtures/inbox_to_record.json`.
- Lead qualifier agent (AI1-T1, platform changeset `0066`): the `lead_qualifier` agent (a draft until an administrator
  activates it) with its Lead Qualifier policy: read, research, update and assign the lead, and two new Consequential
  actions that reach the lead, `lead.send_message` (an email on the lead) and `lead.book_meeting` (a meeting on a D20
  booking page at an offered time, in the lead's name). Both wait for a person's approval and refuse unless the lead holds
  a grant for the `sales_outreach` consent purpose on email. Its Arabic and English evaluation cases are
  `tests/fixtures/lead_qualifier.json`.
- Customer 360 (G15-T1, `@attome/xrm/core/entity`): the account and contact pages show `xrm-customer-360`, the
  customer's open deals, open tasks, unpaid invoices, active entitlements, assets and people (each loading its first
  five and its count when opened, and hiding where its entity is not installed), the recent timeline and an AI summary
  on request; the same component serves the agent workspace's context panel.
- Community forums (G13-T1, new `community` pack): forum categories, threads with an accepted answer, posts,
  votes and ideas with statuses; business rules hold a new thread, post or idea with a link or a blocked term as
  `pending` for the moderation queue (a stored query and a Community menu); Community Moderator and Viewer roles.
- Inter-company postings (W5-T2, ledger pack `0002`): `POST /api/v1/ledger/intercompany` posts both companies' entries in one
  transaction (due-from and income in the first company's books, expense and due-to in the second's, from each pair's
  `gl_intercompany_account`), linked by `intercompany_ref`; `GET /api/v1/ledger/group-trial-balance?from&to` leaves
  linked entries out, eliminating them from group figures.
- `docs/workforce.md` documents workforce management (G17-T17): the records, the staffing requirement, schedule builds and
  publishing, what-if and hiring plans, staff self-service, intraday offers, the agent tools, and what is not built yet.
- AI outcome quality (O11-T1): `record.ai_field`, `record.classify`, `knowledge.answer` and `route.classify`
  declare the `ai_suggestion` outcome kind, so their suggestions now reach the outcome ledger (before, its
  dual-write refused them). `GET /api/v1/admin/outcomes/quality/by-model` and `.../by-agent` (`?days=`, default
  30) report proposals, measured, accepted, edited and rejected counts, acceptance rate and mean effectiveness.
- Export formats (P4-T1): CSV, XLSX and the new PowerPoint (`pptx`) report format write a text cell that starts with
  `=`, `+`, `-`, `@`, a tab or a carriage return as text (prefixed with `'`), for report runs and data exports
  alike; the deployment setting `records.export_formula_guard` (on by default) turns it off. A `pptx` report run
  is a title slide and the rows as tables, 12 a slide, Arabic laid out right to left, at most 600 rows.
- Ticket hand-offs (AI7-T2, `attome-service::handoff`): an agent or a person hands a ticket to a person
  (assigned at once), a queue (moved there unassigned) or an agent, with a summary and reasoning, at most one
  waiting per ticket; only the person it names or a member of the queue accepts it, and only the ticket's
  assignee returns an agent's hand-off with a note, which queues the `ai_handback` job. Each step is a
  business event on the ticket's timeline.
- Agent performance screen (AI8-T6, `/ai/agents/performance`): per-agent tasks, resolution, accuracy,
  hand-off rate, estimated time saved, tokens and cost per task ("no price set" when some tokens had no
  price) over a date range; an agent's daily trend (the dashboard chart) and days, each day's number
  opening the runs behind it. English and Arabic (`aiPerformance.*`), numbers in the page's locale.
- Agent performance routes and action (AI8-T4/T5): `GET /api/v1/admin/ai/agents/performance?from&to`
  (each agent's sums and the rates read from them: resolution, accuracy, hand-off rate, cost per task),
  `GET /api/v1/admin/ai/agents/{id}/performance/daily` and `GET /api/v1/admin/ai/agents/{id}/runs?day&metric`
  (the outcome rows or sessions behind one number, keyset-paged), administrators only, with no message
  text or record values; the read-only `agent.performance` action answers the same for the operations
  agent and MCP.
- Agent performance rollup (AI8-T2/T3): `ai_agent_daily_stat` is computed per agent and UTC day from the
  outcome ledger's `agent_task` rows (done, resolved, measured, effectiveness, hand-offs), the agent's
  message tokens and their price (configured prices, else the approved model catalogue; unpriced tokens add
  no cost and leave `cost_unit` empty) and an estimated time saved per task source. The
  `ai_agent_stats_rollup` job rolls up yesterday once the UTC day reaches 02:00;
  `POST /api/v1/admin/ai/agents/performance/backfill` (`{from, to}`, at most 400 days, administrators,
  audited) queues a range. A rerun replaces the day.
- Promises read from replies (AI5-T4): every five minutes the `ai_promise_extract` job reads new inbound
  messages on invoices with an open collections item and, through one budgeted model call answering strict
  JSON (Arabic or English, Arabic digits included), records a promise with a date as an
  `ai_payment_promise` pending staff review; a duplicate for the same invoice and date is skipped. Prompt
  `collections.extract_promise/v1`.
- Collections panel (AI5-T7, `@attome/xrm/ai`): the invoice form shows `xrm-ai-collections-panel` with the
  invoice's reminders and payment promises (amount, date in the viewer's calendar, the customer's words);
  confirm or reject a promise an agent read, mark an open one kept or broken, each with `If-Match`. English
  and Arabic labels (`aiCollections.*`).
- Daily collections (AI5-T5): the follow-up scan finds collection reminders from 08:00 in the deployment's
  `core.time_zone` each day, and a collections item's run sends its reminder as the owner while the rule
  is active and has reminders left (no customer email or an unsent channel reminds the owner instead).
- Collections routes (AI5-T6, platform changeset `0064`): `GET /api/v1/ai/collections/invoices/{id}/promises`
  and `.../reminders` (read access to the invoice), `POST /api/v1/ai/collections/promises/{id}/confirm` and
  `.../reject` (review of a promise an agent recorded; `ai_payment_promise` gains `review_status`,
  `reviewed_by`, `reviewed_at`) and `POST /api/v1/ai/collections/promises/{id}/status` (`kept` or
  `broken`), each under `If-Match` and update access to the invoice. A rejected promise no longer holds
  reminders back.
- `docs/agents.md` describes hand-offs between agents and people (AI7-T8): the ledger, accepting, handing back and what
  the agent receives, and that queues, claims and live routing stay with their own engines.
- `docs/agents.md` describes agent performance (AI8-T7): what each figure means, the time-saved estimates, the price
  source, the nightly recompute and the runs behind each number.
- `docs/agents.md` describes collections and renewals (AI5-T8): rule kinds, offsets, the email channel, `max_reminders`,
  approval for an agent's send, amounts from the invoice, and the `/api/v1/ai/collections/...` routes.
- `docs/agents.md` describes meeting briefs and notes (AI6-T9): when briefs are made, what they read and
  how they respect record access, notes from transcripts, and confirmation with gated record updates.
- Metric snapshots are banded (P9-T6): new rows say `on_track`, `at_risk` or `off_track` (and `failed`)
  instead of `ok`, `warn` and `crit`. A target's `at_risk_tolerance` (percent of the target) makes a
  near miss at risk and a bigger miss off track, for higher-is-better, lower-is-better and band metrics;
  the explicit thresholds still apply and the worse band wins. Each dimension member is banded against
  its own target (`dimension_value`), else the total's. Older rows keep their values and read as the
  matching band; alerts treat both the same.
- Commission plan acceptance, spiffs and draws (F10-T10, commission pack `0005`):
  `POST /api/v1/commission/plans/{id}/send-for-acceptance` renders a K3 plan document per participant of
  the latest published version and the `commission_acceptance` job sends it as a K4 signature envelope;
  a completed envelope marks the participant `accepted` and releases their `held` payouts (runs hold the
  payout of a participant asked to accept who has not). A component with its own `starts_on`/`ends_on`
  (a spiff) pays only on credits inside that window. Draws: a recoverable draw pays at least the draw
  and recovers the shortfall from later excess earnings; a non-recoverable one pays the larger of draw
  and earnings. Payouts keep `earned`, `draw_ref` and `draw_balance_change`; a repeated run for a period
  undoes its earlier draw change first.
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
- Model calls go through the outbound layer (AB6-T3): each configured model endpoint is an
  `ai_model` service with its own breaker, so a model server that keeps failing (any 5xx, a rate
  limit, a timeout) is refused at once for a while (`InferenceError::Unavailable`, outcome
  `breaker_open` in `attome_inference_requests_total`) instead of every turn waiting on it.
  Embeddings still retry twice on a transient failure, now through the outbound service, honouring
  `Retry-After` up to 60 s inside the request timeout; generation is still never replayed.
- A breaker per outside endpoint (AB6-T5): each REST connector endpoint (system and host) and each
  webhook target (subscription and host) has its own, so one failing endpoint does not slow the
  others. A REST GET is retried; a POST only when it carries an `Idempotency-Key`. A webhook whose
  target's breaker is open is queued again for when it reopens, without counting an attempt.
- Object storage and mail sends go through the outbound layer (AB6-T4): the services
  `object_storage` and `smtp` each have a breaker, bulkheads and one retry budget, so an outage fails
  fast instead of every request waiting out its timeout. A cloud store's own retries are off; a GET,
  HEAD, list page, delete or overwriting PUT is retried up to three attempts, never a create-only
  PUT, a rename or a multipart upload. A mail send is retried only when it carries its delivery row.
- A deal's amount is locked while it has lines (D6-T4): a staff write of `opportunity.amount`
  answers `field_locked`; the lines set it.
- Lists and entity schemas revalidate (AA7-T11): the web app remembers the last answer to each
  `query/execute` and `/schema` request with its ETag (in memory, 200 at most, forgotten on sign-out
  and on a language change) and sends `If-None-Match`, so returning to an unchanged list costs one
  `304`.
- Seven operations had an `operationId` another operation already used, which made the generated
  API types fail to compile; they are now `get_booking_page`, `cancel_booking`,
  `get_meeting_report`, `list_channel_messages`, `mark_channel_read`,
  `register_push_subscription` and `start_mail_connection`. Paths and payloads are unchanged.
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
- `contact.reports_to` and `contact.dotted_line_ref` are engine-managed (D23-T4): a create or
  `PATCH /api/v1/contact/{id}` naming them is refused; set them with
  `PUT /api/v1/sales/contacts/{id}/manager`.
- `GET /api/v1/cobrowse/sessions/{id}/messages` and `GET /api/v1/cobrowse/visitor/messages` answer a
  `CursorPage` (`items`, `next_cursor`) instead of a bare array, and `GET /api/v1/me/mail-connections`
  a `PaginatedResponse`; the co-browse embed reads `items`.
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
