# Changelog

Every release lists what changed for administrators, users and developers. A breaking change to
`/api/v1` (a removed or renamed route, a removed response status or field, a newly required request
field, a changed type) is named under `### Breaking` in the `[Unreleased]` section in the same change
that makes it; the release gate's contract step refuses a release that breaks the API silently.

## [Unreleased]

### Security
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
