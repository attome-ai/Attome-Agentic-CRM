# Extension guide

How to add to Attome without changing its code, so the addition survives upgrades.

## Packs

A pack is a folder under `packs/<name>/changesets/`: numbered changeset files
(`attome-changeset/v1`) that create entities, fields, forms, roles, rules, menus and sample data.
Install one with `attome init --pack <name>`, or name it in `app.packs` in `config.json`; it is
applied at every start through the changeset ledger, so an unchanged pack changes nothing. A pack
that builds on another says so in its changesets' `requires`. `packs/README.md` lists the shipped
packs.

To make one: build the change in a development deployment through the admin screens, export it as a
changeset (`/api/v1/admin/changesets/{id}/export`), and add the file to the pack's folder with the
next number. Each changeset carries a checksum; `node scripts/changesets/reseal.mjs <file>` updates
it after an edit.

## Agents and AI tools

Agents are model objects (`/api/v1/admin/model/agent`): instructions, the tools (actions) they may
use, limits and channels. Every agent write goes through a person's approval; consequential ones need
a second person. Outside tools come from MCP servers (`/api/v1/admin/mcp-servers`). See
[agents](../agents.md).

## Integrations

- **Webhooks and event subscriptions** (`/api/v1/admin/events`) send record changes to another
  system, retried and with a dead-letter list.
- **Server-to-server clients** (`/api/v1/admin/s2s`) sign their calls with HMAC and get only the
  permissions they are given.
- **Connectors** (`/api/v1/admin/integrations`) hold an outside system's credentials, encrypted.

## Web forms on another site

A public service offering can take requests from a form on the customer's own website:
`/embed/service-intake.js` puts the form in a shadow root. It is off until the offering is listed in
the `service.anonymous_intake.offerings` setting and `service.anonymous_intake.user` names the
service account requests are filed as; the website's origin goes in `cors.allowed_origins`.

## Branding and text

Themes (`/api/v1/admin/themes`) set colours, fonts and logos per deployment or business unit; the
built-in wording can be changed per language (`/api/v1/admin/i18n/overrides`) without touching the
code.

## Code extensions (WebAssembly), in progress

Custom code runs as WebAssembly on Wasmtime inside the server (Y10, V2-D125), in the crate
`attome-extension`. What exists today:

- **Limits.** Every call runs in a fresh sandbox with a fuel budget (100,000,000 units), 64 MiB of
  memory and a 500 ms time limit by default; past any of them it stops with a typed error, and the
  server goes on.
- **Host API.** `crates/engine/attome-extension/wit/attome.wit`: records (read, update, create)
  through the record engine with the caller's own access, logs, granted secrets, and HTTP after the
  transaction commits.
- **Grants.** A manifest declares the entities (and attributes), secrets and hosts the extension may
  use; nothing else is reachable.
- **Testing.** `attome_extension::FakeHost` runs the host API in memory (records, logs, secrets,
  stubbed HTTP), held to the same grants, for an extension's unit tests.
- **Job and webhook extensions.** Besides hooks, a module can export `on_job` (run as a job queued
  with `POST /api/v1/admin/extensions/{name}/jobs`, as the caller) or `on_webhook` (an inbound hook's
  handler `{"type": "extension", "name": ...}`, run after the hook's signature checks, as the hook's
  user). It answers `"continue"` or `{"records": [{"entity", "id"?, "values"}]}`; each write must be
  granted and is made through the ordinary write path, at most 100 per run. A failed run is not
  retried, because writes made before the failure stay.
  A job extension can also run by itself: `"schedule": {"cron": "0 6 * * *", "timezone":
  "Asia/Riyadh", "input": {...}}` in its manifest (checked at upload) runs it once per slot across
  every worker, as the administrator who uploaded the published version.
- **Developing.** `attome dev <folder>` watches a Rust extension crate (with its `manifest.json`),
  builds it for `wasm32-unknown-unknown` on every change, prints cargo's errors with their source
  lines, and uploads each good build as a new draft version (`--once` builds one time; `--target`
  or `--url` names the deployment). JavaScript extensions are not supported yet.
- **Record and replay.** `attome_extension::Recorder` wraps a host and keeps every host call of a
  run with its result, every secret value masked; `Replayer` answers the same calls from that
  recording, reaching no record, secret or network, and lists where a changed extension's run
  differs.

- **Record hooks.** The record write path calls registered hooks at four stages: before
  validation, before save (a hook may change the values or reject the write), after save (in the
  transaction) and after commit (in a job, with the stored row). A hook that writes records runs
  hooks again, at most eight levels deep. In a bulk operation or an import, the after-commit hooks
  get the writes in batches of up to 500 records of one entity per call (each write's payload is
  kept with it in its transaction and delivered at least once).
- **Extensions as hooks.** A manifest lists the writes an extension runs on, for example
  `"hooks": [{"entity": "account", "stage": "before_save", "order": 0}]`; each hook needs a read
  grant on its entity. The module exports `memory`, `alloc(len) -> ptr` and
  `on_record(ptr, len) -> i64`: the server writes the write as JSON (`stage`, `entity`,
  `record_id`, `is_create`, `values`, `previous`, `actor`; only the attributes the extension may
  read) at the pointer `alloc` answers, and `on_record` answers its output's pointer in the high 32
  bits and its length in the low 32. The output is `"continue"`, `{"change": {...}}` (before
  stages only; every attribute must be granted for writing) or `{"reject": "message"}`. To
  refuse in the caller's language, the manifest declares `"messages": {"<key>": {"en": "...",
  "ar": "..."}}` (English required; `{name}` placeholders) and the hook answers
  `{"reject": {"key": "<key>", "args": {"name": ...}}}`: a caller sending `Accept-Language: ar`
  reads the Arabic text, everyone else the English. An
  extension that fails refuses the write. A newly published version runs within five seconds;
  switching one off takes effect at once.
- **Form hooks.** An extension can also answer a record form while someone works in it: stage
  `form_load` (the form opened a record or a new one) or `form_change` (a value changed). The form
  calls `POST /api/v1/{entity}/form-hooks` with `{"event": "load" | "change" | "before_save",
  "record_id", "values", "previous"}`; the server runs the matching extensions on those values
  exactly as it runs record hooks (same input, grants and limits; customer code never runs in the
  browser) and answers `{"changes", "rejection", "rejection_translations", "events"}`. A `change`
  fills values in the form and a `reject` shows its message; nothing is saved. `before_save` runs
  the write's own `before_validation` and `before_save` hooks ahead of the save, so a refusal shows
  before the person saves; the save runs them again. `events` names the form events with an
  extension on the entity, so the form calls only those (a change after a 400 ms pause). The caller
  needs read access to the entity's records.
- **Versions.** `POST /api/v1/admin/extensions` uploads a module and its manifest as the next
  version; `.../{name}/versions/{v}/publish` makes one version live (publishing an older one rolls
  back) and `.../{name}/off` stops every version.
- **Run logs.** Each run is kept with its version, time, fuel used, result and log lines, every
  granted secret masked: `GET /api/v1/admin/extensions/{name}/runs`.
- **Testing a version.** `POST /api/v1/admin/extensions/{name}/versions/{v}/test` with
  `{"samples": [{"stage", "entity", "values", ...}]}` (up to 50) runs the version's hook on each
  sample exactly as a write would, saves nothing, and answers each answer with its fuel and time;
  the runs are logged as test runs. Drafts can be tested before they are published.

Not yet: the host API calls from inside a hook (reading other records, secrets, HTTP after the
commit), JavaScript extensions, and approving grants at publish by a second person.

