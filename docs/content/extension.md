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
- **Record and replay.** `attome_extension::Recorder` wraps a host and keeps every host call of a
  run with its result, every secret value masked; `Replayer` answers the same calls from that
  recording, reaching no record, secret or network, and lists where a changed extension's run
  differs.

- **Record hooks.** The record write path calls registered hooks at four stages: before
  validation, before save (a hook may change the values or reject the write), after save (in the
  transaction) and after commit (in a job, with the stored row). A hook that writes records runs
  hooks again, at most eight levels deep.
- **Extensions as hooks.** A manifest lists the writes an extension runs on, for example
  `"hooks": [{"entity": "account", "stage": "before_save", "order": 0}]`; each hook needs a read
  grant on its entity. The module exports `memory`, `alloc(len) -> ptr` and
  `on_record(ptr, len) -> i64`: the server writes the write as JSON (`stage`, `entity`,
  `record_id`, `is_create`, `values`, `previous`, `actor`; only the attributes the extension may
  read) at the pointer `alloc` answers, and `on_record` answers its output's pointer in the high 32
  bits and its length in the low 32. The output is `"continue"`, `{"change": {...}}` (before
  stages only; every attribute must be granted for writing) or `{"reject": "message"}`. An
  extension that fails refuses the write. A newly published version runs within five seconds;
  switching one off takes effect at once.
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

