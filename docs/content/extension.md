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

- **Record hooks.** The record write path calls registered hooks at three stages: before
  validation, before save (a hook may change the values or reject the write) and after save. A hook
  that writes records runs hooks again, at most eight levels deep.
- **Versions.** `POST /api/v1/admin/extensions` uploads a module and its manifest as the next
  version; `.../{name}/versions/{v}/publish` makes one version live (publishing an older one rolls
  back) and `.../{name}/off` stops every version.
- **Run logs.** Each run is kept with its version, time, fuel used, result and log lines, every
  granted secret masked: `GET /api/v1/admin/extensions/{name}/runs`.

Not yet: wiring published extensions into the hook stages, and approving grants at publish. Until
then, extend behaviour through rules, flows and packs.

