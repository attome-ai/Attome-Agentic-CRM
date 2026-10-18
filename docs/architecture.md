# Architecture

Attome is **one Rust binary on PostgreSQL**. This page is the short map; each part gets its own page as
it is built.

## The shape

- **Metadata.** Everything a customer can build is metadata: entities, attributes, forms, views, flows,
  rules, roles, agents and apps. Entity records live in real PostgreSQL tables with native types.
- **Changesets and versions.** Metadata changes only through changesets, drafted in Develop mode (a
  draft workspace inside the same database), and goes live by publishing a numbered version through a
  visible pipeline: validate, test, impact report, approve, apply online, watch, roll back if needed.
- **Cooking.** Publishing compiles metadata into immutable, content-hashed artefacts: render plans, rule
  bundles, permission masks, query plans and a compact schema digest for agents. The request path serves
  from these, never from raw metadata.
- **One operation registry.** Every capability is one operation. The REST API, the MCP tools agents use,
  screen actions, the SDKs and the OpenAPI document are generated from it, so agents and people always
  have the same capabilities and the same permission checks.
- **One behaviour runtime.** Flows, agent plans, record hooks, rules and integrations are one kind of
  graph, run by one runtime that logs every step, so any run can be watched live and replayed.
- **Change feed.** A transactional outbox in PostgreSQL drives cache invalidation, aggregates, webhooks,
  record provenance and live updates in the browser.
- **One renderer.** The web app draws every form, view, dashboard and page from cooked render plans;
  the designer is the same renderer in edit mode, with people and agents editing together.

## Deployment

The same binary runs every size, chosen by configuration: **Solo** (the binary and PostgreSQL only),
Team, High availability, Scale and Hyperscale. It runs natively on Windows and Linux; Docker and
Kubernetes are optional. Each customer has its own deployment and its own database.

## Code layout and layers

| Layer | Folder | Depends on |
|---|---|---|
| Foundation | `crates/foundation/` | nothing in this repository |
| Engine | `crates/engine/` | foundation |
| SDK | `crates/sdk/` | foundation, engine |
| Packs | `crates/packs/` | the SDK only |
| Apps | `crates/apps/` | everything below |

Dependencies never point back up the table. Crates are named `attome-<name>`. Built-in packs use the
same SDK that customers' own engines use.

The metadata model is `crates/engine/attome-model`: one store (`metadata_object` and its versions) for
every kind, the kind registry, the one edit path, validation and the cooker that writes content-hashed
artefacts. Entity and attribute kinds are adapters over their typed tables, and the request path reads
cooked artefacts, never the store. Administrators reach it under `/api/v1/admin/model`.
`crates/engine/attome-metadata` provisions entity tables from that metadata.

## Customising, from no code to Rust

1. Describe it to a building agent.
2. Use the designers.
3. Write expressions (one expression language, run identically in browser and server).
4. Write extensions: WebAssembly components (Rust or TypeScript) in a sandbox, uploaded without a rebuild.
5. Write UI components: standard Web Components placed by metadata.
6. Write native engines: Rust crates against `attome-sdk`, built into a custom server.
7. Change the core: the code is open (AGPL-3.0-only).

## Release gate

`attome release --check` runs formatting, clippy (warnings are errors) and the tests, the same way on
Windows and Linux. A change is ready only when it passes.
