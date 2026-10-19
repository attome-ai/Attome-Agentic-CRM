# Attome: the agentic CRM

**Describe it, or build it yourself. Agents build it and run it. You see and approve everything.**

Attome is an open-source CRM designed for agents first. Agents build the CRM (entities, forms, flows,
rules, dashboards), operate it (triage, follow-up, updates) and look after it (data quality, access
reviews, cost), while people describe, review and approve. Anything an agent can do, a person can do,
through the same API and the same permissions.

> **Status: early development.** This repository is being built in the open. It runs, but it is not
> ready for production use, and there is no packaged release yet.

## Principles

- **Agentic**: every capability is an API operation, an agent tool (MCP) and a screen at the same time.
- **Visible**: every flow, agent action and rule can be seen as a graph, watched live and replayed; every
  number traces back to its records.
- **Customizable**: customers change the data model, forms, flows and logic without forking, and their
  changes survive upgrades.
- **Efficient**: a native Rust server on PostgreSQL, no per-user fees, local AI models by default.
- **Safe**: drafts, previews, approvals and one-step rollback for every structural change.
- **Secure**: an agent never has more access than the person it acts for; one database per customer;
  a tamper-evident audit trail.
- **Arabic and English** throughout, right-to-left built in.

## Repository layout

| Path | What lives there |
|---|---|
| `crates/foundation/` | Generic building blocks (config, database, cache, auth, jobs, storage). |
| `crates/engine/` | The CRM engine: metadata, runtime, security, audit, agents. |
| `crates/sdk/` | `attome-sdk`, the stable SDK every engine and pack is written against. |
| `crates/packs/` | Built-in modules (Sales, Service, …) written on the SDK. |
| `crates/apps/` | The `attome` server and command-line tool. |
| `web/` | The web application. |
| `packs/` | Pack metadata: changesets, layouts, sample data. |
| `docs/` | Documentation; `docs/roadmap-paths.md` maps the roadmap's v1 paths to this tree, and `docs/versions-and-support.md` says how long a release is supported. |

Dependencies point one way: foundation → engine → sdk → packs → apps. See
[`docs/architecture.md`](docs/architecture.md).

## Installing

One command installs a release as a service. On Linux it also installs PostgreSQL 18 with pgvector
when you give no database:

```sh
curl -fsSL https://raw.githubusercontent.com/attome-ai/Attome-Agentic-CRM/main/scripts/install.sh \
  | sudo sh -s -- --admin you@example.com
```

On Windows (an elevated PowerShell), against an existing PostgreSQL 18 database with the `vector`,
`pg_trgm` and `pgcrypto` extensions created:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/attome-ai/Attome-Agentic-CRM/main/scripts/install.ps1))) `
    -DatabaseUrl 'postgres://attome_owner:secret@127.0.0.1:5432/attome' -Admin you@example.com
```

Either way the server and the web app answer on `http://localhost:7865/`; sign in with the one-time
password the install prints.

Both install the `crm` pack (accounts, contacts, leads, opportunities and activities); choose others
with `--packs crm,sales` (Linux) or `-Packs crm,sales` (Windows), or none with an empty list. A pack
is applied at every start through the changeset ledger, so starting again changes nothing.
`packs/README.md` lists the packs, including `library-core` (the MENA base entities).

## Agents and AI

AI is optional and local by default: run the model servers in
[`docs/model-servers.md`](docs/model-servers.md), approve the model, and the assistant, record
summaries, translation, AI fields and agents switch on. [`docs/agents.md`](docs/agents.md) covers
defining agents, what they may do (writes always need a person; consequential ones a second person),
their tools, delegation between agents, money budgets and the safety checks around the model.

## Building and running

Rust 1.97 (pinned in `rust-toolchain.toml`) on Windows or Linux, and PostgreSQL 18 with the `pgvector`
extension. Nothing else: a single server (Solo) keeps its caches, rate limits and coordination in
process memory instead of Redis ([`docs/solo-memory-backend.md`](docs/solo-memory-backend.md)).

```sh
cargo build --release -p attome

# Install Solo on an existing, empty PostgreSQL database: writes config.json with fresh secrets
# and applies the schema.
attome init --database-url postgres://postgres:secret@localhost:5432/attome

attome serve --bootstrap-admin you@example.com   # once: creates the first admin, prints its password
attome serve                                      # the server, on port 7865
```

To start it with the machine, install it as a service from the directory that holds its
`config.json` (an elevated prompt on Windows, root on Linux):

```sh
attome init --database-url postgres://postgres:secret@localhost:5432/attome --out /var/lib/attome/config.json
attome service install --dir /var/lib/attome     # a Windows service, or a systemd unit on Linux
attome service install --dry-run                  # print the steps only
```

`attome sovereignty report` lists where copies of the data live and every outside destination the
configuration names; `deployment.sovereign = true` in `config.json` refuses any outside destination
at boot.

`attome help` lists the other commands (`worker`, `migrate`, `preflight`, `healthcheck`, and the
audit tools).

The release gate, the same one CI runs on Windows and Linux:

```sh
cargo run -p attome-release --target-dir target/gate -- --check   # format, clippy (warnings are errors), tests
```

`attome test` runs the tests a change needs ([docs/testing.md](docs/testing.md)). Tests that need
PostgreSQL, Redis or an object store skip without them; point `DATABASE_URL` at a
throwaway PostgreSQL server (never a real database) to run them.

The web application (Node 22):

```sh
cd web
npm ci
npm run build:all   # libraries first, then the app
npm start           # development server on port 4199
```

## Licence

Attome is free software, licensed under the **GNU Affero General Public License v3.0 only**
(`AGPL-3.0-only`); see [`LICENSE`](LICENSE). Copyright © 2026 Automatica Tech Solutions.

A **commercial licence** is available for organisations that cannot meet the AGPL's terms, for example
to embed Attome in a closed product or to offer it as a closed service. Contact us through
[attome.com](https://attome.com).

## Contributing and security

Contributions are welcome under the [contributor licence agreement](CLA.md);
[`CONTRIBUTING.md`](CONTRIBUTING.md) says how to build, test and open a pull request. Report security
problems privately as described in [`SECURITY.md`](SECURITY.md).
