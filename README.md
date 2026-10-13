# Attome: the agentic CRM

**Describe it, or build it yourself. Agents build it and run it. You see and approve everything.**

Attome is an open-source CRM designed for agents first. Agents build the CRM (entities, forms, flows,
rules, dashboards), operate it (triage, follow-up, updates) and look after it (data quality, access
reviews, cost), while people describe, review and approve. Anything an agent can do, a person can do,
through the same API and the same permissions.

> **Status: early development.** This repository is being built in the open. It is not ready for use
> yet: there is no installable release.

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
| `docs/` | Documentation. |

Dependencies point one way: foundation → engine → sdk → packs → apps. See
[`docs/architecture.md`](docs/architecture.md).

## Building

Rust 1.97 (pinned in `rust-toolchain.toml`) on Windows or Linux:

```sh
cargo build --workspace
cargo run -p attome -- release --check   # the release gate: format, clippy, tests
```

## Licence

Attome is free software, licensed under the **GNU Affero General Public License v3.0 only**
(`AGPL-3.0-only`); see [`LICENSE`](LICENSE). Copyright © 2026 Automatica Tech Solutions.

A **commercial licence** is available for organisations that cannot meet the AGPL's terms, for example
to embed Attome in a closed product or to offer it as a closed service. Contact us through
[attome.com](https://attome.com).

## Contributing and security

Outside contributions are not accepted yet; see [`CONTRIBUTING.md`](CONTRIBUTING.md). Bug reports and
ideas are welcome as issues. Report security problems privately as described in
[`SECURITY.md`](SECURITY.md).
