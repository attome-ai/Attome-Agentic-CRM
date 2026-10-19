# Contributing to Attome

Thank you for helping. Bug reports, ideas, translations, documentation and code are all welcome.

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems never go in a
public issue, discussion or pull request: follow [`SECURITY.md`](SECURITY.md). This guide in Arabic is
[`CONTRIBUTING.ar.md`](CONTRIBUTING.ar.md).

## Before you write code

- **Bugs**: open an issue with what you expected, what happened and how to reproduce it (version or
  commit, operating system, the request and response if it is an API problem).
- **Features and larger changes**: open an issue first and describe the problem you want solved. A
  change that alters the public API, the database schema or a security control is discussed before it
  is written, so neither of us spends time on a pull request that cannot be merged.
- **Packs** (a sector or module built from metadata): use the pack proposal template.
- **Small fixes** (a typo, a clear bug with an obvious fix, a missing translation) can go straight to a
  pull request.

Issues use the templates in [`.github/ISSUE_TEMPLATE`](.github/ISSUE_TEMPLATE) (bug, feature, pack) and
pull requests the [pull request template](.github/pull_request_template.md).

## The contributor licence agreement

Every contribution comes under the [Attome Contributor Licence Agreement](CLA.md). You keep the
copyright in your work; the agreement lets Attome stay AGPL-3.0 and also be offered under a commercial
licence. On your first pull request the CLA check posts a comment; reply with the sentence it gives and
the check passes for that and every later pull request. If you contribute for your employer, section 6
of the agreement says how the organisation accepts it.

A pull request cannot be merged until its CLA check is green.

## Building

You need Rust 1.97 (pinned in `rust-toolchain.toml`) on Windows or Linux, PostgreSQL 18 with
`pgvector` for the database tests, and Node 22 for the web application. Attome must build and run
natively on both Windows and Linux: do not add a dependency that works on only one of them.

```sh
cargo build -p attome                 # the server and command-line tool
cd web && npm ci && npm run build:all # the web application: libraries first, then the app
```

[`README.md`](README.md) has how to install and run a local server.

## Testing

```sh
attome test --changed                 # unit tests of the crates and web libraries you touched
attome test --tier db --changed       # their database tests, against a throwaway PostgreSQL
```

Point `DATABASE_URL` at a throwaway PostgreSQL server, never a database you care about: the database
tests create and drop their own databases. [`docs/testing.md`](docs/testing.md) explains the tiers and
how to tag a test.

Before you open a pull request, run the full release gate on your operating system:

```sh
cargo run -p attome-release --target-dir target/gate -- --check
```

It runs formatting, clippy with warnings as errors, the tests and the API contract checks. A pull
request whose gate is not green is not reviewed. Add `--web` when you changed the web application.

## Writing the change

- Keep a pull request to one change. Refactoring, formatting and the change itself go in separate pull
  requests.
- Add or update tests: a fixed bug gets a test that failed before the fix, and a security-sensitive
  change gets a test of the refused path.
- User-visible text goes in both the English and the Arabic catalogue; never hard-code it. Layouts use
  logical CSS properties (`margin-inline-start`, not `margin-left`) so right-to-left works.
- A route or wire type change regenerates `openapi.json` and the web API types; a breaking API change
  is named under `### Breaking` in [`CHANGELOG.md`](CHANGELOG.md), and every user-visible change gets a
  CHANGELOG line.
- Never commit a secret, a real customer's data or a deployment's configuration.

## Opening the pull request

- Describe what changed and why, and link the issue.
- Say how you tested it, including the gate result.
- Mark anything you are unsure about. Small, focused pull requests are reviewed first.

A maintainer reviews it, may ask for changes, and merges it once the gate and the CLA check are green.

## Labels

Every issue gets one `type:` label and one `status:` label, and `area:` and the others as they apply. The
full list is [`.github/labels.yml`](.github/labels.yml). Issues labelled `good first issue` are a good
place to start.
