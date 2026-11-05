# Extension developer guide

How to write code that runs inside Attome, test it, and publish it, without changing Attome's own
code or rebuilding the server. One page per kind of extension:

| Kind | Runs when | Page |
|---|---|---|
| Record hook | a record is created or changed, at a stage you choose | [hooks.md](hooks.md) |
| Job | someone queues it, or on its own schedule | [jobs.md](jobs.md) |
| Webhook handler | another system calls one of the deployment's inbound hooks | [webhooks.md](webhooks.md) |

## First: do you need code?

Attome offers six levels of customisation, from no code to the server itself. Use the highest
level that does the job, because each level down costs more to write, review and keep working.

| Level | What you write | Where it runs |
|---|---|---|
| 1. Describe | A plain-language request to a building agent | The agent makes metadata |
| 2. Designers | Forms, flows, rules and dashboards, by hand | Metadata |
| 3. Expressions | Formulas, validations and conditions ([rule language](../../rule-language.md)) | The engine, sandboxed |
| 4. **Extensions** (this guide) | Hooks, jobs and webhook handlers | A WebAssembly sandbox in the server |
| 5. UI components | Web components placed on pages ([packages](../../packages.md)) | The browser |
| 6. Native engines | Whole modules in Rust against `attome-sdk` | The server process; needs a rebuild |

Write an extension when a rule needs logic an expression cannot hold, such as a calculation over
several fields with branches, a format check that needs a parser, or the translation of another
system's event into records. Do not write one to set a default, to require a field, or to hide a
field: a designer or an expression does that, and an administrator can read and change it without
a developer.

## What you need

- Rust with the WebAssembly target: `rustup target add wasm32-unknown-unknown`.
- The `attome` command, signed in to a development deployment:
  `attome login --target dev --url https://dev.example.com`.
- `cargo install cargo-audit`, for the dependency check `attome dev` runs before every upload.
- An administrator account on the deployment, or someone who can publish for you.

**TypeScript is not supported yet.** Each kind's page shows the logic in TypeScript, but a
TypeScript extension cannot be built or uploaded until the JavaScript runtime (Javy, roadmap
Y10-T7) ships; `attome new extension --lang ts` says so and stops. Until then, write the
extension in Rust. The TypeScript examples show the same logic, so that a team that knows
TypeScript can read the Rust beside it, and so the code can be moved over when the runtime ships.
Other languages that compile to WebAssembly may work but are not supported.

## Start, build, upload

```sh
attome new extension account_name_rules --kind hook   # or job, webhook
cd account_name_rules
cargo test                                            # the logic, natively, in milliseconds
attome dev . --once --target dev                      # build for WebAssembly, check, upload a draft
```

`attome new extension` writes a small Rust crate:

- `src/lib.rs` holds the extension. All of its logic is in one pure function, `decide`, which
  takes the input as JSON and returns the answer as JSON. Below `decide` is the calling convention,
  which you do not need to change.
- `manifest.json` lists what the extension may touch: its grants, plus a hook's stage or a job's
  schedule.
- `README.md` and `.gitignore`.

`attome dev .` without `--once` watches the folder. On every saved change it builds the crate for
`wasm32-unknown-unknown`, prints any compile errors with their source lines, checks the
dependencies, and uploads each good build as a new **draft** version. A draft runs only when you
test it; it never runs on real writes until it is published.

## The calling convention

An extension is a plain WebAssembly module that exports three things:

- `memory`.
- `alloc(len: i32) -> i32`, which returns a place where the server can write `len` bytes of input.
- The kind's entry point, `on_record` (hook), `on_job` (job) or `on_webhook` (webhook), shaped
  `(ptr: i32, len: i32) -> i64`. The server writes the input JSON at `ptr` and calls the entry
  point. The entry point returns the answer's place in the high 32 bits and its length in the low
  32 bits.

Every call runs in a fresh instance of the module, so nothing carries over from one run to the
next: no globals and no cache. Keep anything that must last in records.

The input and the answer are JSON. Each kind's page describes them.

## The host API

`crates/engine/attome-extension/wit/attome.wit` (package `attome:extension@0.1.0`) declares the
calls a module can make into the server:

| Interface | Calls | Notes |
|---|---|---|
| `records` | `get`, `update`, `create` | Through the record engine, with the access of the person the extension runs for. |
| `log` | `write(level, message)` | Kept with the run, in the run log. |
| `secrets` | `get(name)` | Granted secrets only; values are masked in every log. |
| `http` | `fetch(method, url, headers, body)` | Granted hosts only, and only after the transaction commits. |

**Today, modules do not call the host API.** An extension answers with the records it wants
written (`{"records": [...]}`) or the change it wants made (`{"change": {...}}`), and the server
makes those writes itself through the ordinary write path, held to the same grants. The server
does not yet link the imports above into a running hook. They exist so that tests can exercise
code written against them (see [Testing](#testing)), and they are the interface direct host calls
will use once they are linked.

## Grants

`manifest.json` declares everything the extension may reach. The extension can reach nothing else.

```json
{
  "entities": {
    "account": { "read": true, "write": true, "attributes": ["name", "website"] }
  },
  "secrets": ["erp_token"],
  "hosts": ["erp.example.com", ".example.net"],
  "hooks": [{ "entity": "account", "stage": "before_save", "order": 0 }],
  "messages": { "name_required": { "en": "A new account needs a name.", "ar": "يحتاج الحساب الجديد إلى اسم." } }
}
```

- `entities`: for each entity, whether the extension may read it, whether it may write it, and the
  attributes it may see and set. An extension sees only the attributes listed. A write that names
  any other attribute is refused, and so is the run.
- `secrets`: the names of the secrets it may read ([secrets](../../secrets.md)).
- `hosts`: the hosts it may call. A host is matched exactly, or with a leading `.` to cover a
  domain and its subdomains.
- `hooks`, `schedule` and `messages` are covered on each kind's page.

The server checks the manifest when the extension is uploaded, and refuses a manifest whose hook
names an entity the extension may not read.

## Limits

Every run is held to these limits by default:

| Limit | Default |
|---|---|
| Fuel (WebAssembly instructions, roughly) | 100,000,000 |
| Memory | 64 MiB |
| Time | 500 ms |
| Records a job or webhook may write in one run | 100 |
| Hooks that call hooks (a hook's own writes) | 8 levels |

When a run goes past any limit, it stops with a typed error. The server carries on. A hook that
fails refuses the write it was called for. A job that fails is not retried, because any writes it
made before the failure are kept. A webhook run that fails is retried with its event, up to five
attempts (see [webhooks](webhooks.md#duplicates-and-retries)), so its earlier writes may be made
again.

## Testing

From the fastest test to the closest to production:

1. **`cargo test`**: the generated crate keeps its logic in `decide`, so plain Rust unit tests call
   it with JSON and check the JSON it returns. `attome new extension` writes two to start with.
2. **`FakeHost`** (`attome_extension::FakeHost`): runs the host API in memory, with records, logs,
   secrets and stubbed HTTP, held to the same grants as the real host. Use it for code written
   against the host interfaces.
3. **Record and replay**: `attome_extension::Recorder` wraps a host and keeps every host call of a
   run, with its result, and masks every secret value. `Replayer` answers the same calls from that
   recording without reaching any record, secret or network, and lists where a changed extension's
   run differs. Record a real run once, then replay it in tests after each change.
4. **The test endpoint**: `POST /api/v1/admin/extensions/{name}/versions/{v}/test` with
   `{"samples": [{"stage", "entity", "values", ...}]}` (up to 50 samples) runs the version on each
   sample exactly as a write would, saves nothing, and returns each answer with the fuel and time it
   used. Drafts can be tested this way before they are published. The runs appear in the run log
   marked as test runs.
5. **Customer tests**: once a hook is published, a [customer test](../learn/README.md) that tries a
   write and expects a refusal or a value checks the hook end to end, and an upgrade rehearsal
   runs it again against the new release.

## Dependencies

Before each upload, `attome dev` checks the crate's `Cargo.lock` against the RustSec advisories
(`cargo audit`). It refuses to upload when any dependency has an advisory with a CVSS v3 score of
7.0 or more, or one with no score. There are two ways past a refusal:

- Update the dependency.
- Show that the flaw cannot be reached from the extension, and pass
  `--allow-advisory <ID>=<reason>` with a reason of at least 20 characters. The allowed advisory and
  its reason are printed on every upload.

Advisories with lower scores are printed but do not block the upload. If the check cannot run at
all, the upload is refused unless `--skip-audit <reason>` says why.

The WebAssembly sandbox blocks file, network and clock access whatever a library tries to do, so a
dependency can only do what the host API and the grants allow.

## Publishing

An upload (`attome dev`, or `POST /api/v1/admin/extensions` with
`{"name", "module_base64", "manifest"}`) adds the next version as a draft. Then:

| Step | Call |
|---|---|
| Test the draft | `POST /api/v1/admin/extensions/{name}/versions/{v}/test` |
| Publish it (it runs within five seconds) | `POST /api/v1/admin/extensions/{name}/versions/{v}/publish` |
| Roll back | Publish an older version the same way |
| Stop it everywhere, at once | `POST /api/v1/admin/extensions/{name}/off` |
| Read its runs | `GET /api/v1/admin/extensions/{name}/runs` |

Each run's log keeps the version that ran, the time, the fuel used, the result and the log lines,
with every granted secret masked.

The same module and manifest move between deployments like any other change. Upload the same build
to the test deployment, then to production, and publish it there. To ship an extension inside a
pack, see [packages](../../packages.md).

## Compatibility promise

Customer changes must survive Attome's upgrades (V2-D469). For extensions, that means:

- **What is stable**: the calling convention (`memory`, `alloc` and the kind's entry point), the
  JSON shape of each kind's input and answer as described on its page, and the manifest's fields.
  An upgrade keeps them working, or the upgrade's release notes say otherwise and give a year's
  overlap.
- **The host API is versioned with semver.** It is `attome:extension@0.1.0` today. While its major
  version is 0 it is not yet frozen: a change to it is listed in `CHANGELOG.md`, and a 0.x release
  may change it. From 1.0, a breaking change takes a new major version, and the previous major
  keeps working for at least a year alongside it.
- **What is checked**: an upgrade rehearsal (`attome release`, with `--customer-tests <dir>`) runs
  the customer's own tests against the new release, so a hook that stops working shows up before
  the upgrade reaches production. Keep a customer test for every rule a hook enforces.
- **What is not promised**: running past the limits, timing (a run that takes 400 ms today may take
  more or less after an upgrade), the order of hooks at the same stage with the same `order`, and
  anything not described in this guide.

## Not built yet

- Calls from a running module into the host API (reading other records, secrets, HTTP after the
  commit).
- TypeScript and JavaScript extensions (Javy, Y10-T7).
- A second person approving grants at publish.
- Custom actions, flow steps and computed attributes as extension kinds.
