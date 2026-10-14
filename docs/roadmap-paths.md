# Reading the roadmap in this repository

The v2 roadmap's task plans (`document_v2/roadmap/<ID>.json` in the archive repository) were written
against v1's tree. Every crate, table and path they name has a v2 home; translate with the tables
below (V2-D481..D483). A task whose target has no row here, or that names something this repository
no longer has (licences, seats, trading, bundles as a format), stops for a decision instead of a
guess.

## Folders and crates

| v1 path | v2 path |
|---|---|
| `crates/base/base-<name>` | `crates/foundation/attome-<name>` |
| `crates/xrm/xrm-foundation` | `crates/engine/attome-core` |
| `crates/xrm/xrm-entity` | `crates/engine/attome-metadata` |
| `crates/xrm/xrm-entity-engine` | `crates/engine/attome-records` |
| `crates/xrm/xrm-metadata` (new in Y1: the metadata model) | `crates/engine/attome-model` (`attome-metadata` is the ported xrm-entity) |
| `crates/xrm/xrm-server` | `crates/engine/attome-api` |
| `crates/xrm/xrm-license` | `crates/engine/attome-modules` (module switches only) |
| `crates/xrm/xrm-<name>` (every other engine) | `crates/engine/attome-<name>` |
| `crates/server/src/` (main, boot, jobs, auth, seeds) | `crates/apps/attome/src/` (`main.rs` is `serve.rs`) |
| `crates/server/src/bin/<tool>.rs` | `crates/apps/attome/src/cmd/<tool>.rs` (`attome <tool>`) |
| `crates/server/migrations/` | `crates/apps/attome/migrations/` |
| `crates/server/tests/` | `crates/apps/attome/tests/` |
| `angular/` | `web/` |
| `platform-bundles/`, `changesets/platform/` | the same paths (bundles convert to pack changesets) |
| `verticals/<name>/` | `packs/<name>/changesets/` |
| `crates/trd/` | gone (the trading engine is its own product) |

Rust paths follow the crates: `base_db::` is `attome_db::`, `xrm_foundation::` is `attome_core::`,
`xrm_entity_engine::` is `attome_records::`, and so on. `XrmState`, `XrmSystem`, `XrmModel` are
`EngineState`, `EngineSystem`, `EngineModel`.

## Tables and entities

Drop `xrm_`, then a leading `core_`: `xrm_core_entity_info` is `entity_info`, `xrm_service_ticket`
is `service_ticket`, `xrm_audit_header` is `audit_header`. The user entity is attome-auth's
`user_account` (`xrm_core_systemuser*` is `user_account*`), `xrm_case` is `support_case`, and the
infrastructure tables lost their `base_` prefix (`base_refresh_token` is `refresh_token`). Entity
system columns are `created_at`, `created_by`, `modified_at`, `modified_by`.

## Things that changed shape

- **Jobs.** `PlatformJob` is `attome_core::jobs::EngineJob`; `attome-jobs` is generic over the `Job`
  trait. `AppState` carries no queue handle: enqueue with `attome_jobs::enqueue_in_tx`,
  `enqueue_dedup` or `enqueue_on_pool`. Queues are `attome_job` and `attome_job_batch`.
- **Licences** are gone: `state.license` is `state.modules`, an `attome_modules::ModuleSet`.
- **Migrations** start again at `0001`; the next number is the next free one in
  `crates/apps/attome/migrations/`, with its line in `checksums.sha256` (`sha256sum --text`).
- **Redis** is behind `attome_cache::Store` (Redis or in-process memory, `docs/solo-memory-backend.md`).
- **The gate** is `cargo run -p attome-release -- --check`; CI runs it on Windows and Linux.
