# Y3-T1: the SQL gateway, written and not yet wired

`attome-sqlgateway` (the crate's `src/lib.rs`) is written but not a workspace member, so nothing builds
it yet: code first, the build and tests in the testing phase (owner, 2026-11-05). To wire it, from the
repository root:

1. `cp crates/engine/attome-sqlgateway/pending/config_section_sql_gateway.rs crates/foundation/attome-config/src/config/sections/sql_gateway.rs`
2. `python crates/engine/attome-sqlgateway/pending/wire.py`: the `sql_gateway` config section and its
   boot check, the `config.example.json` block, the workspace member and dependencies (`pgwire` with
   ring features only), the testapp and binary dependencies, `attome_server::middleware::auth::authenticate_api_key`,
   and the start-up in `crates/apps/attome/src/serve.rs`.
3. `python crates/engine/attome-sqlgateway/pending/intake.py`: the twelve new crates in
   `docs/dependencies/intake.json` (licences checked against `deny.toml`).
4. `mv crates/engine/attome-sqlgateway/pending/sql_gateway.rs crates/engine/attome-testapp/tests/`
   and `mv crates/engine/attome-sqlgateway/pending/docs/sql-gateway.md docs/`; link it from
   `docs/README.md` beside "SQL reports"; add the CHANGELOG line (Added: the SQL gateway, off by
   default, loopback only, simple and extended protocol, no bound parameters yet).
5. Regenerate `config.schema.json` and `docs/config-reference.md`
   (`ATTOME_WRITE_CONFIG_SCHEMA=1 cargo test -p attome-config --test config_schema`).
6. Owed runs: `cargo clippy -p attome-sqlgateway -p attome-config -p attome-server -p attome --all-targets -- -D warnings`,
   `cargo test -p attome-sqlgateway --lib`, `cargo test -p attome-config --lib sql_gateway`,
   `cargo test -p attome-testapp --test sql_gateway -- --test-threads=1`, `cargo deny check`.

Then delete this folder.
