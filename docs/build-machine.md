# Work owed to a machine that builds

Code is written on a machine that does not build; GitHub Actions compiles, lints and tests every
push. A few jobs need a local build or a local tool and wait here until a machine that builds runs
them. Each entry says what to run and what to commit. Delete an entry once it is done.

## Regenerate the API contract

New or changed routes since the last regeneration: the metadata model admin API
(`/api/v1/admin/model/...`, roadmap Y1-T9, including `.../publish`), its file export and import
(`GET /api/v1/admin/model/export`, `POST /api/v1/admin/model/import`, Y1-T10), and the form render
plan (`GET /api/v1/model/forms/{id}/plan`, now with an `If-None-Match` header and a 304, Y14-T2),
and the live channel (`GET /api/v1/live`, Y14-T3).

```sh
cd web
npm ci
npm run generate:api      # builds `attome serve --print-openapi`
```

Commit `openapi.json` and both `api-types.ts` files. Then run
`cargo test -p attome --test audit_coverage_emission --test route_authz` so the new mutating routes
(`POST /api/v1/admin/model/{kind}/{id}/commands`, `.../publish` and `/api/v1/admin/model/import`)
are covered by the audit and authorization suites,
which read the committed `openapi.json`.

## Build pgvector for Windows

`scripts/install.ps1` needs an existing PostgreSQL 18 with pgvector because pgvector publishes no
Windows build (V2-D486). On a Windows machine with Visual Studio's C++ tools and PostgreSQL 18:

```bat
git clone --branch v0.8.1 https://github.com/pgvector/pgvector.git
cd pgvector
set "PGROOT=C:\Program Files\PostgreSQL8"
nmake /F Makefile.win
nmake /F Makefile.win install
```

Then add those steps to `.github/workflows/release.yml`'s Windows job, ship `vector.dll` and the
extension's control and SQL files in the archive, and let `install.ps1` install PostgreSQL 18 and
copy them in when no `-DatabaseUrl` is given.

## Run the auth fuzz targets

`crates/foundation/attome-auth/fuzz` is its own workspace (nightly toolchain, libFuzzer), so no
gate runs it. Z4-T11 added two targets; run each for a minute on Linux or WSL and keep the corpus:

```sh
cd crates/foundation/attome-auth/fuzz
cargo +nightly fuzz run fuzz_jwks_eddsa_token -- -max_total_time=60
cargo +nightly fuzz run fuzz_otp_verify_normalise -- -max_total_time=60
```

The fuzz crate's own `Cargo.lock` predates `ed25519-dalek` in attome-auth; the first run updates it.
Commit the updated lock with the corpus.
