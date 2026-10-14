# Work owed to a machine that builds

Code is written on a machine that does not build; GitHub Actions compiles, lints and tests every
push. A few jobs need a local build or a local tool and wait here until a machine that builds runs
them. Each entry says what to run and what to commit. Delete an entry once it is done.

## Regenerate the API contract

New or changed routes since the last regeneration: the metadata model admin API
(`/api/v1/admin/model/...`, roadmap Y1-T9).

```sh
cd web
npm ci
npm run generate:api      # builds `attome serve --print-openapi`
```

Commit `openapi.json` and both `api-types.ts` files. Then run
`cargo test -p attome --test audit_coverage_emission --test route_authz` so the new mutating route
(`POST /api/v1/admin/model/{kind}/{id}/commands`) is covered by the audit and authorization suites,
which read the committed `openapi.json`.
