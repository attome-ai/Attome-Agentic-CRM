# Attome SDKs for Python, C# and Java

The TypeScript SDK is `web/projects/sdk` (`@attome/sdk`). The Python, C# and Java SDKs are generated
from `openapi.json` by [OpenAPI Generator](https://openapi-generator.tech) (Apache-2.0) and carry a
small hand-written layer each. Nothing generated is committed: `sdks/build/` is rebuilt every time.

## What they cover

`sdks/config.json` names the operations: the record API every deployment has (list, read, create,
change and delete records of any entity) and `POST /api/v1/query/execute`. Entity fields come from
each deployment's metadata (`GET /api/v1/schema/{entity}`), so a record's `data` is a map. More areas
are added by naming their operations in `config.json`.

`sdks/subset.mjs` cuts those operations and every schema they use out of `openapi.json` and writes
`sdks/build/attome-sdk.json` as OpenAPI 3.0.3, which every generator language supports in full
(`openapi.json` is 3.1: nullable type lists, `const` and `examples` are rewritten). It also fills two
gaps of the generic record routes, whose bodies the server resolves from runtime metadata and so does
not declare: create and update take an object body, and update takes the `If-Match` header it
requires.

## Attome's layer

| | Python | C# | Java |
|---|---|---|---|
| class | `attome_sdk.client.AttomeClient` | `Attome.Sdk.AttomeClient` | `io.attome.sdk.AttomeClient` |
| auth | `Authorization: ApiKey <public_key>:<secret>` | same | same |
| retries | 429, 502, 503, 504; `Retry-After` honoured | same (a `DelegatingHandler`) | same |
| idempotency | one `x-idempotency-key` per write, kept on its retries | per request, kept on its retries | per write, kept on its retries |
| paging | `records()` follows `next_cursor` | `Records()` | `records()` |
| optimistic concurrency | `update(entity, id, row_version, fields)` sends `If-Match` | `UpdateAsync` | `update` |

The generated API classes (`EntityApi`, `QueryApi`) stay available for everything else.

## Build and test

`.github/workflows/sdk-check.yml` runs, per language: the subset, the generator (Docker image
`openapitools/openapi-generator-cli`), the build, and the smoke test in `sdks/<language>/` against a
[Prism](https://github.com/stoplightio/prism) mock of `attome-sdk.json`. Prism refuses a request the
document does not allow (no API key, a PATCH without `If-Match`), so a pass means each SDK sends what
the API declares and reads what it answers. By hand, with Node, Docker and the language's toolchain:

```bash
node sdks/subset.mjs
docker run --rm -v "$PWD:/local" openapitools/openapi-generator-cli:v7.10.0 generate \
  -i /local/sdks/build/attome-sdk.json -o /local/sdks/build/python -g python --package-name attome_sdk
cp sdks/python/client.py sdks/build/python/attome_sdk/client.py && pip install ./sdks/build/python
npx @stoplight/prism-cli@5.12.0 mock -p 4010 sdks/build/attome-sdk.json &
python sdks/python/smoke.py http://127.0.0.1:4010
```

The C# and Java steps are the workflow's.
