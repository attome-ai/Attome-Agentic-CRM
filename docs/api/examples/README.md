# API examples

Request and response examples that `web/scripts/generate-api-types.mjs` sets on the matching
operations of `openapi.json` every time it runs. They are captured from integration tests, not
written by hand (S2-T10):

```powershell
$env:ATTOME_CAPTURE_EXAMPLES = "$PWD\docs\api\examples"
cargo test -p attome-api --test calendar_v2 --test field_types_u9 -- --test-threads=1
cd web; npm run generate:api
```

A test's request helper calls `attome_testkit::examples::capture_example` (feature `examples`);
nothing is written unless `ATTOME_CAPTURE_EXAMPLES` is set. Each call becomes
`<METHOD>_<path>.json` holding `{method, uri, request, status, response}`, the first capture of a
path winning. Every value under a key that names a secret (password, secret, token, api_key,
cookie, authorization) is replaced with `<redacted>` before the file is written. The generator
matches a file to the path template with the most literal segments, and keeps the first example
of each operation and status.

Review a capture before committing it: test fixtures hold throwaway names and addresses, never
real people's.
