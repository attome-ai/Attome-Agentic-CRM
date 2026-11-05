# Jobs

A job extension runs when someone queues it, or by itself on a schedule. It answers the records it
wants written, and the server writes them through the ordinary write path, so each write is
checked against access, validated by the business rules and audited. Read the
[guide's overview](README.md) first for the grants, limits and publishing steps.

## Start

```sh
attome new extension account_website --kind job
```

`manifest.json`:

```json
{
  "entities": { "account": { "read": true, "write": true, "attributes": ["website"] } }
}
```

## Running it

- **On demand**: `POST /api/v1/admin/extensions/{name}/jobs` with `{"input": {...}}` queues one run
  of the published version and answers 202. The caller needs the Automation privilege, and the
  run's writes are made as the caller.
- **On a schedule**: add a `schedule` to `manifest.json`. The server checks it at upload.

  ```json
  "schedule": { "cron": "0 6 * * *", "timezone": "Asia/Riyadh", "input": { "days": 30 } }
  ```

  The job runs once per slot across all of the deployment's workers, as the administrator who
  uploaded the published version. `timezone` defaults to UTC.

## Input

```json
{ "kind": "job", "input": { "account_id": "0190a0b0-0000-7000-8000-000000000001", "website": "https://acme.example" } }
```

`input` holds what the run was queued with, or the schedule's `input`.

## Answer

| Answer | Effect |
|---|---|
| `"continue"` | Nothing is written. |
| `{"records": [{"entity": "account", "id": "...", "values": {...}}]}` | Each record with an `id` is updated, and each without one is created, in order. |

A run may write at most 100 records. Every write must be granted. A write that is not granted, or
that the write path refuses, fails the run. Writes made before the failure are kept, and **a failed
run is not retried**: it appears in the run log and in the dead letters. Make a job safe to run
twice, for example by updating records it can find again rather than always creating new ones.

## Example: Rust

```rust
use serde_json::{Value, json};

/// Sets the account's website from the run's input; with either value
/// missing, writes nothing.
pub fn decide(run: &Value) -> Value {
    let input = &run["input"];
    match (input["account_id"].as_str(), input["website"].as_str()) {
        (Some(id), Some(website)) if !id.is_empty() && !website.is_empty() => json!({
            "records": [ { "entity": "account", "id": id, "values": { "website": website } } ]
        }),
        _ => json!("continue"),
    }
}

// `alloc` and `on_job(ptr, len) -> i64` follow, as generated.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_job_updates_the_account_it_is_given() {
        let run = json!({ "kind": "job", "input": { "account_id": "0190a0b0-0000-7000-8000-000000000001", "website": "https://acme.example" } });
        assert_eq!(decide(&run)["records"][0]["values"]["website"], "https://acme.example");
    }

    #[test]
    fn a_job_without_an_account_writes_nothing() {
        let run = json!({ "kind": "job", "input": { "website": "https://acme.example" } });
        assert_eq!(decide(&run), json!("continue"));
    }
}
```

## Example: TypeScript (not buildable yet)

For when TypeScript extensions ship (Javy, Y10-T7):

```ts
import type { Account } from './generated/attome';

interface JobRun<I> { kind: 'job'; input: I }
type Write<T> = { entity: string; id?: string; values: Partial<T> };
type Answer = 'continue' | { records: Write<Account>[] };

export function decide(run: JobRun<{ account_id?: string; website?: string }>): Answer {
  const { account_id, website } = run.input;
  if (!account_id || !website) return 'continue';
  return { records: [{ entity: 'account', id: account_id, values: { website } }] };
}
```

## Try it

```sh
cargo test
attome dev . --once --target dev          # prints: uploaded account_website version 1 as a draft
curl -X POST "$ATTOME/api/v1/admin/extensions/account_website/versions/1/publish" \
  -H "Authorization: ApiKey $KEY"
curl -X POST "$ATTOME/api/v1/admin/extensions/account_website/jobs" \
  -H "Authorization: ApiKey $KEY" -H 'Content-Type: application/json' \
  -d '{"input": {"account_id": "<an account id>", "website": "https://acme.example"}}'
curl "$ATTOME/api/v1/admin/extensions/account_website/runs" -H "Authorization: ApiKey $KEY"
```

The test endpoint (`.../versions/{v}/test`) runs hooks only. To try a job before publishing it,
publish it on a development deployment, or test `decide` with `cargo test`.
