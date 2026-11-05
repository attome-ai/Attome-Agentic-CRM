# Webhook handlers

A webhook extension turns another system's events into records. Another system calls one of the
deployment's inbound hooks, `POST /api/v1/hooks/{name}`. The hook checks the caller, and the
extension decides what to write. Read the [guide's overview](README.md) first for the grants,
limits and publishing steps.

## How a delivery reaches the extension

Before the extension runs, the inbound hook does all the checking:

1. The hook is active, the caller's address is allowed and, if the hook requires it, its client
   certificate is verified.
2. The signature or bearer secret checks out, and a signed timestamp falls within its window.
3. The body is JSON and carries the fields in the hook's `schema.required`.
4. The event's id has not been seen before (a replay is refused).
5. The event is stored in the hook's inbox and the caller gets a 202 at once. A job then calls the
   extension, as the hook's `run_as` service user.

The extension never sees an unsigned or replayed call. It does not have to check signatures
itself, and it cannot read the hook's secret.

## Start

```sh
attome new extension signup_to_account --kind webhook
```

`manifest.json`:

```json
{
  "entities": { "account": { "write": true, "attributes": ["name", "website"] } }
}
```

Publish the extension first. Then point an inbound hook at it, which needs the Integrations
privilege:

```sh
curl -X POST "$ATTOME/api/v1/admin/inbound-hooks" \
  -H "Authorization: ApiKey $KEY" -H 'Content-Type: application/json' \
  -d '{
    "name": "crm_signup",
    "auth": { "kind": "hmac", "preset": "custom", "header": "x-signature", "encoding": "hex" },
    "secret": "<a long random secret, shared with the sender>",
    "schema": { "required": ["company"] },
    "handler": { "type": "extension", "name": "signup_to_account" },
    "run_as": "<the id of a service user>"
  }'
```

The hook is refused when no published extension has the handler's name. The
[integrations guide](../extension.md#integrations) covers the other `auth` presets, `ip_allow`,
`require_mtls` and `ordering_key`.

## Input

```json
{ "kind": "webhook", "hook": "crm_signup", "body": { "company": "Acme", "website": "https://acme.example" } }
```

`body` is the event exactly as the sender posted it.

## Answer

The same as a [job's](jobs.md#answer): `"continue"`, or
`{"records": [{"entity", "id"?, "values"}]}`, at most 100 records, every write granted and made as
the hook's service user through the ordinary write path.

## Example: Rust

```rust
use serde_json::{Value, json};

/// A new account for an event with a company; nothing for one without.
pub fn decide(delivery: &Value) -> Value {
    let event = &delivery["body"];
    let Some(company) = event["company"].as_str().map(str::trim).filter(|c| !c.is_empty()) else {
        return json!("continue");
    };
    let mut values = serde_json::Map::new();
    values.insert("name".into(), json!(company));
    if let Some(website) = event["website"].as_str().filter(|w| !w.is_empty()) {
        values.insert("website".into(), json!(website));
    }
    json!({ "records": [ { "entity": "account", "values": values } ] })
}

// `alloc` and `on_webhook(ptr, len) -> i64` follow, as generated.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_event_with_a_company_creates_an_account() {
        let delivery = json!({ "kind": "webhook", "hook": "crm_signup", "body": { "company": " Acme " } });
        let answer = decide(&delivery);
        assert_eq!(answer["records"][0]["values"]["name"], "Acme");
        assert!(answer["records"][0].get("id").is_none(), "a create, not an update");
    }
}
```

## Example: TypeScript (not buildable yet)

For when TypeScript extensions ship (Javy, Y10-T7):

```ts
import type { Account } from './generated/attome';

interface Delivery<B> { kind: 'webhook'; hook: string; body: B }
type Answer = 'continue' | { records: { entity: string; id?: string; values: Partial<Account> }[] };

export function decide(delivery: Delivery<{ company?: string; website?: string }>): Answer {
  const company = delivery.body.company?.trim();
  if (!company) return 'continue';
  const values: Partial<Account> = { name: company };
  if (delivery.body.website) values.website = delivery.body.website;
  return { records: [{ entity: 'account', values }] };
}
```

## Duplicates and retries

The inbox stores each event id once, so a sender that delivers the same event twice gets a 202
both times, and the second delivery is not processed.

Unlike a job, a webhook run that fails **is** retried: the inbox processes the event again, up to
five attempts, after which the event is marked failed and its job goes to the dead letters, where
it can be replayed. Records a failed attempt wrote before failing are kept, so a retried attempt
writes them again. Keep a webhook extension to one write per event where you can.

An extension cannot look records up yet, so it cannot find an existing record by the sender's own
key. For an event that must update a record when it already exists (an upsert), use the inbound
hook's record handler with a `key` attribute instead of an extension; it updates the live record
holding that key and creates one only when none does.
