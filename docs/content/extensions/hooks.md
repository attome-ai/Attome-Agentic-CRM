# Record hooks

A record hook runs on every create or update of the entity it names, at the stage it names. It can
let the write go on, change the values being written, or refuse the write with a message. Read the
[guide's overview](README.md) first for the grants, limits and publishing steps.

## Stages

| Stage | When | The hook may |
|---|---|---|
| `before_validation` | Before the business rules judge the values | change values, or refuse |
| `before_save` | Just before the row is written | change values, or refuse |
| `after_save` | After the row is written, inside the transaction | refuse, which rolls back the write |
| `after_commit` | After the transaction commits, in a job (up to three attempts), with the stored row | act on the write; a refusal is only logged, since the write has happened |
| `form_load`, `form_change` | While someone works in a form (nothing is saved) | fill values in the form, or show a refusal |

Hooks at the same stage run in their `order`, lowest first. A hook whose own writes call hooks
again is allowed up to eight levels deep. In a bulk operation or an import, `after_commit` hooks
get the writes in batches of up to 500 records of one entity.

## Start

```sh
attome new extension account_name_rules --kind hook
```

`manifest.json`:

```json
{
  "entities": { "account": { "read": true, "write": true, "attributes": ["name"] } },
  "hooks": [{ "entity": "account", "stage": "before_save", "order": 0 }]
}
```

Each hook needs a read grant on its entity. To change values, it also needs a write grant on every
attribute it changes.

## Input

The server writes this JSON at the place `alloc` returns, then calls `on_record`:

```json
{
  "stage": "before_save",
  "entity": "account",
  "record_id": "0190a0b0-0000-7000-8000-000000000001",
  "is_create": true,
  "values": { "name": "  Acme " },
  "previous": null,
  "actor": "0190a0b0-0000-7000-8000-0000000000aa"
}
```

`values` and `previous` (the stored values, on an update) hold only the attributes the extension
may read.

## Answer

| Answer | Effect |
|---|---|
| `"continue"` | The write goes on unchanged. |
| `{"change": {"name": "Acme"}}` | The values are changed, then the write goes on (`before_*` stages only). |
| `{"reject": "A new account needs a name."}` | The write is refused with this message. |
| `{"reject": {"key": "name_required", "args": {}}}` | The write is refused with a message from the manifest, in the caller's language. |

A hook that fails, or that goes past a limit, refuses the write.

## Example: Rust

`src/lib.rs` as `attome new extension` writes it, with the calling convention shortened:

```rust
use serde_json::{Value, json};

/// A new account with no name is refused, a name with spaces around it is
/// trimmed, anything else goes on.
pub fn decide(input: &Value) -> Value {
    let name = input["values"]["name"].as_str();
    let is_create = input["is_create"].as_bool().unwrap_or(false);
    match name {
        None | Some("") if is_create => json!({ "reject": { "key": "name_required", "args": {} } }),
        Some(name) if name.trim() != name => json!({ "change": { "name": name.trim() } }),
        _ => json!("continue"),
    }
}

// `alloc` and `on_record(ptr, len) -> i64` follow: they read the input,
// call `decide`, and return the answer. Leave them as generated.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_account_without_a_name_is_refused() {
        let input = json!({ "stage": "before_save", "entity": "account", "is_create": true, "values": {} });
        assert_eq!(decide(&input)["reject"]["key"], "name_required");
    }

    #[test]
    fn a_name_is_trimmed() {
        let input = json!({ "stage": "before_save", "entity": "account", "values": { "name": "  Acme " } });
        assert_eq!(decide(&input), json!({ "change": { "name": "Acme" } }));
    }
}
```

The refusal uses a message key, so `manifest.json` declares the text:

```json
"messages": {
  "name_required": { "en": "A new account needs a name.", "ar": "يحتاج الحساب الجديد إلى اسم." }
}
```

English is required and Arabic is optional. `{name}` in a text is filled from the refusal's `args`.
A caller sending `Accept-Language: ar` reads the Arabic text.

## Example: TypeScript (not buildable yet)

The same logic, for when TypeScript extensions ship (Javy, Y10-T7). It cannot be built or uploaded
today. `attome sdk generate` writes the `Account` type from the deployment's own model.

```ts
import type { Account } from './generated/attome';

interface RecordEvent<T> {
  stage: 'before_validation' | 'before_save' | 'after_save' | 'after_commit';
  entity: string;
  record_id: string;
  is_create: boolean;
  values: Partial<T>;
  previous: Partial<T> | null;
  actor: string;
}

type Answer =
  | 'continue'
  | { change: Record<string, unknown> }
  | { reject: string | { key: string; args: Record<string, unknown> } };

export function decide(input: RecordEvent<Account>): Answer {
  const name = input.values.name;
  if (input.is_create && !name) return { reject: { key: 'name_required', args: {} } };
  if (name && name.trim() !== name) return { change: { name: name.trim() } };
  return 'continue';
}
```

## Try it

```sh
cargo test
attome dev . --once --target dev
# The upload prints the draft's version, here 1.
curl -X POST "$ATTOME/api/v1/admin/extensions/account_name_rules/versions/1/test" \
  -H "Authorization: ApiKey $KEY" -H 'Content-Type: application/json' \
  -d '{"samples": [{"stage": "before_save", "entity": "account", "is_create": true, "values": {}}]}'
curl -X POST "$ATTOME/api/v1/admin/extensions/account_name_rules/versions/1/publish" \
  -H "Authorization: ApiKey $KEY"
```

Within five seconds of publishing, creating an account with no name through the app or the API is
refused with the message.

## Form hooks

The same hook can answer a form while someone fills it in. Add a `form_load` or `form_change` stage
to `hooks`. The form calls `POST /api/v1/{entity}/form-hooks`, and the server runs the hook on the
form's values exactly as it would on a write. A `change` fills values in the form and a `reject`
shows its message. Nothing is saved. The hook's code runs on the server, never in the browser.
