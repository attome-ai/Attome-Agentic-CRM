# Learning paths

Four short paths for a builder new to Attome, each a set of exercises on your own **Solo**
install (one server on your machine; see the [install guide](../install.md)). Every exercise
ends with an **answer check**: a customer test you add and run, which passes only when your
configuration does what the exercise asks. A customer test runs its writes in a transaction
that is always rolled back, so checking an answer never changes your data.

| Path | You learn | Time |
|---|---|---|
| [1. Your first entity](01-first-entity.md) | entities, fields, records over the API | 30 min |
| [2. Rules that guard your data](02-rules.md) | defaults and refusals in business rules | 30 min |
| [3. Who may do what](03-access.md) | roles, privileges and what a role cannot do | 30 min |
| [4. Changes as code](04-changes.md) | optimistic updates, changesets, moving a change to another install | 45 min |

## Before you start

1. Install Solo and sign in as the administrator at `http://localhost:7865/`.
2. Create an API key for yourself (**Settings → API keys**) and keep it in a shell variable;
   the examples use `curl` with it:
   ```sh
   export ATTOME=http://localhost:7865
   export KEY=<public id>:<secret>
   ```
3. Every path builds on the one before: do them in order.

## How an answer check works

Each check is a customer test: some records to start from (`given`), the writes to try
(`when`, optionally as a role), and what must then hold (`expect`): an attribute's value, or
the error a write must meet (`validation`, `forbidden`, `conflict`, `not_found`).

Add it once:

```sh
curl -s -X POST "$ATTOME/api/v1/admin/customer-tests" \
  -H "Authorization: ApiKey $KEY" -H "Content-Type: application/json" \
  -d @check.json
```

where `check.json` is `{"name": "...", "definition": { ... }}` from the exercise, then run it
with the id it returned:

```sh
curl -s -X POST "$ATTOME/api/v1/admin/customer-tests/<id>/run" -H "Authorization: ApiKey $KEY"
```

`"passed": true` means the exercise is done; otherwise `failures` says what did not hold.
**Admin → Customer tests** shows the same checks and their last results.
