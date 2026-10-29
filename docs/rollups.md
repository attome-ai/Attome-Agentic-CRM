# Rollup fields

A rollup field holds a value computed from related records: an account's total invoiced, its
number of open cases, the date of its last order. It is stored in a column like any other
field, so lists, filters and reports read it directly, but nobody writes it: the platform keeps
it up to date.

## Defining one

In the entity editor, **Add rollup** opens the rollup editor. Through the API, create a field
with `field_type: "rollup"` and the definition as its `options`
(`POST /api/v1/admin/entities/{id}/fields`):

```json
{ "logicalname": "won_total", "name": "Won total", "field_type": "rollup",
  "options": {
    "function": "sum",
    "path": [{ "entity": "opportunity", "via": "account_ref" }],
    "attribute": "amount",
    "filter": "status == \"won\"",
    "window": { "days": 365, "date_attribute": "close_date" },
    "mode": "fast",
    "result_type": "currency" } }
```

| Option | Meaning |
|---|---|
| `function` | `count`, `distinct_count`, `sum`, `avg`, `min`, `max`, `first` or `last`. |
| `path` | One to three steps from this entity to the records counted. Each names an entity and its lookup to the step before. `account ← opportunity ← opportunity_line` is two steps. The editor offers one step; longer paths go through the API. |
| `attribute` | The field of the last step's records aggregated. `count` needs none. `sum` and `avg` take a number or currency; `min`, `max`, `first` and `last` also take a date; `distinct_count` takes most plain fields. A field hidden by field security cannot be aggregated. |
| `filter` | A condition in the rule language over the last step's records. It must run in the database, so it uses that entity's own stored fields. |
| `window` | Only records whose date field falls in the last `days` (1 to 3660). |
| `order_by` | For `first` and `last`: a date or number field (`created_at` when absent). |
| `mode` | `fast` (the default) or `exact`, below. |
| `result_type` | What the column holds: a number for counts, otherwise the aggregated field's type. Saving names the right one if it differs, and it cannot change once the field exists. |

Saving checks the whole definition against the entities as they are. A rollup cannot be
required, has no maximum length, and refuses a written value from any client, import, merge,
copy or rule.

## How it stays up to date

- **Fast** (any definition): a few seconds after a related record changes, the `rollup_fast`
  job (every 5 seconds) follows the change up the path and recomputes each parent it reaches,
  including the old parent when a record moves.
- **Exact** (a `count` or `sum` over one lookup, with no filter or window): the related
  record's own save adds and takes back its amount on the parent, so the value is right as soon
  as the save commits, also under concurrent saves.

A new or changed rollup is filled for every existing record by the `rollup_backfill` job,
1,000 records per run. The nightly `rollup_heal` job recomputes a sample of about 1% of
records, plus those whose window dropped records since the day before, and fixes and logs any
value that drifted, for example after a hard delete or a bulk update made outside the API.

Writing a rollup value does not change the record's row version and does not emit a change
event, so editing the record is never refused because its rollup moved.

## Explaining a value

On a record, **How is this calculated?** under a rollup field lists the related records it
counts that you may open, and how many more it counts that you may not.
`GET /api/v1/{entity}/{id}/rollups/{attribute}/explain` returns the same: the definition, the
stored value, `counted`, `hidden` and the first 100 readable records with their amounts.

## Group totals over a hierarchy

A lookup from an entity to itself flagged as its hierarchy (`"hierarchy": true`) can name a
second self lookup as its top: `"top_field": "top_parent_ref"`. The platform then keeps that field
pointing at each record's root, a root at itself, on every save and when a branch moves; a value
written to it is replaced. The top field must exist before the hierarchy names it.

A rollup over the top field then totals a whole group on its root. The CRM pack's account has
two, with the path `account (via top_parent_ref) ← opportunity (via account_ref)`:
`group_open_pipeline` (open deal amounts) and `group_won_revenue` (deals won in the last 365
days). Accounts below the root show their top parent; the group totals are on the root.
`sales_parent_ref` is a second parent for sales reporting that the group totals do not follow.

When a branch moves, the `rollup_fast` job recomputes both the old and the new root from the
moved account's change, so both groups' totals take in the whole branch within seconds.
