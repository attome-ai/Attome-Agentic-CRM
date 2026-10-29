# Polymorphic lookups

A polymorphic lookup (a "regarding" field) points at a record of one of several entities. It is two
text attributes: the target entity's logical name and the target record's id. The id attribute's
`options.polymorphic` names the pair and what it may point at:

```json
{ "polymorphic": {
    "pair": "regarding_entity",
    "targets": ["account", "contact"],
    "on_delete": { "account": "restrict", "contact": "cascade-deactivate" } } }
```

| Option | Meaning |
|---|---|
| `pair` | The attribute holding the target entity's logical name. |
| `targets` | The entities it may point at. |
| `extends` | Every entity built on this base (instead of, or beside, `targets`). |
| `any` | Every entity. |
| `on_delete` | What deleting a target does to the records pointing at it, per target entity, with `"*"` for every other: `orphan` (the default; they keep the reference), `restrict` (the delete is refused while a live record points at it, naming the path) or `cascade-deactivate` (they are deactivated with it, and restoring the target brings them back). |

Every write sets both attributes together, to an allowed, live record the writer may read. A filter
can follow the pair into the target's own fields: `regarding_entity = account AND regarding_id.city
= Riyadh`.
