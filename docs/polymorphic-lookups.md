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

## Many parties: activity parties

One activity can involve several people of different kinds. The CRM pack's `activity_party`
(changeset 0009) links an activity (`activity_ref`) to a contact, account, lead or user (the
polymorphic pair `party_entity`/`party_id`) with how they take part: `organizer`, `required`,
`optional`, `from`, `to`, `cc` or `bcc`. A link goes with its activity (a cascade lookup) and with
the person when they are deleted (`on_delete: {"*": "cascade-deactivate"}`). Filtering by the
party's own fields works through the pair, as for any polymorphic lookup: `party_entity = contact
AND party_id.city = Riyadh`.

## The platform's record-attached entities

A note, a note's reply, an activity, a communication, a follow, a tag on a record and a reminder
point at their record through a polymorphic lookup (A8-T4, platform changeset 0080): `record_id`
with `entity_name` as its pair, any entity as a target. Every write that sets them checks that the
record exists, is live and can be read by the writer, and both are set together. A document's
record (`attome_document`'s `record_id` and `entity_name`) is one too (platform changeset 0082). The
pairs in infrastructure tables (approvals, timeline pins, AI references) are not metadata fields.

## Portal writes

A portal user (a web portal principal, not staff) may set a polymorphic pair only to a record of an
entity its portal role reads, among those the field's options allow, and only to a record inside
that role's read scope on the entity: the same conditions that decide what the portal user sees
there. Any other record, entity or field is refused as if the record did not exist. So a customer
uploading a document to their own case names the case, and no other record they can't open.
