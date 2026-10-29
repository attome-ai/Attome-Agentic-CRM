# Metadata layers

How a deployment's entities and fields combine what the platform ships, what installed apps add,
and what the customer changes, and how a builder handles an upgrade that touches a customised item.
Every route here needs an administrator (`admin.data_model`).

## The three layers

Every property of an entity or a field (its display name, whether it is required, its maximum
length, ...) has a value in up to three layers, lowest first:

| Layer | Who sets it |
|---|---|
| `platform` | The platform's own definitions, applied at boot. |
| `app` | An installed app: a pack's `product` changesets. Apps are ordered among themselves. |
| `customer` | The deployment's own builders, through the admin routes, the designer or a customer changeset. |

The value that applies is the one from the highest layer that sets the property. A layer stores only
the properties it changes (`metadata_property_layer`), so a customer who renames a field keeps the
platform's later fixes to its other properties.

The changeset ledger stores four owner names on each row (`owner_layer`), and they map onto the three
layers: `platform` is the platform, `product` is an app, and `project` and `customer` are the
customer. The stored names do not change.

## Seeing an item's layers

- `GET /api/v1/admin/metadata/{kind}/{key}/layers`: each property's value in every layer that sets
  it, and the layer whose value applies. `kind` is `entity` (key: its logical name) or `attribute`
  (key: `<entity>.<field>`).
- `GET /api/v1/admin/metadata/{kind}/{key}/layers/diff`: the properties two layers set differently.
- `GET /api/v1/admin/metadata/app-layers`: the installed apps in layer order. An app's first install
  gives it the next place; a later app sits above an earlier one, and the customer above all apps.

The admin console shows the same on its "Where settings come from" and "Upgrade conflicts" screens,
in English and Arabic.

## Upgrades and conflicts

When an upgrade changes a property that the customer (or an app) also changed, the upgrade keeps the
customer's value and records an open conflict with the platform's old value, its new value and the
customer's value. Nothing is merged on its own.

- `GET /api/v1/admin/metadata/conflicts?status=open` lists them, newest first.
- `POST /api/v1/admin/metadata/conflicts/{id}/resolve` with `{"choice": "keep_customer"}`,
  `{"choice": "take_platform"}` (the customer's value is removed) or
  `{"choice": "combine", "value": ...}` (the value becomes the customer's).
- Asked to, an agent proposes a resolution with its reasoning
  (`metadata.propose_conflict_resolution`). It only proposes; a builder resolves.
- `GET /api/v1/admin/metadata/upgrade-impact` lists, for a platform or app changeset, the
  customisations on items it retires, deletes or renames, so they can be checked before the upgrade.

Planning an app's changeset lists in `clashes` the properties another installed app already set on
the items it touches, and refuses it (`app_clash`) unless the plan request sets `accept_clashes`.

## Resetting a customisation

`POST /api/v1/admin/metadata/{kind}/{key}/reset` puts an item's customised properties (all of them,
or the ones named in `{"properties": [...]}`) back to what an app or the platform gives them. Add
`?preview=true` to see what would change without changing it. A reset can be undone once,
`POST /api/v1/admin/metadata/resets/{reset_id}/undo`, unless the item was customised again since.

## Reserved names and locks

A new entity or field may not take a name the platform ships, nor one starting with `attome_` or
`xrm_`: those prefixes are kept for future platform items, so a later release never collides with a
customer's name. Customer names need no prefix.

An item a layer locked (`metadata_lock`) refuses every change (409 `metadata_locked`). An add-only
item takes additions, such as a new field or choice value, but refuses changing or removing what it
has (409 `metadata_add_only`). An entity's lock covers its fields. Locks are shipped by the platform
or an app; no route sets them.

## Agents

A building agent edits only the customer layer. An edit an agent makes on its own to an item the
platform or an app owns is refused with 403 and logged. A proposal a person confirms is that
person's edit.

## `is_customized`

Entity and field rows still carry the older `is_customized` flag, and writes still set it. It is
being retired in steps, each its own release:

1. Expand (done): the layer rows are written beside it, and boot no longer skips a whole customised
   row. Rows customised before the layers existed were backfilled on their first boot: each property
   whose value differs from the platform's definition was recorded as the customer's.
2. Switch: every reader of `is_customized` reads the layer rows instead, and the flag becomes
   derived (true when the item has a customer-layer property).
3. Contract: a new migration drops the column once no code reads it. The migrations that added it
   are not edited.
