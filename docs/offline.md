# Offline use

A field team keeps a chosen slice of the CRM on their device and keeps
working without a connection. What a device holds is decided per role by an
**offline profile**; the server decides, at every sync, what each person may
still have.

Offline use needs the `offline` module and the offline pack (which adds the
two profile entities). Devices register themselves (`POST /api/v1/devices`)
the first time the app signs in.

## Offline profiles

An `offline_profile` record says what one role keeps:

| Field | Meaning |
|---|---|
| `name` | What administrators call it. |
| `role_ref` | The role it applies to. A person gets the first enabled profile, by name, among their roles. |
| `max_storage_mb` | How much the device's offline store may use. |
| `max_days_offline` | How long the device may stay offline before it must sync again. |
| `include_maps` | Whether map tiles for the records' locations come along. |
| `is_enabled` | Turns the profile off without deleting it. |

Each `offline_profile_entity` record under it names one entity:

| Field | Meaning |
|---|---|
| `entity_logicalname` | The entity. |
| `stored_query_ref` | The stored query that picks the records (by id). Empty: the entity's default view. |
| `include_related` | Lookup fields whose target records come along, comma separated. |
| `include_files` | Whether the records' files come along. |
| `max_rows` | The most records of this entity a device keeps. |

Create and change both through the ordinary record API or the admin screens,
like any other record.

## What a device gets

`GET /api/v1/offline/profile` gives the device its profile: for each entity it
may read, the field metadata and the rules the app runs before a change is
synced (expression rules as their source and language version, and the
business rules that apply to the person). `bundle_version` changes whenever
any of that changes, so the app knows to fetch it again.

`POST /api/v1/offline/pull` sends records in pages. Every record comes through
the profile's stored query, run as the person, so record-level security and
field security apply exactly as on screen. A device first receives everything
its profile covers, then only what changed since its last pull. When the
person can no longer read a record (their access changed, the record left the
query's filter, or it was deleted), the next pull tells the device to drop it.

## What never goes offline

- **Sensitive attributes** (`is_sensitive`): not their values, not their
  metadata, not rules about them. They stay on the server.
- Entities the person may not read, even when their role's profile lists them.
- Records outside the stored query, or beyond what the person may read.

## Device security

- The server keeps each device's sync position. A device cannot ask for
  records it was not sent through its profile.
- **Remote wipe:** an administrator wipes a device from the device list
  (`POST /api/v1/admin/devices/{id}/wipe`). The app clears its data at its
  next start, and the person's sessions end everywhere, so the device cannot
  sign back in with what it holds. A device told to wipe gets nothing more
  from `pull`.

## The administrators' device view

`GET /api/v1/admin/devices` lists every device with its owner, platform and
app version, when it last synced (pull and push), the changes waiting on it,
the storage it uses and its last sync error.

`POST /api/v1/admin/devices/{id}/offline-refresh` makes a device start over
at its next pull: its record list is cleared and everything is sent again.
Use it after changing a profile's queries, or when a device reports a sync
error.

## Changes made offline

Sending changes made offline back to the server (`POST /api/v1/offline/push`,
with per-field merging when two people changed the same record) is not
available yet. Until it is, offline data is for reading.

## Not in this release: the on-device helper

An optional assistant that runs on the device is planned but not part of this
release. It has to run a model small enough for a phone while following the
same permission and data rules as the server, so it comes after offline sync
itself is proven in the field.
