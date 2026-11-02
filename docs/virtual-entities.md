# Virtual entities

A virtual entity is an entity in the metadata whose rows live somewhere else: another database, a
partner's API. The record routes serve it through a **provider** registered for it in code
(`attome_records::virtual_entity::register("<entity>", provider)`), not from the deployment's
database (L8-T1).

| Route | What happens |
|---|---|
| `GET /api/v1/{entity}` | The provider lists one page. Every `filter[<field>][<op>]` must be one the provider can apply itself; otherwise the request is refused with 422 naming the filter, never filtered halfway. Sort, page size and cursor pass through. `delta_token` is refused: there is no change feed. |
| `GET /api/v1/{entity}/{id}` | The provider reads one row. |
| `POST`, `PATCH` | The provider's create or update, when it has one; 405 when it is read-only. |
| `DELETE` | 405. |

**Access is entity-level.** Whoever holds the entity's privilege for the operation sees every row
the provider returns; owners, shares, sharing rules and record filters do not apply to rows the
deployment does not hold (V2-D1628). Grant the read privilege only to the people who may see all of
them.

Record ids are UUIDs: a provider maps its own keys to them (a UUIDv5 of the external key, for
example). List answers are cached on each server for 30 seconds per query; a create or update
through the entity clears that entity's answers on the server that made it.
