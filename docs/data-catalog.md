# Data catalogue

The data catalogue answers "which data do we have, what does it mean, who owns it, who uses it
and how do I get to it". It is built from the metadata itself, with no crawler, and stays current
because it is rebuilt whenever the model is published.

## Assets

`catalog_asset` holds one row per asset, keyed by `(kind, ref)`:

| Kind | Ref | From |
|---|---|---|
| `entity` | logical name | `entity_info` |
| `attribute` | `entity.field` (its parent is the entity) | `attribute_info` |
| `option_set` | `entity.field` of a choice attribute | `attribute_info` |
| `view` | id | `view` |
| `saved_query`, `report` | id | `sql_query` (a report when `is_report`), `attome_report` |
| `dashboard` | id | `attome_dashboard` |
| `metric` | id | `dashboard_metric_definition` |
| `flow` | id | `workflow_definition` |
| `agent_tool` | action id | the AI action registry |

The index is rebuilt after every model publish and by the `catalog_asset_rebuild` job (every 15
minutes, and once at boot), so changes made through the admin routes are picked up too. An asset
that is gone, inactive or deleted drops out. Names and descriptions in English and Arabic feed one
search vector with Arabic normalisation: alef forms, taa marbuta and diacritics are folded. A
description someone has written is never overwritten by the metadata.

## Who sees what

Every catalogue route needs the `metadata.read` privilege, which administrators already hold.
A person sees only the assets of the entities they may read. Within those entities they see only
the attributes they may read, so a sensitive attribute also needs its field read grant. A hidden
attribute is never named anywhere: not in fields, lineage, search or the personal data map.

With `catalog.show_hidden_existence` on (it is off by default), a hidden attribute is listed by
name only, marked `hidden`, so the person can ask for access to it.

## Routes

| Route | What it does |
|---|---|
| `GET /api/v1/catalog/entities`, `GET /api/v1/catalog/entities/{logicalname}` | Entity browse, and the entity's detail: schema summary, lineage, usage and glossary terms. |
| `GET /api/v1/catalog/assets?q=&kind=&domain=&label=` | Search with facets for kind, domain and label. The facets count what the words match. |
| `GET /api/v1/catalog/assets/{id}` | The asset page. Description, domain, owner, label, terms, quality, profile, lineage, usage and certification each appear only when the owning feature has data. |
| `PATCH /api/v1/catalog/assets/{id}/description` | Edits the bilingual description with `If-Match`. The new text is a draft. |
| `POST /api/v1/catalog/assets/{id}/description/approve` | A builder approves the draft with `If-Match`, and its status becomes `reviewed`. |
| `POST /api/v1/catalog/assets/{id}/access-requests` | Asks for access with a reason. Only one request per person and asset can be pending. |
| `POST /api/v1/catalog/access-requests/{id}/decide` | The owner grants or refuses. |
| `GET /api/v1/catalog/personal-data-map` | Every attribute labelled personal, financial or health, with what reads it. |
| `GET /api/v1/catalog/export` | Every asset's metadata, paged, for a harvester such as Purview or Collibra. It never includes record values. It answers only when `catalog.export_enabled` is on; otherwise it returns 404. |

## Access requests

The owner of an asset is an administrator, or the steward or deputy of its data domain (L3). That
domain is the asset's own, or its entity's. Anyone else gets 404 when they try to decide a
request, so they cannot learn that the request exists.

A grant goes through the role-grant path that `/api/v1/admin/security` uses: step-up, the
granter's ceiling and the approval gate. If the grant needs an approval, the request records it.
If the grant is refused, the request returns to pending and nothing is given.

## Usage

The nightly rollup (`catalog_usage_rollup`) records for each entity:

- the record count;
- the last write;
- search impressions over 30 days;
- its readers, grouped by kind (`query`, `workflow`, `dashboard`, `rule`) and taken from the
  metadata references.

An entity is flagged `unused` when it has had no write for 90 days, no search impression for 30
days, and has no readers.

## Agents

Four AI actions reach the catalogue through the `CatalogTools` seam. Each acts as the person, with
the same privilege and visibility rules:

- `catalog.search`: finds assets by words and kind.
- `catalog.describe_asset`: returns an asset's page.
- `catalog.ask`: answers a question in plain words, citing the assets a search found (judged like
  `knowledge.answer`).
- `catalog.draft_descriptions`: proposes descriptions. They stay drafts until a builder approves
  them, and an agent's call waits for a person to confirm it.

## Audit

The following are audited:

- description edits and approvals (Configuration category, in the edit's own transaction);
- access requests (`catalog.access_requested`);
- refusals (`catalog.access_refused`);
- grants, through the role-grant path's own events.

Exports are not audited yet.

## Not built yet

- The catalogue screens for search, the asset page and the personal data map (L4-T6). The existing
  screen at `/xrm/admin/data/catalog` browses entities only.
- Semantic search.
- Outside systems.
- Questions on assets.
- Asset history between published versions.
- An export in an open metadata standard: which standard to follow is still undecided.
