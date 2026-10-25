# OData feed (Excel and Power BI)

Attome serves its records as a read-only OData v4 feed at `/api/v1/odata`, so Excel and
Power BI read live data without an export. The feed shows only what the signed-in key may
read: entities it cannot read are missing, records outside its record-level access never
appear, and sensitive attributes without a field-read grant are neither listed nor returned.

## Connecting

Create an API key for the person whose access the report should have, then in Power Query
(Excel: **Data → Get Data → From Other Sources → Blank Query**; Power BI: **Get data → Blank
query**) enter:

```
= OData.Feed("https://crm.example.com/api/v1/odata", null,
    [Headers = [Authorization = "Bearer <public-key>:<secret>"]])
```

Choose the entity sets to load. Refreshing re-reads them.

## What the feed answers

| URL | Answer |
|---|---|
| `/api/v1/odata` | The entity sets the key may read. |
| `/api/v1/odata/$metadata` | Their schema: the key `id` and each readable attribute, typed (`Edm.Decimal` for numbers and currency, `Edm.DateTimeOffset` for dates, `Edm.Boolean`, `Edm.Guid` for lookups, `Edm.String` for the rest). |
| `/api/v1/odata/{entity}` | Records, 200 a page, with `@odata.nextLink` to the next page. |
| `/api/v1/odata/{entity}/$count` | How many records match, as text. |

Supported options: `$select` (fields, or a related field as `primary_contact/name`),
`$filter` (`eq`, `ne`, `gt`, `ge`, `lt`, `le`, `and`, `or`, `not`, parentheses, `in (…)`,
`contains`, `startswith`, `endswith`, `eq null`), `$orderby`, `$top`, `$count=true` and
`$format=json`. `$expand`, `$search`, `$apply` and `$skip` above 0 are refused with a message
naming them; pages follow `@odata.nextLink`.

Every request runs as a structured query on the read-only database pool, under the same time
limit and plan-cost guard as `POST /api/v1/query/run`.
