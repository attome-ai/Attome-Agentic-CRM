# Reporting tools (BI)

Attome's records reach a BI tool through the read-only OData feed (`/api/v1/odata`, see
[the OData feed](../../odata.md)). The feed answers as the person whose API key the report uses:
entities they cannot read are missing, records outside their record-level access never appear,
and sensitive attributes they may not read are neither listed nor returned. A shared report shows
each viewer what its key's person may see, so give a report the key of a person whose access fits
its audience, never an administrator's.

## Power BI and Excel

1. The report's person creates an API key for it (`POST /api/v1/auth/api-keys`); the key acts
   as them, limited to the scopes it is given, and its secret is shown once.
2. In Power BI choose **Get data → Blank query** (Excel: **Data → Get Data → From Other Sources →
   Blank Query**), open **Advanced Editor** and paste
   [`templates/attome-pipeline.pq`](templates/attome-pipeline.pq).
3. Set `BaseUrl` to the deployment's address and `ApiKey` to `<public-key>:<secret>`; in Power BI,
   make both parameters (**Manage parameters**) so the key is not kept in the report file.
4. Load. The starter gives one table of opportunities (CRM pack) with their account's name, typed
   amounts and a `close_month` column, ready for a pipeline-by-stage or a won-by-month chart.

Refreshing re-reads the feed. Pages of 200 records follow `@odata.nextLink`; `$filter` and
`$select` are pushed to the server when Power Query folds them (filter on a column before
expanding, as the starter does). `$expand` and `$apply` are refused, so joins and grouping happen
in Power Query, as in the starter.

Scheduled refresh in the Power BI service needs the deployment's address reachable from it (or an
on-premises data gateway inside the customer's network) and the key stored as the data source's
credential (**Anonymous** authentication with the `Authorization` header from the query).

## Metabase and other SQL tools

Not supported yet. Metabase, Superset and similar tools read a database over SQL, and a direct
connection to Attome's database would bypass record-level access. They will connect through the
SQL gateway (roadmap Y3), which signs in with an API key and applies the same access as the API;
until it ships, use the OData feed from a tool that reads OData, or export records.
