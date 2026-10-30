# Pages

A page (the `page` model kind) is a tree of components: an app home, a workspace, a custom page, a
portal page or a record page. Each component is bound to the data it shows and runs under the
signed-in person's own rights. The web app shows a published page at `/xrm/pages/{id}`, with
`?entity=&record=` for a record page.

## Bindings

A component's `binding` names one source:

- `view` or `query`: a view or stored query, by id.
- `entity`: an entity's records, by logical name, as its default list shows them.
- `record`: `current` (the page's record) or a lookup attribute of it, by id.

On a record page, a `view` or `entity` binding may add `related_by`, a lookup field of the listed
records that must name the page's record. An `entity` binding may also add `where`, up to ten
`{ "field", "op": "eq" | "in", "value" }` conditions:

```json
{ "id": "deals", "type": "list",
  "binding": { "entity": "opportunity", "related_by": "account_ref",
               "where": [{ "field": "stage", "op": "in", "value": ["proposal", "negotiation"] }] } }
```

A `metric` bound to an entity shows how many records match. A component bound to an entity that is
not installed on the deployment, or that the person may not read, hides itself.

## Record pages

A record page with `"default": true` is its entity's record page. `GET
/api/v1/model/entities/{entity}/record-page` returns it: the customer's own first, then an
installed app's. The customer 360 panel on a record's form links to it.

The crm pack ships `account-360` (`packs/crm/model/page/crm/account-360.json`): counts of open
opportunities, unpaid invoices, cases and contacts, the account's summary, and tabs for its
contacts, open opportunities, cases, invoices and timeline. Cases and invoices show when the
customer-service and finance packs are installed.
