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

## Portal pages

A page with `"audience": "portal"` (or `"public"`) is shown to a web portal's signed-in users at
`/p/{keyword}/{page name}`, the page named `portal-home` at `/p/{keyword}`, and a record page at
`/p/{keyword}/{page name}/{record id}`. The portal app reads them with
`GET /{keyword}/api/v1/pages` and `GET /{keyword}/api/v1/pages/{name}`, and every component reads
its data through that portal's record API under the portal user's own role plan: an `entity`
binding with `related_by` and `eq` conditions becomes the record list's equality filters, a view or
query binding shows nothing, and flows and actions are not offered. A navigate target names the
portal as `-` (`/p/-/portal-case/{id}`). A record page whose root has
`props.reply = {"entity", "lookup", "body"}` gets a reply box: the reply is a record of that entity
whose lookup names the page's record, written through the portal's plan like any portal write.
A page whose root has `props.create = {"entity", "fields": [...]}` gets a create form (AC11-T2):
it asks for the listed fields the portal user's plan lets them write, as
`GET /{keyword}/api/v1/metadata/{entity}` describes them (a choice as a list, a lookup as the
records of its target the user can read), and creates the record through the portal's record API.

A `custom` component renders the block kind registered under its `component` name. A feature entry
point registers its blocks with `providePageBlocks([{component, load}])` on the injector that shows
the pages, where `load` imports the block's component only when a page shows one. Each block
receives the page node as its `node` input and reads the page (its record, language and
`site`, the portal's keyword) through `PageContext`. An unregistered name shows its id. Portal pages
register the store's blocks (`store.*`, `docs/portal-shop.md`).

The customer-service pack ships `portal-home`, `portal-cases`, `portal-case` (with replies as
`case_message` records, pack changeset 0004), `portal-knowledge` and `portal-catalog`. What each
shows depends on the portal role's grants on `service_ticket`, `case_message`,
`knowledge_data_item` and `service_offering`. The portal also has its own sign-in, profile and
consent pages.

The partner pack ships `portal-home` (leads offered, deal registrations, resources),
`portal-deals` (a partner registers a deal through the create form), `portal-deal` (its status and
protection end), `portal-resources` (published `partner_resource` records, pack changeset 0002),
`portal-leads`, `portal-opportunities`, `portal-mdf` (funds, requests and claims),
`portal-certifications` and `portal-performance` (the partner's scorecard snapshots). Each shows what
the member's partner role reads (`attome partner portal-roles`): their own partner's records only.
MDF requests and claims are made through the partner routes, not a create form.

### A portal on its own domain

A user administrator gives a portal its own domain with
`PUT /api/v1/admin/webportals/{id}/domain` (`{"domain": "support.example.com"}`, `null` clears it;
one portal per domain; audited). Point the domain's DNS at the server: on that host, `/` asks
`GET /api/v1/portal-host` and opens the portal, and every portal call is same-origin there. With
ACME on (see [edge.md](edge.md)), the certificate covers every portal domain found at boot, so
restart after adding one. Behind a proxy that terminates TLS, add the domain to its certificate
instead.

The portal's own pages are sign-in, profile, consent and **My data** (`/p/{keyword}/privacy`, R1-T2):
the person asks for a copy of their data, a portable file, a correction, a restriction, an
objection or erasure, giving their password again to prove it is them
(`POST /{keyword}/api/v1/me/privacy-requests`), and follows each request's status and deadline
(`GET` there). A request is a data subject request about their verified email address, worked by
staff with the others under the deployment's law.

## Switching an entity to a metadata form

A record page opens the entity's hand-written form unless the deployment switches the entity to a
published metadata form: the setting `forms.runtime_entities` maps entity logical names to form ids
(`{"deal": "<form id>"}`). A switched entity's record page draws that form with the runtime
renderer (tabs, columns, live rules, field security, form hooks) and creates or saves records
through it; `GET /api/v1/model/entities/{entity}/runtime-form` answers the form, or 404 when the
entity keeps its own. The hand-written form stays in the code until the switch is verified; removing
the entity from the setting brings it back.
