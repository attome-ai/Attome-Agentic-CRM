# Builder guide

For the people who shape a deployment to a business: its entities and fields, forms and menus,
rules, flows and packs. Everything is metadata: it changes through the admin screens or the API,
never through SQL, and every change is audited and can be moved between deployments as a changeset.

## Entities and fields

An entity is a table of records (accounts, cases, invoices); a field is one of its columns. Create
and change them in the entity screens or at `/api/v1/admin/entities`. Before a change to a table in
use, ask how it will run: `POST /api/v1/admin/entities/{id}/change-plan` answers instant, online or
background for each change, without writing anything ([changing a live table](../schema-changes.md)).

Field types include text, number, currency, date (with Hijri display), choice and multi-choice,
lookup to another entity, file and image, formula, rich text, colour and icon. A field can be
required, unique, sensitive (masked unless a field profile opens it) or read-only after create.

## Forms, menus and other model objects

Forms, option sets, menus (navigation), record types, reply templates, agents, prompt overrides,
environment variables and guided tours are model objects: drafted, validated, then published at
`/api/v1/admin/model/{kind}`. A draft never affects people until it is published; every version is
kept, and two versions can be compared.

- **Record types** give one entity several forms and stages (a "complaint" and a "request" case).
- **Menus** are filtered per role.
- **Guided tours** walk a person through a screen once; see the tour kind's fields in the model
  screen.

## Rules and flows

- **Business rules** (`/api/v1/admin/business-rules`) set defaults, compute values, require or lock
  fields and refuse a save, in the rule language ([functions](../rule-language.md)).
- **State models** (`/api/v1/admin/state-models`) give a record its stages and the transitions
  between them, with who may move it.
- **Workflows** react to record changes and schedules: notify, assign, create records, wait for
  approval, call a webhook.
- **Duplicate rules** catch the same customer twice ([duplicates](../duplicates.md)).

## Packs and changesets

A pack is a set of changesets: the entities, fields, forms, roles and sample data of one business
area (CRM, sales, service, HR...). `attome init --pack crm,sales` installs packs; at runtime a builder
plans and applies changesets at `/api/v1/admin/metadata/changesets/plan` and `.../apply`. Applying
is recorded in a ledger, so applying again changes nothing, and production can require a second
person to approve.

Region presets (Saudi Arabia, the UAE, Egypt) are the `regions` pack; the first-run wizard installs
it.
