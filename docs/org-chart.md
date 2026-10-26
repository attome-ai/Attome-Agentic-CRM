# Org charts

Org charts (roadmap D23) record who reports to whom at a customer, and who is on a deal's buying
committee.

The fields come from two packs:

- the crm pack (`packs/crm/changesets/0003-crm-org-chart-enrichment.json`) adds, on `contact`:
  `reports_to`, `dotted_line_ref`, the department and the former-employee fields;
- the sales pack adds the export template (`0023-sales-org-chart-export.json`) and org chart drafts
  (`0024-sales-orgchart-drafts.json`).

Every route below is in the sales module and answers `404` when that module is off.

## What is off by default

Nothing writes a reporting line on its own:

- **No reporting lines** until a person sets them, or accepts a draft.
- **No drafts** until someone asks for proposals for an account.
- **No coverage gaps** until a deal stage lists the roles it requires
  (`opportunity_stage.required_contact_roles`).
- **Influence and attitude** on a deal's contacts are shown only to holders of the Deal Attitude
  field profile.

## The reports-to rule

`contact.reports_to` (the solid line) and `contact.dotted_line_ref` (the dotted line) are
engine-managed. The generic record API refuses them; they change only through
`PUT /api/v1/sales/contacts/{id}/manager` (`{manager_id, line}`, with the contact's `row_version`
in `If-Match`). The route checks three things:

- the caller may update the contact and read the manager;
- **the manager works at the same account, or at another account in its group (D2), and no
  further.** Two accounts are in one group when they share the top of their `parent_account_ref`
  chain. A manager at an unrelated account is refused with `422`.
- the line forms no loop: the manager does not report, along the same kind of line, to the contact.

The change goes through the records engine, so row version, validation, audit (one
`sales.manager_set` event per change) and the change feed apply. The answer names the previous
manager, so setting it back undoes the change.

## Reading the chart

`GET /api/v1/sales/accounts/{id}/org-chart` returns the account's contacts that the caller may read,
arranged by who they report to.

| Option | Effect |
|---|---|
| `group=true` | The whole group: every account sharing the top of the parent chain. |
| `expand=id,id` | Opens collapsed branches. Branches deeper than three levels collapse to a count unless named. |
| `cursor` | The next page. A call reads at most 500 contacts, by id. |

A contact whose manager is missing or not readable is listed as `unplaced`, never under someone
else.

`GET /api/v1/{entity}/{id}/ancestors` and `.../descendants` take `?field=` to choose which
self-referencing lookup to walk: `reports_to` or `dotted_line_ref` for a contact. Without it, an
entity with two such lookups answers `422`, asking for one.

## People who leave

`POST /api/v1/sales/contacts/{id}/left` (`{left_on, new_account_id?}`, with `If-Match`) keeps the
contact and its history, marks it `is_former_employee` with `left_on`, and lists in
`needs_new_manager` the contacts who reported to it.

With `new_account_id`, it also creates the person's contact at that account. The duplicate rules
apply to it; a likely duplicate is refused before anything is written. A `moved_to` relationship
links the old contact to the new one.

## Buying committee

`GET /api/v1/sales/opportunities/{id}/committee-map` returns:

- the account's chart;
- each contact on the deal, with their role;
- the "influences" links between them;
- the roles the deal's stage requires;
- the coverage gaps.

A gap is either a required role nobody on the deal holds, or a high-influence contact nobody has met
in the last 180 days (no meeting activity regarding them). The second kind is shown only to someone who may read influence.

The gaps are stored per deal and recomputed from the change feed when the deal or its contact
roles change.

## Drafts

`POST /api/v1/sales/accounts/{id}/org-chart/propose` queues a job. The job reads the account's
contacts that the requester may read, and writes open drafts of who each unplaced person probably
reports to, plus their department where it is missing.

Drafts are proposed from job titles and departments, in English and Arabic. No model is used and no
record text leaves the deployment.

`POST /api/v1/sales/orgchart-drafts/{id}/decide` (`{accept}`):

- **accept** sets the manager through the manager route above, with all its checks;
- **reject** only marks the draft.

A decided draft cannot be decided again.

## Export

`POST /api/v1/sales/accounts/{id}/org-chart/export` (`{format: "pdf", locale}`) queues a PDF of the
account's people through docgen. It answers `202` with the `render_id`, which
`GET /api/v1/docgen/renders/{render_id}` follows. Any format other than `pdf` is refused with
`422`.

## Agent tools

These four tools act as the person and see only what the person may read:

- `sales.orgchart.read`
- `sales.committee.read`
- `sales.coverage.gaps`
- `sales.orgchart.propose`

`sales.orgchart.propose` only queues drafts.
