# Revenue recognition: the policy guide

For finance teams and auditors. It lists every setting that shapes how Attome recognises revenue, the
order in which standalone selling prices are found, how contract changes are treated, and how a month
is closed. The treatments follow the IFRS 15 model (identify the contract and its obligations, allocate
the price, recognise as each obligation is satisfied), but Attome is not certified against IFRS 15 or any
other standard.

**An auditor must review and accept this configuration before revenue figures from Attome are used in
production financial statements.** Record the acceptance, and repeat it after any change to the
settings below.

## Switches and settings

| Name | Kind | Default | What it decides |
|---|---|---|---|
| `revrec.basic` | flag | off | Revenue recognition at all: schedules, the close, the reports. |
| `revrec.contracts` | flag | off | Revenue contracts and performance obligations built from orders, subscriptions and invoices; contract combination. |
| `revrec.ssp_allocation` | flag | off | Allocating a contract's price over its obligations by standalone selling price. Off: each obligation keeps its own line amount. |
| `revrec.ssp_list_discount_percent` | setting, 0 to 100 | 0 | The SSP fallback from a list price: list price less this percent. |
| `revrec.ssp_cost_margin_percent` | setting, 0 to 1000 | 0 | The SSP fallback from cost: cost plus this percent. |
| `revrec.loyalty_point_value` | setting, ≥ 0 | 0 | The value of one loyalty point; part of an order's price is deferred for the points it earns. 0: nothing is deferred. |
| `revrec.loyalty_breakage_percent` | setting, 0 to 100 | 0 | Points expected never to be used; lowers the deferral and raises what each used point recognises. |
| `revrec.posting_target` | setting | `ledger` | Where an approved close posts: Attome's ledger, or `connector:<integration system id>` to send the journal to an ERP once. |

Settings are deployment-wide and changed through `PUT /api/v1/admin/settings/{key}`; each change is
audited.

## Standalone selling prices

An obligation's SSP is the first of these that gives a price, and the method used is stored on the
obligation:

1. **Entered** (`entered`): the product's SSP entry valid on the contract date, the latest version first.
   `PUT /api/v1/ledger/revrec/ssp` adds a version (holders of `ssp_entry.create`); earlier versions stay,
   so a past allocation still names the one it used.
2. **Observed** (`median_standalone`): the median price of the product sold on its own over the last
   365 days, counting only sales within 15 % of the overall median, and only with at least 3 of them.
3. **List less discount** (`list_less_discount`): the list price less `revrec.ssp_list_discount_percent`.
4. **Cost plus** (`cost_plus`): the cost plus `revrec.ssp_cost_margin_percent`.

The contract price is split over the obligations in proportion to their SSPs, so a discount falls on each
in proportion. The cent left by rounding goes to the obligation with the largest SSP. An obligation with no
SSP by any method weighs its own line amount. Allocation never changes a contract with a locked line.

## Recognition patterns

| Pattern | Recognised |
|---|---|
| `point_in_time` | In full in the month of delivery or acceptance; nothing before. |
| `ratable` | Evenly per day over the service dates. |
| `milestone` | Each completed milestone's share in the month it completed. |
| `usage` | Each rated usage amount in the month it was rated. |
| `percent_complete` | Allocated amount × cost to date ÷ estimated total cost, less what was recognised. |

## Contract changes

A change (a subscription amendment, a change order, a credit note) is previewed before it touches any
schedule (`POST /api/v1/ledger/revrec/changes`), then applied or discarded
(`.../changes/{id}/apply`, `.../changes/{id}/discard`). The treatment is chosen from the change:

- **Separate contract**: goods added that are distinct and priced at their standalone price. Existing
  schedules stay as they are.
- **Prospective**: the goods still to deliver are distinct from those delivered. The new total less what is
  already recognised is spread over the planned lines.
- **Cumulative catch-up**: otherwise. The planned lines are rescaled and the difference to date lands in the
  first open line.

A revenue accountant may name a different treatment; the preview records the override. Applying only
writes lines still planned with the amount the preview saw, never a recognised or locked line. Contracts
of one customer that are in substance one deal may be combined
(`POST /api/v1/ledger/revrec/contracts/combine`): their obligations move to the first and the others
close as `modified`; this is refused once any of their lines is locked.

## The monthly close and its approval

`POST /api/v1/ledger/revrec/close` opens the month's close; a background job recognises the month's
planned lines and writes each contract's deferred and unbilled balance. The close then waits for approval
by a revenue controller. Once approved, `POST /api/v1/ledger/revrec/close/{id}/post` posts one journal entry
per contract through the `revrec_close` posting rule (or sends it to the ERP named by
`revrec.posting_target`, once, keyed by the close) and locks the month's lines. A locked line never changes;
a later correction is a change in an open month. [The monthly revenue close](revenue-close.md) has the steps.

## Audit trail

Every step writes a business event: `revrec.ssp_set`, `revrec.contracts_combined`,
`revrec.change_previewed`, `revrec.change_applied`, `revrec.change_discarded`, `revrec.close_started`,
`revrec.close_failed` and `revrec.close_posted`. Settings changes are security events.
