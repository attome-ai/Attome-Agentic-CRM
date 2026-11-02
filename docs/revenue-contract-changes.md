# Revenue contract changes

When a contract changes after revenue recognition has started (a subscription amendment, an order change
order, a credit note), its schedules have to follow. A change is always **previewed first** and applied
only when a revenue accountant (holder of `revenue_contract.update`) applies the preview. Revenue
recognition (`revrec.basic`) must be on.

## How a change is treated

The treatment follows IFRS 15, decided from two facts you give with the change:

| The change | Treatment | What happens to the schedules |
|---|---|---|
| adds goods that are distinct and priced at their standalone price | separate contract | nothing; the added goods are recognised under their own contract |
| otherwise, the goods still to deliver are distinct from those delivered | prospective | the new total less what is already recognised is spread over the planned lines |
| otherwise | cumulative catch-up | the planned lines are rescaled to the new total, and the difference to what should have been recognised to date lands in the first open line |

You may name a treatment yourself; the preview then records that the rule was overridden. Recognised and
locked schedule lines never change, under any treatment.

## Routes

- `POST /api/v1/ledger/revrec/changes` `{contract_id, change_kind, source_ref?,
  adds_distinct_at_standalone_price, remaining_distinct, treatment?, obligations: [{obligation_id,
  new_total}]}`: stores the preview (each planned line's amount before and after) and changes nothing
  else. `change_kind` is `amendment`, `change_order` or `credit_note`.
- `POST /api/v1/ledger/revrec/changes/{id}/apply`: writes the previewed amounts and each obligation's new
  allocated amount. If a line was recognised, locked or changed since the preview, nothing is applied
  (409): preview again.
- `POST /api/v1/ledger/revrec/changes/{id}/discard`.

Each step is audited on the contract.

## On screen

`/xrm/admin/revrec/changes/{id}` (the `contract_change` record's id) shows a previewed change: for each
obligation, every open period's amount before and after and the difference, the periods in the reader's
calendar (Hijri or Gregorian), with **Apply** and **Discard**. It reads right to left in Arabic. The ledger
pack's changeset `0006` adds list views (open contracts, obligations to satisfy, this month's planned
lines, standalone prices, changes to apply, closes, deferred and unbilled balances), a **Revenue** menu
and Arabic labels for every revenue status and kind.
