# The monthly revenue close

Each month's recognised revenue is closed once (F11-T7): the month's planned schedule lines are
recognised, every contract's deferred and unbilled balance is written, a controller approves, and the
revenue is posted to the ledger and the lines locked.

## Before the first close

- Revenue recognition is on (the `revrec.basic` flag).
- A posting rule (`gl_posting_rule`) for source kind **`revrec_close`**: the debit account is deferred
  revenue (or contract liability) and the credit account is revenue, in the journal it names.
- An open ledger period (`gl_period`) holding the month's last day.
- The person closing holds `revrec_close_run.create` (Revenue Accountant, Revenue Controller in the
  ledger pack's revenue roles).

## Closing a month

1. `POST /api/v1/ledger/revrec/close` `{"fiscal_period": "2027-01"}` opens the close and answers `202`
   with it. A month whose ledger period is closed is refused (`422`); asking again for a month already
   closing (or closed) answers that close.
2. A background job walks the contracts 500 at a time, marking the month's planned lines recognised and
   writing each contract's `revenue_balance_snapshot` for the month:
   - **billed to date**: issued invoices dated on or before the month's end, for the contract's source
     (the invoice itself, or the invoice lines whose `source_kind` and `source_ref` name its order or
     subscription); credit notes subtract and pro forma invoices do not count;
   - **recognised to date**: the contract's recognised and locked lines up to the month;
   - **deferred** is billed minus recognised when that is positive, **unbilled** when it is negative.

   The close then waits for approval (`ledger.revrec_close`, regarding the close).
3. Once approved, `POST /api/v1/ledger/revrec/close/{id}/post` posts the month's recognised revenue
   through the `revrec_close` rule, one journal entry per product dated the month's last day (each entry
   once, so a retry does not post twice), locks the month's lines and marks the close `posted`. If the
   approval was rejected or expired, the close becomes `failed` and the decision's comment is in its
   audit event; start the month again.

Starting and posting a month hold a lock per month, so two people cannot close the same month at once.

## Balances between closes and the reports

Every night the roll-forward rewrites each contract's balance snapshot for the current month as it stands
(no line changes status), so the reports below are current between closes. The ledger pack's changeset
`0007` ships them as reports: **Revenue: Waterfall** (planned revenue by future period), **Deferred
Roll-forward** (billed, recognised and deferred by period), **Unbilled Balance** (each contract's latest),
**Remaining Performance Obligations** (planned revenue per contract) and **Recognised vs Billed by
Customer**.
