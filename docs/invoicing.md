# Invoicing

Invoices from request to settled: drafts priced by the tax engine, numbers taken on issue, an issued
invoice that never changes, corrections as credit and debit notes, the bilingual document and its
sending, payment status, statements, ageing and write-offs. The records come from the billing pack
(`packs/billing`, installed after crm, sales, finance, regions, vendor-supplier and
contract-management); the engine is `crates/engine/attome-billing`, gated on the `billing` module.

## Records

`invoice` is the finance pack's invoice, extended by the billing pack: kind (`invoice`,
`credit_note`, `debit_note`, `deposit`, `pro_forma`), account and contact, billing address, the
buyer's VAT number, currency and exchange rate, payment terms, supply date, series, the original
invoice and reason of a note, stored totals (net, discount, VAT, grand, paid, open, written off),
the payment status and the attached document. `invoice_line` holds a product or free text, unit,
quantity, unit price, discount, VAT category, rate, VAT amount, line total, the period served and
the source it came from. `invoice_schedule` repeats a template invoice monthly, quarterly or yearly.
Tax rates are the regions pack's `region_tax_rate` (country, category, rate, effective dates).

## Draft, issue, locked

- `POST /api/v1/billing/invoices/{id}/recompute` prices a draft's lines with the rate in force on
  the supply date (else the issue date, else today) and stores line and invoice totals, rounded per
  line in the currency's minor units, then summed. It needs `invoice.update` and
  `invoice_line.update`.
- `POST /api/v1/billing/invoices/{id}/issue` (`billing.issue`) numbers a draft
  `{series}-{year}-{000001}` (series `INV`, credit notes `CRN`, debit notes `DBN`, deposits `DEP`,
  or the invoice's own `series_key`) under a per-series lock, so numbers are gap-free: a draft has
  none, and a busy series answers `409` to retry. Issuing dates the invoice, sets the due date from
  the payment terms, locks the lines and writes the ledger posting row. Above
  `billing.issue_approval_threshold` it opens a `billing.issue` approval instead. A pro forma
  invoice is never issued (`409`); convert it with `POST …/{id}/convert-pro-forma`.
- After issue, editing the invoice's buyer, dates, number or amounts, or any line, is refused by the
  pack's business rules. Payment fields are the engine's only.

## After issue

The `BillingAfterIssue` job runs the issue hooks in order: e-invoicing (AG2, when built), then the
document, then sending. Each is safe to repeat.

- **Document.** The invoice in Arabic and English side by side, with seller (`billing.seller_name`,
  `billing.seller_vat_number`) and buyer VAT numbers and the issue date in Gregorian and Hijri, is
  rendered by the docgen sidecar and attached to `invoice.document` as the person who issued it.
- **Sending.** The PDF is emailed to the invoice's contact and the invoice moves to `sent`. While
  e-invoicing is `pending` or `submitted` the send waits; a `rejected` or `failed` invoice is never
  sent; without a contact email the invoice stays `issued` for a person to send.

## Corrections

- `POST …/{id}/credit-notes` (`billing.credit`) drafts a credit note for chosen lines of an issued
  invoice, negated, with a reason. A line is never credited beyond what is left on it, checked on
  create and again when the note is issued.
- `POST …/{id}/debit-notes` drafts a debit note with new charges.
- `POST …/{id}/cancel` issues a full credit note for whatever is still uncredited.
- `POST …/{id}/apply-deposit` deducts an issued deposit invoice from a final draft, once.

## Requests and schedules

`POST /api/v1/billing/invoice-requests` (`billing.issue`) stores an invoice another feature asks
for, once per `source_kind` and `idempotency_key`. Every five minutes the pending requests become
drafts, created as the person who asked: one per request, or one per currency and day for an
account with `billing_group_invoices`. Daily, each enabled schedule whose `next_run` has come is
copied into a draft (once per period) and moves on.

## Payments, statements, ageing, write-offs

- Payment status, paid and open totals follow payment allocations and the due date; a nightly sweep
  marks past-due open invoices `overdue`. Nobody marks an invoice paid by hand.
- `GET /api/v1/billing/accounts/{id}/statement?from=&to=` gives the opening balance, the period's
  documents, payments and write-offs, and the closing balance, per currency.
- `GET /api/v1/billing/ageing?as_of=` pages the open amounts per account and currency in current,
  1-30, 31-60, 61-90 and over-90-day buckets; `GET …/ageing/totals` sums them per currency. Both
  follow the caller's record scope on accounts, so a salesperson sees only their accounts.
- `POST …/{id}/write-off` (`billing.write_off`) writes off up to the open amount with a reason;
  above `billing.write_off_approval_threshold` it waits for a `billing.write_off` approval.

In the app, Billing in the sidebar opens the invoices, the receivables ageing (each account links to
its statement) and the schedules. Amounts keep their currency's decimals (three for KWD, BHD, OMR
and JOD) and the screens read right to left in Arabic.

## Roles

| Role | May |
|---|---|
| Billing Clerk | Create and edit drafts, lines and schedules. |
| Accounts Receivable | The clerk's work, plus issue and credit. |
| Finance Manager | All of it, plus write off and manage tax rates. |
| Billing Viewer | Read invoices, lines, schedules and tax rates. |

## Agents

`billing.find_invoices`, `billing.account_balance` and `billing.explain_tax` read as the person;
`billing.draft_invoice` and `billing.draft_credit_note` file drafts after a person confirms.
Issuing, cancelling, issuing a credit note and writing off stay with people.
