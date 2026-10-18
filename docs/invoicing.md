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

The `BillingAfterIssue` job runs the issue hooks in order: e-invoicing, then the document, then
sending. Each is safe to repeat.

- **E-invoicing (ZATCA).** With `einvoice.enabled` and an onboarded device (see below), the issued
  document is written as ZATCA's UBL invoice, stamped on the device (its counter and hash chain kept
  under a row lock) and cleared when the buyer has a VAT number, reported otherwise.
  `invoice.einvoice_status` follows: `pending`, `cleared`, `reported` or `rejected` (ZATCA's
  messages on `GET /api/v1/billing/invoices/{id}/einvoice`). A pending document is retried every
  five minutes, and the next hooks run once it clears or reports.

- **Document.** The invoice in Arabic and English side by side, with seller (`billing.seller_name`,
  `billing.seller_vat_number`) and buyer VAT numbers and the issue date in Gregorian and Hijri, is
  rendered by the docgen sidecar and attached to `invoice.document` as the person who issued it.
- **Sending.** The PDF is emailed to the invoice's contact and the invoice moves to `sent`. While
  e-invoicing is `pending` or `submitted` the send waits; a `rejected` or `failed` invoice is never
  sent; without a contact email the invoice stays `issued` for a person to send.

## E-invoicing devices

`POST /api/v1/einvoice/devices` (`einvoice.manage`, Finance Manager) creates a device (EGS unit)
with its signing key and certificate request, from the seller settings (`billing.seller_name`,
`billing.seller_vat_number`, `billing.seller_crn` and the seller's national address).
`POST /api/v1/einvoice/devices/{id}/onboard` with the Fatoora portal's OTP gets the compliance
CSID, passes one compliance check per document kind and gets the production CSID. Keys and secrets
are encrypted under `einvoice.key_encryption_key`. Buyers on standard (B2B) invoices need their
national address on the account (`billing_street`, `billing_building_number`, `billing_district`,
`billing_city`, `billing_postal_zone`).

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
- `POST /api/v1/billing/payments` records a payment received by transfer, cheque or cash and
  allocates it (oldest due first, or as the payer says); the rest is the customer's credit, applied
  later with `POST /api/v1/billing/accounts/{id}/apply-credit`. `POST .../payments/{id}/reverse`
  (`billing.payment_reverse`) reverses a payment with a reason; nothing is ever deleted.
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

## Payment gateways

Card and wallet payments run through the customer's own merchant account at Moyasar or HyperPay;
Attome never sees a card number.

Card data stays with the gateway: the payer types it on the gateway's page or in its form, so the
deployment follows the SAQ A pattern. This describes scope; it is not a PCI certification. Off until
set up: every gateway (until `billing.gateway.rules` names one), payment links and the payment page,
saved-card charges (`billing.saved_methods.enabled`), and reconciliation. Not built yet: credit limits
and paying from the customer portal.

- A gateway is an integration system of kind `payment_gateway`: its `base_url` (Moyasar
  `https://api.moyasar.com/v1`; HyperPay `https://eu-prod.oppwa.com`, test `https://eu-test.oppwa.com`),
  `config` `{"gateway": "moyasar"}` or `{"gateway": "hyperpay"}`, and its credential:
  - Moyasar: `{"secret_key": "sk_live_...", "webhook_secret": "..."}`, the webhook secret being the
    one entered when adding the webhook in Moyasar's dashboard.
  - HyperPay: `{"access_token": "...", "entity_ids": {"card": "...", "mada": "...", "apple_pay": "..."},
    "webhook_secret": "<the webhook's 64-character hex key>"}`; mada always has its own entity.
- `billing.gateway.rules` picks the gateway for a payment by currency, payer country and amount; the
  first rule that matches wins.
- `POST /api/v1/billing/payment-links` (`payment_link.create`) makes a single-use link for an issued
  invoice's open amount, an order's total, or an amount for an account, valid 72 hours unless
  `expires_in_hours` (1 to 720) says otherwise. The link is shown once:
  `<app.public_frontend_url>/pay/<public_id>.<secret>`; only a hash of the secret is kept. The page
  reads `GET /api/v1/pay/{token}` and starts payment with `POST /api/v1/pay/{token}/checkout`; both
  are public, rate limited, and answer the same 404 for a wrong, expired, used or cancelled link.
  A link is used when its payment succeeds, which pays its invoice first.
- The payer opens the link at `/pay/<token>`: a public page, in Arabic or English (from the payer's
  browser, with a toggle, right to left in Arabic), showing the amount, the invoice number and the
  seller. Pay sends them to the gateway's own page (Moyasar), or shows the gateway's form on the page
  (HyperPay). Card details are only ever typed on the gateway's page or form. HyperPay's form needs
  its host allowed in the Content-Security-Policy (`script-src`, `frame-src`), which ships without it.
- Billing > Payments in the sidebar lists payments, with views of this month's payments, unallocated
  credit, open disputes and payouts with differences.
- Saved cards (off until `billing.saved_methods.enabled` is on): each day, a due invoice with an open
  amount is charged to its account's default saved payment method. A charge whose answer was lost is
  asked again with the same key, so the gateway charges it once. A failed charge is retried after the
  days in `billing.retry.days` (1, 3 and 7 by default), and the invoice's contact is emailed a fresh
  payment link each time; after the last try the invoice is handed to collections
  (`billing.invoice.collections_handoff` on the change feed). HyperPay's card updater keeps a saved
  card's number and expiry current.
- Refunds: `POST /api/v1/billing/payments/{id}/refunds` (`payment.refund`, Finance Manager) refunds
  part or all of a paid payment, never more than is left after earlier refunds. Above
  `billing.refund.approval_threshold` (0 = never) it waits for a `billing.refund` approval. The refund
  goes back through the payment's gateway (or, for a transfer, is recorded for a person to pay back);
  the payment becomes `partially_refunded` or `refunded`, and each invoice it paid gets a draft credit
  note for its share, for finance to review and issue.
- Disputes: a chargeback the gateway reports (HyperPay) opens a `payment_dispute` with its evidence
  deadline (seven days when the gateway names none), marks the payment `disputed` and tells the
  Finance Managers in the app. `GET /api/v1/billing/disputes/{id}/evidence` lists the paid invoices'
  PDFs and the files attached to those invoices and to the link's order; a person submits the evidence
  to the gateway.
- Settlement: each day the gateways' payouts for the day before are matched to their payments by
  gateway reference (`gateway_payout`): `matched` when every payment is known and the gross, fees and
  net agree, otherwise `difference` with the unmatched references and expected totals; the stored
  query "Billing: Payouts with differences" lists those. Each payout's fees go on the change feed as
  `billing.gateway_fee` for the ledger to post. Moyasar offers payouts to aggregation merchants only.
- The gateway's webhook URL is `https://<deployment>/api/v1/billing/gateways/<system id>/webhook`.
  A call whose secret (Moyasar) or encryption (HyperPay) does not verify gets `401`. Each verified
  event is stored once and applied by a background job, so a redelivered event never changes a
  payment twice; an event that cannot be applied (no payment has its reference) keeps its error in
  `billing_gateway_event` and is retried up to ten times.

## Roles

| Role | May |
|---|---|
| Billing Clerk | Create and edit drafts, lines and schedules. |
| Accounts Receivable | The clerk's work, plus issue and credit; record payments and create payment links. |
| Finance Manager | All of it, plus write off, refund, reverse payments, read payouts and manage tax rates. |
| Billing Viewer | Read invoices, lines, schedules, tax rates, payments, refunds and disputes. |
| Payments Viewer | Read payments, refunds, disputes and payment links. |

A payment's gateway reference and fee, and every payout field, are sensitive: only the Finance
Manager (field profile "Payment finance fields") reads them, and search, reports and queries mask them
for everyone else. A saved card's gateway token is readable by no role (field profile "Saved card
tokens", given to none); the engine reads it to charge the card.

## Agents

`billing.find_invoices`, `billing.account_balance` and `billing.explain_tax` read as the person;
`billing.draft_invoice` and `billing.draft_credit_note` file drafts after a person confirms.
Issuing, cancelling, issuing a credit note and writing off stay with people.

Payment tools (F5-T13): `billing.payment.lookup` finds payments the caller may read, and
`billing.payment_link.create` makes a payment link for an open invoice; it is consequential, so the
agent asks before it acts, and it sends nothing. Refunds, saved payment methods, write-offs and credit
limits have no agent tool.
