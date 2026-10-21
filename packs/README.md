# Pack metadata

The metadata half of each pack: changesets, form and page layouts, sample data and translations.
A pack installs and uninstalls by publishing these changesets.

## library-core

The MENA base library other packs and agents build on (A1-T12): `party` (a person or an
organisation), `person` (the four-part Arabic name, first, father, grandfather and family, plus the
English names; `national_id`, `iqama_number` and `emirates_id` are sensitive personal data),
`organisation` (commercial registration, VAT number, parent), `address` (the Saudi national address:
short address, building number, street, district, city, postal code, additional number), `work_item`
and `agreement` (with a Hijri start date). Activity, product and payment come with the crm, sales and
finance packs. Install it with `--packs crm,library-core`.

## billing

Subscriptions and customer payments, the records the `billing` engine works on. `0001`: a
`subscription` per account (term, billing timing, frequency and alignment, renewal, trial, pause and
cancel), its `subscription_line`s and charge models, the append-only dated `subscription_segment`s a
change writes, and the `subscription_charge`s a billing run plans (F3). `0002`: `customer_payment`,
append-only `payment_allocation` to invoices, `payment_refund`, `payment_dispute`,
`saved_payment_method` (the gateway token is masked), `payment_link` and `gateway_payout`, plus credit
limit, payment terms and credit hold on `account` (F5). `0005`: invoicing (F4) on the finance pack's `invoice`: kind (invoice,
credit and debit note, deposit, pro forma), payment status, account and contact, buyer VAT number,
currency, supply date, number series, the original invoice of a note, stored totals and the e-invoice
status; `invoice_line` with VAT category, rate and amount; `invoice_schedule` for recurring
invoices. Tax rates are the regions pack's `region_tax_rate`. Roles: Billing Clerk, Accounts
Receivable (issue, credit), Finance Manager (also write-offs and tax rates) and Billing Viewer. It builds on crm (`account`) and sales
(`product`, `order`, `quote`) and on an `invoice` and a `contract` entity; install it after them.

## commission

Sales commissions (F10): `comp_plan` with versions and components (rate tables, tiers, caps, gates),
`plan_participant`, `comp_period`, `comp_credit` from deals, orders, invoices and payments,
calculation runs (`comp_run`) with `comp_statement_line`s and `comp_payout`s, adjustments, disputes and
draws; the `commission` engine computes the amounts. `0002` adds the Commission Seller (reads only
what they own), Commission Manager (their team), Sales Ops and Commission Finance (all) roles, and
makes every amount, cap and balance sensitive behind the Commission Amounts field profile those
roles hold, so search, reports and query execution mask pay for everyone else.

## marketing

Email deliverability (E6): the `marketing_deliverability_policy` and an email status with engagement
and sunset dates on `contact` and `lead` (from crm).

## offline

Offline profiles (B18): `offline_profile` per role (storage and days-offline limits) and
`offline_profile_entity` per entity (the stored query, related lookups, files, row cap) the
`offline` engine syncs to devices.

The sales pack's `0006` adds call lists and the power dialer (D21): `call_list`, `call_list_member`,
append-only `call_attempt`, `call_outcome_rule`, `calling_hours` and `caller_id_rule`.

## fulfilment

Fulfilment and delivery (F6): `stock_location`, `fulfilment_order` and lines sourced from an `order`,
`shipment`s with packages and lines, append-only `delivery_proof`, holds and exceptions.

## partner

Partner relationship management (F9): programmes and tiers, deal registration, applications and
onboarding, certifications, market development funds with requests and claims, tier change
proposals, and partner fields on `account` and `lead`.

## workforce

Workforce management (G17): planning groups, shift templates and breaks, rule sets per country,
schedules and shift assignments, preferences, swap requests and overtime offers, which the
`workforce` engine's staffing and shift-rule checks work on.

The marketing pack's `0002` adds campaigns with members and marketing lists with combinations.
The sales pack's `0007` adds opportunity lines and schedules, `0008` competitors and win-loss reviews.
`0017` adds the win and loss reports: win rate overall, by competitor and by quarter, reasons by
competitor and by segment, region and size, discount and cycle length by competitor, and losses on
price by discount band. A deal counts against a competitor when it was lost to it or the competitor
is on the deal.

## privacy

Privacy programme (R5): a record of processing activities, impact assessments (DPIA) and personal
data breaches with when they were found and the deadline to notify the regulator.

## internal-audit

Internal audit (R13): engagements, workpapers with evidence files, findings with rating, owner and
due date, and follow-ups until a finding is verified closed.

## bcm

Business continuity (R15): business impact analysis per process (RTO, RPO, maximum tolerable
downtime), continuity plans and exercises with achieved recovery times.

## recruiting

Recruiting (W7): requisitions, job postings, candidates (personal data), applications through
stages, interviews with scorecards, and offers (salary masked).

## field-service

Inventory (I6): stock balances per product and location as a roll-up of append-only movements,
reservations, serial numbers and lots; returns (I11) with lines, reasons, the return-window check,
inspection and disposition.

The human-resources pack's `0002` adds positions, leave types and balances and labelled HR documents
(a health document is special-category data); the customer-service pack's `0002` adds entitlements
and their usage ledger (G10), and its `0003` links a case to its entitlement and the entitlement to
its SLA policy, which the SLA engine applies before the policy rules (G9-T2).

## itsm

IT service management on the platform service ticket: configuration items with classes and typed,
directional relationships (H5); urgency, major-incident manager, affected CI and restore time on the
ticket, and post-incident reviews with actions (H1); problems, their incidents and known errors with
workarounds (H2); change requests with type, risk, window, plans, affected CIs and pre-approved
standard templates (H3); releases grouping changes and tasks with a go/no-go decision (H4).

The sales pack's `0009`–`0011` add forecasts, territories, playbooks, deal teams and splits, quote and
order totals, quotas, and contact-role influence behind the Deal Attitude field profile (`0012`
adds product-mix reports and `0013` the team calling metrics); the crm pack's
`0003` adds the contact org chart, enrichment fields and ISIC sections; the marketing pack's `0003`
adds events, its `0004` nurture programmes, tracks and content with a lifecycle stage on leads
and contacts, and its `0005` the website tracking sites, visit summaries and watched pages.

## community

Community forums (G13): `forum_category` (with an Arabic name and a portal switch), `forum_thread` (a
question in a category, open, answered or closed, pinned, with its accepted answer), `forum_post`
(replies, staff replies and their vote score), `forum_vote` (one voter's vote on a post or an idea) and
`forum_idea` (new, under review, planned, in progress, done or declined, with the votes and our
response). A new thread, post or idea that holds a link or a blocked term is set to `pending` by a
business rule and waits in the Community: Moderation Queue; a moderator approves or rejects it, and an
empty moderation status reads as published. Edit the rules to add your own blocked terms. Roles:
Community Moderator and Community Viewer.

## ledger

General ledger (W5): the chart of accounts, accounting periods that open and close, journals,
append-only journal entries with balanced debit and credit lines, and posting rules that map a
source document kind to the accounts it debits and credits. The Accountant and Ledger Viewer
roles ship with it; the `ledger` engine is gated on the `ledger` module.

## procurement

Procurement (W3): purchase requisitions and their lines, purchase orders to a vendor with lines
that track received and billed quantities, goods receipts against order lines, and vendor bills
with a three-way-match status; each document has a number within its series and a lifecycle.
The Requester, Buyer, Receiver and AP Clerk roles and the open-orders and bills-due reports ship
with it. Needs the vendor-supplier pack; the `procurement` engine is gated on the `procurement`
module.

## Industry packs

Each industry pack is one changeset of entities, a stage model on its main record, roles with their
grants, report queries for its dashboards and a sidebar. Systems of record (core banking, HIS, ERP,
SIS, BSS and OSS) stay outside and are referenced by id, never copied.

- `government` (X5): licences with review, inspection, issue, suspension, revocation and expiry;
  checklists, fees, inspections, violations with objection and appeal, correspondence numbered per
  Hijri or Gregorian year, committees and numbered decisions, benefit cases.
- `financial-services` (X3): products, financial accounts read from core banking, KYC with risk rating
  and periodic review, financing applications with Islamic structures, credit reviews decided by a
  person, regulated complaints, masked cards.
- `healthcare` (X4): patients (health data masked as special category), providers, locations,
  appointments, visits, referrals with SLAs, NPHIES pre-authorisation, care programmes, complaints.
- `manufacturing` (X6): customer sites, sales agreements with planned and actual volumes, rebates and
  payouts, tenders with local-content scores, samples, quality complaints through 8D, compliance
  documents.
- `nonprofit` (X7): households, funds by type (zakat, sadaqah, waqf and others), gifts with
  yearly-numbered receipts, pledges, appeals, waqf assets and distributions, programmes, aid cases kept
  apart from fundraisers by role.
- `education` (X8): families, students and guardians with consent, programmes and intakes, admissions
  through stages to an offer, scholarships, fee plans, success alerts.
- `retail` (X9): chains, routes, outlets, store visits and shelf audits, in-store and van orders,
  seasonal trade promotions and claims, retailer agreements, recalls.
- `telecom-energy` (X10): service sites, a catalogue mirrored from the BSS, installed services and
  meters, connection and move requests, outages by area, regulated complaints, vulnerable-customer
  flags, dealers.

The enterprise-architecture pack's `0002` (X11) adds portfolio fields with TIME decisions, assessments,
interfaces, architecture reviews and roadmap items. The asset-management `0002`, field-service `0003`,
contract-management `0002`, vendor-supplier `0002`, finance `0002` and human-resources `0003`
changesets extend those packs (I8, I9, H6, I1, I5, I10, W1, W2, W4, W8).
The asset-management `0003` keys the software catalogue on name and version and seeds
end-of-support and end-of-life dates for common operating systems, databases, runtimes and office
software from endoflife.date (H6-T1); its `0004` reports entitled seats against installs and the
over-deployed products (H6-T2).
The contract-management `0003` (W1-T14) adds the Contract Manager, Legal, Contract Requester (own
requests only) and Contract Viewer roles; a confidential contract is read by Legal only (a grant
condition on the other roles, so lists, search and reports agree), and contract value, current
terms and clause text are sensitive behind the Contract terms profile managers and legal hold. Boot
adds a retention rule that proposes each contract for review seven years after its end date.
Its `0004` (W1-T13) records where a draft contract came from (`source_kind`, `source_id`): the
contract engine drafts one sales contract per accepted quote or confirmed order, gives each contract
type an intake offering, and drafts a contract of that type from each request filed under it.
The human-resources `0003` (W8-T1) adds HR offerings and HR cases on the service ticket (offering,
employee, a confidential flag and confidential notes behind the HR Confidential profile), and its
`0004` gives the HR Specialist role every case and the offerings, and adds an Employee role that
raises cases and sees only its own. The pack cannot know a deployment's other ticket roles, so keep
them off confidential cases with a grant condition on their `service_ticket.read`, in a customer
changeset:
`{"op": "add_role_grant_condition", "target": {"role": "<ticket role>", "privilege": "service_ticket.read", "condition": "is_confidential|0|false"}, "args": {"definition": {"field": "is_confidential", "operator": 0, "value": false}}}`.

## regions

Region presets (X12): the country, tax-rate and identity-document reference entities, then Saudi
Arabia (`0001`) and the UAE and Egypt (`0002`): currency, VAT rates, ID and registration-number
patterns with their check-digit rule, mobile and address formats, and a business-week calendar with
the fixed-date public holidays. Hijri holidays follow the moon sighting and are added per year.
