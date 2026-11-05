# Pack metadata

The metadata half of each pack: changesets, form and page layouts, sample data and translations.
A pack installs and uninstalls by publishing these changesets.

A pack may also ship model objects (forms, pages, flows, dashboards and the other kinds
`attome model export` writes) under `model/<kind>/<pack>/<name>.json`, in the export file shape with
`app` set to the pack's name. Boot installs them after the pack's changesets and publishes each on
the pack's layer, all in one transaction. An upgrade replaces an object only while it is still the
pack's: if the customer published their own version or has a draft open, the customer's version is
kept, and an object a newer pack no longer ships is left in place. Both are listed with
`GET /api/v1/admin/model/pack-objects` and warned about in the boot log.

Ids differ per deployment, so a pack file names what its document refers to; a string that is
exactly one of these is replaced by the id at install, and a name that matches nothing stops the
install: `@entity:account`, `@attribute:account.industry`, `@view:account/Active Accounts`,
`@query:account/Open Pipeline` (`@query:/<name>` for a query of no entity), `@role:Sales Manager` and
`@<kind>:<app>/<name>` for another model object, this pack's own included (`@component:crm/kpi_tile`).

Ten packs ship a **metadata form** per entity they create (`model/form/<pack>/<entity>.json`, A12-T5),
generated from the entity's hand-written form: its tabs, sections, columns and fields, with tab and
section labels as catalog keys (`xrmForm.tabs.details`) that the form renderer translates. The
hand-written form stays the one shown until the entity is listed in `forms.runtime_entities` with its
published form's id (`docs/pages.md`).

A pack may also keep **golden workflows** in `golden/golden.json` (`attome-pack-golden/v1`): `packs`,
the packs to install first, in order (itself included), and `tests`, customer tests (`name`,
`description`, `definition`, as `docs/testing.md` describes them) over bilingual sample records. A
value `{"$ref": "<name>"}` in a step points a lookup at a record the test named earlier, and `{"$ref": "@caller"}` at the person the test runs as. The
attome-testapp test `pack_golden_workflows_pass` installs each pack's list and runs its tests, so they
run in the release gate's `tests` step on every release; nothing a test does is kept. Boot never reads
`golden/`.

Each pack also carries `pack.json`: its version (the minor part counts its changesets), its level
(`starter`, `standard` or `complete`) and the packs it depends on. `docs/pack-quality-bar.md` says what
each level needs.

## library-core

The MENA base library other packs and agents build on (A1-T12): `party` (a person or an
organisation), `person` (the four-part Arabic name, first, father, grandfather and family, plus the
English names; `national_id`, `iqama_number` and `emirates_id` are sensitive personal data),
`organisation` (commercial registration, VAT number, parent), `address` (the Saudi national address:
short address, building number, street, district, city, postal code, additional number), the party link
on `work_item` (the Work item base itself is a platform entity, V2-D1588, so the service ticket extends it)
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

**Sunset** (E6-T9, `0013` adds the policy's `reengagement_design_ref` and `reengagement_purpose`):
with `sunset_enabled` on, a nightly job sends one re-engagement email (the design, as an E3 send
under that consent purpose) to contacts and leads with no marketing engagement for `sunset_months`
(12 when unset), and sunsets (`marketing_sunset_at`) those who still have not engaged 14 days later.
Campaigns leave sunset people out. An open or click of a tracked email, a form submission or a
contact's reply to one of our emails (a shared mailbox, J2) brings a person back.

**Journey email step** (E8-T6, `marketing.send_email`: `design_id`, `purpose`, `on_blocked` skip or
wait, `send_time` now or best): before sending it checks consent for the purpose, the suppression
list, the sunset, the quiet hours of `marketing.journey_quiet_hours`, the working time (holidays
included) of the calendar `marketing.journey_calendar_ref` names, and the weekly cap
`marketing.weekly_message_cap` (3, shared with campaigns); a quiet hour waits, the others block
(`marketing_journey_block`). It sends once per run and step, as a one-recipient campaign send, so
the unsubscribe link and consent re-check apply. A test enrolment goes to the journey's first
`test_addresses` entry. SMS, WhatsApp, push, in-app and task steps are refused at publish
(`channel_unavailable`) until their senders exist.

`0020` adds the **marketing dashboards** (E28-T1) and the **Marketing Manager** role they land on
(business unit, position hierarchy): report queries for campaign performance (members, responses,
conversions), leads by
first touch source over 180 days (attribution) and campaign return (won revenue from the accounts a
campaign's leads became, each opportunity counted once, against the budget). Pages `marketing-campaigns`,
`marketing-funnel`, `marketing-attribution` and `marketing-roi` chart them and the
lifecycle queries; campaign and lead lists open their records. The **Marketing** menu lands Marketing
Managers on the campaigns page.

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
Its `0011` adds the first and latest campaign touch (source, medium, campaign, landing page,
referrer and when) to leads and contacts, written when a web visitor is identified (E14-T7).
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

## grc

Policy reviews, attestations and exceptions (R9): a review date and cadence on the platform's
`grc_policy`, attestation campaigns asking a role's holders to acknowledge a policy's current
version by a date, and exceptions that are approved and expire. Needs the GRC module.

## bcm

Business continuity (R15): business impact analysis per process (RTO, RPO, maximum tolerable
downtime), continuity plans and exercises with achieved recovery times.

## recruiting

Recruiting (W7): requisitions, job postings, candidates (personal data), applications through
stages, interviews with scorecards, and offers (salary masked).

## field-service

Inventory (I6): stock balances per product and location as a roll-up of append-only movements,
reservations, serial numbers and lots; returns (I11) with lines, reasons, the return-window check,
inspection and disposition. Its `0010` adds device rules (I7) and a `device_id` on the
asset-management pack's asset and meter reading, so it needs that pack installed first.

The **technician app** (I4-T1) is the model object `model/navigation/field-service/technician.json`:
Today (my work orders scheduled for today, those completed today) and Job (open tasks, parts lines),
over the views `0011` adds; a work order's signature (`customer_signature`, `signed_by`) and its
completion are on the work order itself. `model/entity_settings/field-service/` marks the work order,
its tasks, lines and time entries offline (B18). What a device takes offline is the technician role's
offline profile (the offline pack's `offline_profile`, with these entities): roles differ per
deployment, so the administrator creates it.

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

`0034` makes a product a variant of another (`variant_of_ref`, `variant_label`) for the store (F8-T10).
`0035` adds the report queries behind the **sales dashboards** (D28-T1), which the pack ships as
pages under `model/page/sales/`: `sales-pipeline` (open and won deals, value by stage, weighted
pipeline by close month), `sales-forecast` (this period by category), `sales-activities` (the last 30
days), `sales-win-loss` (win rate by quarter and competitor, losses on price) and `sales-team` (the
deals the viewer's role reaches, at risk and open). Every list opens the record a row is (drill-down).
The pack's **Sales** menu (`model/navigation/sales/sales.json`) lists them and lands Sales
Representatives and Territory Sales Reps on the pipeline and Sales Managers on the team page; a pack
file names a role as `@role:<role name>`.

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
`0003` adds revenue recognition (F11): `revenue_rule` (point in time, ratable, milestone, usage,
percent complete) and a revenue rule on the sales pack's `product`; `revenue_contract` (keyed by its
source order, subscription or invoice) with its `performance_obligation`s, standalone selling prices
and allocations; the `ssp_entry` price list; the `revenue_schedule_line`s per fiscal period;
`contract_change` with its treatment; `revrec_close_run` and `revenue_balance_snapshot`. It builds on
crm (`account`) and sales (`product`); install it after them. `0004` records on each obligation
how its standalone selling price was found (`ssp_method`) and the `ssp_entry` version it used (F11-T4).
`0005` adds the Revenue Accountant (contracts, obligations, schedules and changes, not prices), Revenue
Controller (all of revenue recognition) and Revenue Auditor (read only, the ledger included) roles
(F11-T11). Revenue recognition stays off until the `revrec.*` flags are switched on.

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
The vendor-supplier `0004` (R14-T1) adds third-party risk: a `risk_tier`, `risk_rating` and next
assessment date on each vendor, `vendor_questionnaire` (a survey's response entity, the tier it is for
and its scoring rules) and `vendor_assessment`. Publish the questionnaire's survey with
`send_on` `{entity: vendor_assessment, field: status, value: sent, recipient: contact_ref}` so the
vendor's contact gets the signed link; the daily GRC sweep opens due assessments, scores the answers
and sets the next date by tier (`attome_grc::tprm`).
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

## crm: portal contacts

`0010` links a portal user to the contact it is (`webportal_user.contact_ref`), set when a portal
sign-up's email is verified: the one live contact with that address, or else a new contact with
`portal_review = pending` for staff to confirm or merge.

## crm: global account team

`0012` adds the **Global Account Manager** role (D2-T2). It reads and updates the accounts, contacts
and opportunities its holder owns and those owned by everyone under them in the position hierarchy
(the owner subtree, A17-T3), and reads their activities. To give a group's global account manager
its subsidiaries, put the subsidiaries' account managers in positions under the global manager's;
nothing else widens, and being on an account's team still grants nothing by itself.

## crm: industry codes

`0013` ships the whole ISIC Rev.4 list as `isic_code` records (D24-T3): 21 sections, 88 divisions,
238 groups and 419 classes, each with its parent. The English labels come from the UN Statistics
Division structure file and the Arabic from the UN Arabic edition (ST/ESA/STAT/SER.M/4/Rev.4). It
also upserts the sections from `0003` and the divisions from `0011`, so their Arabic matches the UN
text. A group that the UN prints without a label of its own takes its division's label.

## customer-service: dashboards

`0005` adds the **Service Agent** (team access) and **Service Manager** (business unit, position
hierarchy) roles and four report queries (G16-T1): first contact resolution over 90 days (a resolved
ticket with at most one agent reply), backlog by age band, handle time by agent (claimed to resolved,
in hours) and SLA attainment by customer. The pack's pages `service-manager` (open and breached
tickets, first contact resolution, average CSAT, backlog age, SLA attainment by customer, handle time,
tickets past their SLA) and `service-agent` (the team's open tickets, those past their SLA first) open a
ticket from any list, and its **Service** menu lands each role on its page.

## KPI queries as QuerySpecs

The KPI and summary queries several packs ship were plain SQL over one entity (`CRM: Open Pipeline
Value`, `CRM: Lead Funnel`, `Education: Admissions Funnel` and the like). The record filter that
narrows a stored query to its reader works on the query's output, and an aggregate's output has no
`id`, organisation or owner column to narrow, so a reader below full read access was refused. Each
pack's `*-kpi-queryspec` changeset (crm `0014`, contract-management `0009`, customer-service
`0006`, marketing `0021`, partner `0010`, and `0002` or `0003` in education,
enterprise-architecture, financial-services, government, manufacturing, nonprofit, retail and
telecom-energy) re-declares those that QuerySpec can express as spec-only stored queries: same
name, entity, privilege and output columns, run through the QuerySpec engine, which applies the
reader's record scope and field security before it aggregates (V2-D1808). A sum over no rows is now
empty rather than `0`. Queries QuerySpec cannot yet express stay SQL and run for administrators and
full-read readers only: per-aggregate `FILTER` counts (CS SLA Compliance, contract playbook
deviation count, retail visit compliance), averages of a time difference (partner lead accept
hours), "this week" (healthcare appointments) and `expires_on > CURRENT_DATE` (partner
certifications).
