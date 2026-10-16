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
limit, payment terms and credit hold on `account` (F5). It builds on crm (`account`) and sales
(`product`, `order`, `quote`) and on an `invoice` and a `contract` entity; install it after them.

## commission

Sales commissions (F10): `comp_plan` with versions and components (rate tables, tiers, caps, gates),
`plan_participant`, `comp_period`, `comp_credit` from deals, orders, invoices and payments,
calculation runs (`comp_run`) with `comp_statement_line`s and `comp_payout`s, adjustments, disputes and
draws. Every amount, rate and balance is a masked field; the `commission` engine computes them.

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
