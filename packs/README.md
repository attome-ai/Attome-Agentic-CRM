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
