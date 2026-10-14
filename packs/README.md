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
