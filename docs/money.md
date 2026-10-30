# Money amounts and currencies

A money field (field type `currency`) stores an amount together with the currency it is in
(A19-T1).

## Storage

- The amount is in the field's own column. A column created since A19-T1 is `NUMERIC(20,6)`;
  older columns stay `NUMERIC`.
- The currency is in a second field beside it, `<field>_currency`: an ordinary text field
  holding an ISO 4217 code (three capitals, such as `SAR`). Provisioning adds it whenever a money
  field is created or reconciled. Being an ordinary field, it is read, written, filtered, shown
  on forms and audited like any other.
- Money fields made before A19-T1 get their currency field at the next boot, and their stored
  amounts get the deployment's base currency. A money field made by changing a number field's
  type gets its currency field at the next boot too.
- When the name `<field>_currency` is already taken by a field of another type, no currency field
  is added (a warning is logged) and that field's amounts are not rounded.

## Writing

On a create or update that sets an amount:

1. The currency is the one the request sends in `<field>_currency`; on an update that sends none,
   the record's stored currency; otherwise the base currency. It is written with the amount.
2. The amount is rounded half away from zero to the currency's decimals: KWD, BHD, OMR, JOD,
   IQD, LYD and TND to 3, JPY, KRW, VND, CLP, ISK and UGX to 0, the others to 2.
3. A currency the `currency` table does not hold is refused with a 422 naming `<field>_currency`.

Changing only the currency of a stored amount does not round the amount again.

## The currency table

`currency` (migration 0335) holds each currency's code, decimals, symbol and English name. It is
infrastructure data shipped with the platform; it is read-only to the application.

## The base currency

The deployment setting `core.base_currency` (default `USD`) is the currency of an amount written
without one, and the currency given to amounts stored before A19-T1. Set it before the first boot
that runs A19-T1 for the backfill to use it.

Amounts are not converted between currencies: a sum over records in several currencies adds
the numbers as stored.

## Exchange rates

`exchange_rate` (migration 0337) holds dated rates: one unit of `from_currency` in `to_currency` on
`rate_date`, kept to 10 decimal places, from a named `source` (`manual` for a rate entered by hand,
or the feed that imported it, such as `sama` or `cbuae`). There is at most one rate per pair, day
and source; storing another replaces it.

The rate for a day is the newest stored rate on or before it, so a weekend or holiday uses the last
published rate. When rates from several sources exist for that day, the source named by the
deployment setting `core.fx_source` wins; a newer rate from another source still wins over an older
one from the preferred source. When only the opposite direction is stored (SAR to USD when USD to
SAR is asked for), its inverse is used. A currency converts to itself at 1.

| Route | Who | What |
|---|---|---|
| `GET /api/v1/exchange-rates/rate?from=USD&to=SAR&on=2026-10-30` | anyone signed in | The rate that applies on the day (today when `on` is left out), its day and source, and whether it was inverted; 404 when none applies |
| `GET /api/v1/exchange-rates?from=&to=` | anyone signed in | Stored rates, newest day first, one page at a time |
| `POST /api/v1/exchange-rates` | the Deployment administration area | One rate entered by hand |
| `POST /api/v1/exchange-rates/import` | the Deployment administration area | Up to 1,000 rates from one source in one transaction; nothing is stored if one is not valid |
| `DELETE /api/v1/exchange-rates/{id}` | the Deployment administration area | Removes one rate |

Both currencies must be in the currency table. Every write is audited as a configuration change.
To take a central bank's daily rates, point a connector or a scheduled flow at its published rates
and post them to the import route with the bank's source name.

## Converting to the base currency

A money attribute can store each amount in the base currency as well. Turn it on with the
attribute option `fx`:

```json
{"fx": {
  "rate_date": "attribute:closed_on",
  "lock_at_stage": {"attribute": "stage", "values": ["won"]},
  "missing_rate": "block"
}}
```

| Key | Values | Default |
|---|---|---|
| `rate_date` | `record_date` (the day the record was created), `today` (the day of the write), or `attribute:<name>` (a date or date-time attribute of the record; today while it is empty) | `record_date` |
| `lock_at_stage` | an attribute and the values at which the rate stops changing | none |
| `missing_rate` | `warn` (store the amount without a base amount, and log it) or `block` (refuse the write, error code `missing_rate`) | `warn` |

Saving the attribute with `fx` adds two number attributes beside it: `<name>_base`, the amount in
the base currency rounded to that currency's decimals, and `<name>_rate`, the rate used. Every
write that sets the amount, its currency or the rate's date attribute fills both, with the rate for
that day as described above. Once the stored value of the `lock_at_stage` attribute is one of its
values, later writes keep the stored rate, and a changed amount is converted with it. A malformed
`fx` option is refused when the attribute is saved. Amounts stored before conversion was turned on
are converted on their next write.

## Revaluation

`GET /api/v1/reports/fx-revaluation?entity=invoice&attribute=total&as_of=2026-10-31&open_field=status&open_values=issued,overdue`
revalues the open amounts of one money field that converts to the base currency (its `fx` option)
(A19-T6). Per currency other than the base it gives the records, their amount, the base amount
booked for them, the rate on `as_of` (today when absent), the amount at that rate and the
difference, a gain when positive; `total_gain_loss` adds the lines that have a rate, and
`missing_rates` names the currencies with none on or before the day. Without `open_field` every
live record counts. The totals cover every record, so the report needs read access to every record
of the entity.

## In the app

The money control (A19-T5) shows and edits an amount in its own currency, with that currency's
symbol and decimals, and a currency picker bound to `<field>_currency`; a field with the `fx` option
shows its base amount as a hint. Lists show each amount with its own currency. The currencies come
from `GET /api/v1/currencies` (code, decimals, symbol, name, and which is the base). Nothing is
converted in the browser; the old static rate table is gone.
