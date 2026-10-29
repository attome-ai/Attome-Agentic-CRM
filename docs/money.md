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
