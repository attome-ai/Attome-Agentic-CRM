# Opportunity lines

For builders and administrators of the sales module: the products on a deal, how they are priced,
how the deal's totals follow them, and what can be switched on. Everything here is in the
`attome-sales` engine; the API reference has every route's request and answer.

## Switching it on

Every part is behind a feature flag of the sales module, all **off** by default
(`/api/v1/admin/features`). While a flag is off, its routes answer `404 feature_hidden`, as if
absent.

| Flag | What it switches on |
|---|---|
| `sales.opportunity_lines` | Lines on a deal, the deal discount and the product picker |
| `sales.recurring_lines` | Recurring lines (a yearly value as well as a one-time one) |
| `sales.schedules` | Revenue and quantity schedules on a line |
| `sales.quote_sync` | Copying the primary quote's lines onto the deal |
| `sales.product_suggestions` | Drafted product suggestions for a deal |

## Lines

`GET` and `POST /api/v1/sales/opportunities/{id}/lines`, `PATCH` and `DELETE
.../lines/{line_id}`, and `POST .../deal-discount` change a deal's lines. Each call sends the
deal's row version in `If-Match`, and runs in one transaction under the deal's lock: every line is
repriced together, each line's total is stored, the deal's totals are written, and the deal's stored
split amounts are recalculated.

- A line's product must be on the deal's price list, in the deal's currency; otherwise the call is
  refused with `422 product_not_on_price_list`. The list price always comes from the price list,
  never from the caller.
- `GET /api/v1/sales/price-lists/{id}/products?q=&sku=&on=` is the product picker: the products a
  line may use on a date, with their list price and quantity breaks, searched by name or SKU and
  filtered by the caller's product record rules.
- `opportunity_line` is written only through these routes. Its `line_total` and `list_price`, and the
  deal's `has_lines`, `one_time_total`, `recurring_annual` and `total_contract_value`, are managed by
  the engine: an ordinary record update cannot set them.

### The deal's amount

While a deal has lines, every line change sets its `amount` to the one-time total plus one year of
recurring value. A hand edit of the amount is kept only until the next line change, and removing the
last line leaves the amount as it was.

## Pricing order

Pricing is fixed, in this order, at full precision:

1. **List price**, from the deal's price list (with quantity breaks).
2. **Sales price**: an override of the list price for the line, when one is given.
3. **Line discount**: a percentage first, then an amount.
4. **Deal discount**: a percentage, applied to each line after the line's own discount.

Each line's total is then rounded **once**, to the currency's minor units, half away from zero.
Totals are the sums of the rounded line totals.

## Schedules

`POST /api/v1/sales/opportunity-lines/{line_id}/schedule` replaces a line's schedule: spread evenly
over a number of months, by a percentage pattern (which must add up to 100), or row by row (which
must add up to the line). Each row is rounded once, and the remainder goes to the last row, so a
schedule always adds up to its line exactly.

`POST /api/v1/sales/opportunities/{id}/schedules/shift` moves every row of a deal by whole months.
It is called only after the user agrees to move the schedule with a new close date, never on its
own. A deal with more than 500 rows is shifted by a background job. Periods are Gregorian dates;
Hijri is a display choice.

## Quote sync

`POST /api/v1/sales/opportunities/{id}/sync` copies one way per call:

- `from_quote` replaces the deal's lines with copies of the primary quote's lines and reprices the
  deal. The quote's unit price becomes the list price and its discount the line discount.
- `to_quote` is refused: quotes are priced by CPQ and changed through it.

The deal remembers a hash of its lines at the last sync. When both the deal and the quote changed
since then, a sync without `force` answers `409 sync_both_changed` with both sets of lines, so the
user chooses which side wins.

## Undo

A deal discount or a quote sync answers with a snapshot id. The person who made the change can undo
it with `POST /api/v1/sales/undo/{snapshot_id}`:

- within **30 minutes**, once;
- only while nothing has touched the lines since (each line still has the version the change left).

Undo puts the earlier lines back and reprices the deal. Snapshots older than a day are removed
nightly.
