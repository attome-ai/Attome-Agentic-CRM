# Shop sync

An online shop (Salla, Zid, Shopify, WooCommerce) is a shop connection
(`shop_connection`, sales pack changeset `0030`) whose orders, customers and
products are written into Attome as D10 orders, D1 contacts and D8 products
(F8-T2). The platform adapters (F8-T3, F8-T4) fetch from the shop and map its
JSON into one neutral shape; everything after that is shared.

## What a sync writes

`attome_sales::shop_sync::upsert_from_source` takes one shop record and writes
it through the record engine as the connection's service user, so field rules,
validation, audit and the change feed apply as for any other write.

| Shop record | Becomes | Matched first by |
|---|---|---|
| Customer | `contact` (name, email, mobile phone) | a live contact with the same E.164 mobile or phone, or the same email (lower case) |
| Product | `product` (name, SKU, description; orderable) | a live product with the same SKU; a product without one gets `<platform>-<shop id>` |
| Order | `order` and its `order_line`s | — |

An order's `source` is `shop:<platform>` and `source_order_number` the number
the shop shows (sales pack changeset `0031`). Its currency is the shop's own.
Line prices that include VAT are split into net and VAT at the line's rate; the
order's grand total is what the shop says the customer pays. The order goes
under the customer's account, else the connection's **default account**
(`default_account_ref`); with neither, the order is refused, so set a default
account for a shop that sells to people.

## Once per source record

`shop_sync_map` holds one row per connection, kind and shop id (its business
key, so its unique index decides who writes first). A replayed webhook or a
backfill that sees an order again updates the order it already made (status
and totals) instead of making a second one. An order's lines are written once.

The record engine writes one record per transaction: when a line cannot be
written, the half-written order is deleted again and the next sync retries it.

## Matching duplicates

The sync matches exact phone and email only. The duplicate rules (A15) still
scan contacts and find what an exact match misses.
