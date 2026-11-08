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

## Salla and Zid (F8-T3)

`attome_integration::connector::adapters::salla` and `::zid` implement the shop platform trait.
Every call goes through the SSRF-guarded client with a 15-second timeout. A platform that is
unreachable, rate-limited (429) or failing (5xx) is reported as the `commerce` capability being
down; any other refusal names only its status, never the body.

| | Salla | Zid |
|---|---|---|
| API | `https://api.salla.dev/admin/v2`, the store's OAuth token as a bearer | `https://api.zid.sa/v1`, the partner token as a bearer plus the store's `X-Manager-Token` |
| Orders | `GET /orders` (sorted by `updated_at`), then each order's amounts (`/orders/{id}?format=light`) and lines (`/orders/items`) | `GET /managers/store/orders?payload_type=default` (lines included), by `updated_at`, 100 a page |
| Line prices | net of VAT, with the VAT rate | including VAT, with the VAT rate |
| Line product | the SKU (Salla's order items carry no product id), or `item:<id>` | the product's id |
| Backfill cursor | the page number | the page number; a short page is the last |
| Times | local, with their zone; an order outside the Gulf zones is refused, not misdated | no zone; read as Saudi time (UTC+3) |
| Webhooks | `order.created`, `order.updated`, signed (`salla` inbound preset) | the order; the signature scheme is unconfirmed, so the inbound hook uses its own secret |
| Customers, products | listed | not built (customers arrive with orders) |
| Writing stock or products | not built | not built |

The order shapes come from the platforms' published API references (read 2026-11-06). The test
fixtures in `crates/engine/attome-integration/tests/fixtures/shop/` are built from those
references, not recorded from a live store: no partner access exists yet. Replace each with a
recorded payload once there is one, and confirm the points marked as owed in each adapter's
module notes: Zid's time zone, shipping lines and webhook signature, and the Salla product and
delivery-address shapes.

## Shopify and WooCommerce (F8-T4)

`attome_integration::connector::adapters::shopify` and `::woocommerce` implement the same trait,
through the same guarded client.

| | Shopify | WooCommerce |
|---|---|---|
| API | `https://{shop}.myshopify.com/admin/api/2026-07` (Admin REST), the token in `X-Shopify-Access-Token`; only a `*.myshopify.com` host is accepted | `https://{store}/wp-json/wc/v3`, the consumer key and secret as Basic credentials; any store URL that is not `https` is refused |
| Orders | `GET /orders.json?status=any&order=updated_at asc` | `GET /orders?orderby=modified&order=asc` |
| Line prices | net or including VAT as the order's `taxes_included` says; the rate is the sum of the line's tax rates | net (`subtotal / quantity`), the rate `subtotal_tax / subtotal` |
| Line product | the product id (the SKU or `item:<id>` for a custom line) | the variation id, else the product id |
| Backfill cursor | orders: the last `updated_at` (inclusive); customers and products: the last id (`since_id`) | the page number; a short page is the last |
| Times | ISO 8601 with offset | UTC (`date_created_gmt`) |
| Cash on delivery | a cash-on-delivery gateway and not paid | payment method `cod` |
| Webhooks | `orders/create`, `orders/updated`; `X-Shopify-Hmac-Sha256` (the `shopify` inbound preset) | `order.created`, `order.updated`; `X-WC-Webhook-Signature`, base64 HMAC-SHA256 of the body |
| Customers, products | listed; a product is its first variant | listed |
| Writing stock or products | not built (stock is per inventory item and location) | not built |

Shopify calls the REST Admin API legacy; it is used because the resources read are the same in
GraphQL and the platform trait is REST-shaped. Shapes come from the platforms' references (read
2026-11-08) and the two fixtures are built from them, not recorded: replace them with recorded
payloads once there is a development store. A full page of Shopify orders that share one
`updated_at` ends the run (logged) rather than loop.

## The sync job and the shop webhook (F8-T5)

A connection's sync runs as the registered job `shop_sync`, never on a request. It is queued by:

- **A shop webhook.** Make an inbound hook (Admin, Inbound hooks) whose handler is
  `{"type": "shop_sync", "connection": "<shop connection id>"}`, with the shop's signature as its
  authentication: the `shopify` preset (`X-Shopify-Hmac-Sha256`), the `salla` preset
  (`X-Salla-Signature`), or a custom `hmac` auth for WooCommerce (`X-WC-Webhook-Signature`, base64). The
  hook checks the signature, the address rules and replay of the event id before anything is queued,
  answers 202, and queues one sync per connection (one already waiting is not queued twice). An
  unsigned or wrongly signed call is refused with 401 and queues nothing.
- **The 15-minute tick**, for every connection whose `status` is `active`.

A run syncs orders (`sync_orders`), customers (`sync_customers`) and products (`product_direction` =
`shop_to_attome`), each from its stored cursor (`shop_sync_cursor`, migration 0403), as the user who
created the connection. A page's records are written first (a record already synced is updated, never
made twice, so a replayed webhook creates nothing new); only then does the cursor move. At most 20
pages of a kind per run, so a large backfill continues on the next run. A refused page or record sets
the connection's `status` to `error` (an administrator resumes it by setting it back to `active`); a
platform that is down does not. A good run sets `last_sync_at`.

The connection's credential is an integration credential (`integration_credential_ref`) holding a
JSON object: Salla `{"access_token"}`, Zid `{"partner_token", "manager_token"}`, Shopify
`{"shop_domain", "access_token"}`, WooCommerce `{"store_url", "consumer_key", "consumer_secret"}`.
Creating, pausing and resuming a connection is the generic `shop_connection` entity API (`status` =
`active` or `paused`, with `If-Match`), which audits each change.

