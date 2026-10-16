# Procurement

The procurement pack (`packs/procurement`) and the `attome-procurement` engine, gated on the
`procurement` module, cover buying from a vendor: a requisition is approved, becomes a purchase
order, goods are received against it and the vendor's bill is matched and posted. The pack needs the
vendor-supplier pack for `vendor`.

## Records

| Entity | What it holds |
|---|---|
| `purchase_requisition` and its lines | What someone needs, by when, the suggested vendor and an estimated total. Draft, submitted, approved or rejected, then ordered. |
| `purchase_order` and its lines | The order to a vendor with currency, payment terms and totals. Each line tracks the quantity received and billed. Draft, issued, partly received, received, closed. |
| `goods_receipt` and its lines | What arrived against which order lines, and how much was rejected. |
| `vendor_bill` | The vendor's invoice for an order, with its match status (matched, price or quantity variance). Draft, posted, paid. |

Every document has a number within its series. The Requester, Buyer, Receiver and AP Clerk roles
ship with the pack, with the open-orders and bills-due reports.

## Budget check

`attome_procurement::budget::check` answers whether a spend may go ahead. What is available on a
budget line is its amount less what is committed (approved requisitions and open orders) and what
is already spent. A spend that would go over it either warns, and is allowed, or is blocked, as the
deployment's overspend policy says.

## Vendor scorecards

`attome_procurement::scorecard::monthly` scores each vendor per month from:

- on-time delivery: receipts that arrived on or before the expected date;
- quality: accepted quantity out of received quantity;
- supplier SLAs: clocks met out of clocks closed.

Each part is a percentage, and the score is their weighted mean (40, 40 and 20 by default) over the
parts that had anything to measure that month.
