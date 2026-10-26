# Delivery by your own drivers

When a shipment goes with the deployment's own fleet, its driver (`shipment.driver_ref`) records
the delivery. Only that driver can; anyone else gets `403`, even with the privilege
(`delivery_proof.create`).

## Out for delivery

`POST /api/v1/fulfilment/shipments/{id}/out-for-delivery` moves the shipment to `out_for_delivery`.

With the setting `fulfilment.delivery.otp` on, it also texts the customer a six-digit delivery code.
The code goes to the order's `delivery_phone`, or else its account's phone. Only a hash of the code
is kept. Sending the shipment out again replaces the code.

## Proof

`POST /api/v1/fulfilment/shipments/{id}/proof` records what happened:

```json
{ "outcome": "delivered", "otp": "481926", "received_by": "Sara",
  "photo": "<file key>", "signature": "<file key>", "latitude": 24.71, "longitude": 46.67 }
```

- `outcome` is `delivered`, `failed_attempt` or `refused`.
- Photo and signature are files already uploaded through the files API.
- With delivery codes on, a delivery needs the right code. After five wrong codes the code is
  locked until the shipment is sent out again.

The proof is kept as a `delivery_proof` record, and the shipment moves to the outcome. A delivery
sets the delivered date, adds the shipped quantities to the order lines and raises the
`fulfilment.shipment.delivered` event. A shipment already closed refuses further proof (`409`).

## Cash on delivery

When the order's `cod_amount` is above zero, proving the delivery records the cash as one payment
from the order's account, method `cash`, referenced `shipment <id>`. A repeated proof never records
it twice. The driver then also needs `customer_payment.create`.

## Screens

The fulfilment pack adds the views To release, On hold, Backorders, In transit and Own fleet
deliveries, and Operations > Fulfilment, Shipments and Fulfilment exceptions in the sidebar (only
with the fulfilment module). A sales order's form has a Fulfilment tab: each line's ordered,
shipped, delivered and backordered quantities, its promised date in the person's calendar, and its
shipments with a tracking link where the carrier has one. The tab reads
`GET /api/v1/fulfilment/orders?order_id=` (`fulfilment_order.read`).
