# Telling customers where their order is

Two things, both off by default and both part of the fulfilment pack.

## Order updates by email and text

Turn on the setting `fulfilment.customer_updates` and set an order's **Updates contact**
(`order.updates_contact_ref`). That contact is then told when:

| Step | When | Template |
|---|---|---|
| shipped | a shipment of the order is picked up or in transit | `fulfilment.shipped` |
| out for delivery | a shipment goes out for delivery | `fulfilment.out_for_delivery` |
| delivered | a shipment is delivered | `fulfilment.delivered` |
| delayed | the order passes its promised date unshipped (a `late` exception) | `fulfilment.delayed` |

A message goes only when the contact has granted the **order_updates** consent purpose; without it
nothing is sent. The pack ships each template in English (`en`) and Arabic (`ar-SA`); a contact whose
preferred language is Arabic gets the Arabic one. Templates are ordinary notification templates, so you
can change their wording or channels: `default_channels` is `email,sms` (email to the contact's address
unless it is suppressed, a text to their mobile through the SMS provider). They may use
`{{order_number}}`, `{{carrier}}` and `{{tracking_number}}`. WhatsApp is not used yet: its templates
need the provider's approval first.

The updates are read from shipment and exception changes every minute. Each step of each shipment (and
the delay of each order) is decided once: replaying events never sends twice, and a step that was not
sent for lack of consent is not sent later. Turning the setting on does not send updates for changes made
while it was off.

## Where is my order, on the portal

With the setting `fulfilment.portal` on, a signed-in portal user may read one of their own account's
orders: `GET /{keyword}/api/v1/fulfilment/orders/{order_id}` answers each line with its ordered,
shipped and delivered quantities, promised date, status, and the shipments carrying it with carrier and
tracking number. The account is the portal user's contact's account, never one the request names; any
other order, and the route while the setting is off, answer 404.
