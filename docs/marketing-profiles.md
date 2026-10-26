# Marketing profiles: events, identity, attribution and campaign members

This page covers what marketing knows about a person and what that knowledge earns: the events a
contact or visitor produces, which contact an email or visitor belongs to, how much credit each
touch gets when a deal is won, and how a list becomes a campaign's members.

## Profile events

`POST /api/v1/marketing/profile-events` takes up to 500 events in one batch:

```json
{ "events": [
  { "contact_id": "…", "kind": "page_view", "properties": { "path": "/pricing" } },
  { "anonymous_id": "visitor-7", "kind": "visit" },
  { "contact_id": "…", "kind": "purchase", "at": "2026-10-26T09:30:00Z",
    "properties": { "amount": 120.5, "campaign_id": "…" } }
] }
```

- The caller needs `contact.update`, and may send 60 batches a minute.
- Each event names a contact the caller may read, or an anonymous id.
- An event's time defaults to now and must fall within the last 7 days.
- Its properties are a JSON object of at most 8 KB.

Events that fail a check come back in `rejected` with their index and reason; the rest are kept.
Events are kept for `marketing.profile_event_retention_months` (13 by default).

### Traits

`GET /api/v1/marketing/contacts/{id}/traits` rolls a contact's events up when read:

| Trait | From |
|---|---|
| `last_seen_at` | The latest event of any kind. |
| `visits` | Events of kind `visit`, `page_view` or `session_start`. |
| `purchases`, `total_purchases` | Events of kind `purchase`, and the sum of their numeric `amount`. |
| `events` | Every event kept. |

Traits are computed when read, never stored, so they are never stale.

## Identity links

An identifier (an email address, a tracking visitor id, a portal user or a phone number) belongs to
at most one contact. Only deterministic events link one:

- a portal sign-in;
- a form submitted with an email (the form's email and its visitor id);
- a tracked email click.

Emails are compared lower-cased and trimmed, and phone numbers by their digits.

Linking an identifier again to the same contact changes nothing. When a second contact claims it,
nothing moves: the claim is kept as a conflict for a person to settle.

- `GET /api/v1/marketing/identity/conflicts` lists open conflicts, newest first.
- `POST /api/v1/marketing/identity/conflicts/{id}/resolve` with `{"keep": "existing"}` keeps the link
  where it is; `{"keep": "new"}` moves it to the claiming contact.

Both need `contact.update`.

## Attribution

Every night, each won opportunity (`closed_won` with a close date) gets credit for the marketing
touches of its account's contacts in the year before the close: their profile events and form
submissions. A profile event's `campaign_id` property ties its touch to a campaign. Its `channel`
property (or else its kind) names the channel.

Five models are stored:

| Model | Credit |
|---|---|
| `first_touch` | All to the first touch. |
| `last_touch` | All to the last touch before the close. |
| `linear` | Equal shares. |
| `u_shaped` | 40% first, 40% last, 20% shared by the middle. |
| `time_decay` | Halving for every 7 days before the close. |

Each touch's share and its part of the won amount are stored. An opportunity is computed again only
when it changes. `GET /api/v1/marketing/opportunities/{id}/attribution?model=linear` reads one
model, by touch and by campaign, for a caller who may read the opportunity.

## Campaign members from a list

`POST /api/v1/marketing/campaigns/{id}/members/from-list` with `{"list_id": "…", "purpose": "…"}`
adds a marketing list's people to a campaign in the background. It needs `campaign_member.create`.

- The list's people are worked out as the person who asked, so their record access applies.
- People already members are skipped, and a retry adds only who is missing.
- For an email, social, advertising or content campaign, people without a current consent for the
  purpose are skipped; the purpose is then required.
- Members are created as `targeted` through the record API, so rules and audit apply. One request
  adds at most 50,000.

`GET /api/v1/marketing/campaigns/{id}/members/summary` counts the campaign's members by status.
