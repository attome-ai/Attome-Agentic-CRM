# Marketing lists and segments

A marketing list is the set of people a send, a journey or a nurture programme reaches. Lists are
records of the `marketing_list` entity (marketing pack), created and edited on their generic form or
through the entity API; the routes below add what a form cannot do. Route shapes are in
`openapi.json`.

## Static lists and segments

A list has a `kind`:

- **static**: its members are exactly the people added to it. People are added and removed by hand,
  from a view selection, from a form or a flow (`POST /api/v1/marketing/lists/{id}/members`,
  `POST .../members/remove`, at most 1,000 ids at a time), or by importing a CSV document
  (`POST .../imports`): the first column of each row is an email or a record id, matched to people
  you may read. An import can be undone within a few days (`POST .../imports/{import_id}/undo`),
  which removes exactly the members it added.
- **segment**: its members are the records a stored query returns. `query_id` names the stored
  query, by its id or as `<entity>/<name>`. A segment's members cannot be changed by hand.

`target_entity` is `contact`, `lead` or `account`. An account list can expand to its accounts'
contacts (`account_expand`: all contacts, or the decision makers and economic buyers named on their
opportunities).

## Combinations

A list can combine other lists (`marketing_list_combination` records on the list's form). In
`position` order, each combination applies its `operand_list_ref`:

| `operation` | Effect |
|---|---|
| `include` | adds the operand list's people |
| `intersect` | keeps only the people also in the operand list |
| `exclude` | removes the operand list's people |

Operand lists are worked out the same way, up to a few levels deep; a list that reaches itself is
refused as a cycle. Example: "engaged contacts in Riyadh, minus customers" is a segment over a
"contacts in Riyadh" stored query, `intersect` the starter list "Engaged in the last 90 days", then
`exclude` "Customers with a won opportunity".

## Refresh

`refresh_mode` says when a segment's members are worked out again:

- **manual**: when someone asks (`POST .../refresh`, answered 202; `last_refreshed_at` moves when it
  has run).
- **scheduled**: every hour or every day (`refresh_interval`).
- **live**: as records change. Only the people a change touched are checked again, never the whole
  segment, so a live segment's stored query may read only its target entity, the consent state, and
  entities one lookup away from the target ("contacts of accounts in retail"). Saving a live list
  whose query reads more is refused; if its query is later republished to read more, the list falls
  back to its schedule until fixed.

Every change of membership writes an entered or left event with its reason (`scheduled`, `live`,
`manual`, an import, a form, a flow). A scheduled or live list nobody has used for 90 days is paused
nightly, and resumes the next time it is read. Changing what a list holds while a live journey takes
entries from it is refused (409 `list.in_use`) unless confirmed with the header
`Attome-Confirm: list.in_use`.

## Counts, explanations and history

Everything here is worked out as you, and never names a person you cannot read. The **Segment** tab
of a list's form shows the same.

- `GET .../count`: the size, estimated by default or exact with `exact=true`; with `purpose_key`,
  also how many can be emailed for that consent purpose (granted consent, an email that is not
  suppressed, not sunset).
- `GET .../sample`: up to 20 people.
- `GET .../explain/{person_id}`: why one person is in or out, step by step (the list itself, then
  each combination).
- `GET .../members` and `GET .../members-as-of`: current members, and who was in it on a past date.
- `GET .../usage`: the email and SMS sends, nurture programmes and journeys that use the list.

The agent tools `segment.explain_change` (why the size changed between two dates),
`segment.lookalike` (choice values clearly more common among the members) and, for administrators,
`segment.draft` (a segment's query drafted from a description and checked as a publish would) save
nothing; see [agents](agents.md).

## Whose access a segment runs with

A segment runs as a reader. A person looking into a list sees only the people they may read; a
background refresh runs as the list's owner, so a list never holds people its owner could not see.

Some lists must cover more than their owner may read (a deployment-wide newsletter list built by a
marketer with a narrow role). Such a list can be granted **wide access** (`wide_access_granted`):
its refreshes then run as the deployment's marketing user, the user the setting
`marketing.segment_user` names. Granting or removing it needs the privilege
`marketing_list.grant_wide_access` (or system administrator) and writes an Access security event in
the same save. With no marketing user set, a wide list is refused (`segment.no_marketing_role`)
rather than run as anyone else. Readers of a wide list still see only the people they may read.

## Starter segments

The marketing pack ships four stored queries over contacts to build segments from: engaged in the
last 90 days, new this month, unengaged for six months, and customers (lifecycle stage `customer`).
Create a segment list naming one as its query (`contact/<query name>`); it refreshes once it has an
owner. The lists are not shipped ready-made, so a pack install never forces list names to be unique.
