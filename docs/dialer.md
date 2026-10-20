# Call lists and the power dialer

A call list is a queue of people to phone. A rep opens the dialer on a list, takes the next person
who may be called, calls them through the deployment's telephone system, records what happened, and
moves on. Everything comes from the sales pack (`packs/sales/changesets/0006` onwards) and needs the
sales module; nothing dials unless a person presses call.

## What is off until set up

- **No one may call.** The pack's roles hold the dialer privileges: *Sales Representative* may read
  and create call lists, call from them and save attempts (`call_list.read`, `call_list.create`,
  `call_list.call`, `call_attempt.create`); *Sales Manager* may also share lists and keep calling
  hours and caller ids (`call_list.share`, `calling_hours.*`, `caller_id_rule.*`). Give people a
  role, or the privileges through a role of your own.
- **No country may be called.** A number is callable only inside a `calling_hours` row for its
  country (or a `*` row for every country without its own). None ship: there are no Saudi, UAE or
  Egyptian defaults, because the permitted hours are a legal question for each deployment. Add the
  rows your counsel approves before anyone dials.
- **No voicemail drop.** A list drops a recorded message only when its `voicemail_enabled` is set.
- **No outcome changes records.** An outcome changes a lead or deal only through an outcome rule.

## Setting a list up

`call_list` holds the list:

| Field | Meaning |
|---|---|
| `source_kind` | `view` (a saved query, `view_ref`), `tasks_due` (the caller's open phone-call tasks due today) or `manual` (records named one by one). |
| `max_attempts_per_record`, `max_attempts_per_day` | Stop calling a person after this many attempts in all, or today. |
| `retry_wait_minutes` | How long an unanswered person waits before coming round again (60 by default). |
| `countdown_seconds` | The pause the dialer shows before ringing the next person. |
| `voicemail_enabled` | Whether a recorded message may be dropped into a call. |
| `script_ref` | The call script shown beside the person. |
| `is_shared` | Other reps may call from it; sharing needs `call_list.share`. |

Building a list (`POST /api/v1/sales/call-lists/{id}/build`) adds the records the caller may read
that have a phone number, in source order; building again adds only records not already on it.

**Outcome rules** (`call_outcome_rule`) say what an outcome does on a list: set the lead's status
(`set_lead_status`) or the deal's stage (`set_opportunity_stage`), add a call-back task after some
minutes, and for a wrong number flag the record's phone for checking where the entity has that
field. Rules run after the attempt is saved, as the person who called, through the ordinary record
update (validation, audit and row versions apply).

**Caller ids** (`caller_id_rule`) choose the number the customer sees, per country of the customer's
number: the list's rule for that country, else its catch-all rule, else the telephone system's own
number. Only numbers the telephone system owns are used.

## Taking a call

1. **Claim** (`POST /api/v1/sales/call-lists/{id}/claim`) gives the caller the next waiting person.
   Someone marked do-not-call, without an active `sales_calls` consent (when the deployment defines
   that purpose), or past the attempt limit is skipped, with the reason; someone outside calling
   hours or past today's limit is snoozed until later. Each skip writes an audit event.
2. **Dial** (`POST /api/v1/sales/call-lists/{id}/dial`) rings the rep's own phone, then the person,
   through the deployment's voice system (J6), and logs the call on the record.
3. **Voicemail** (`POST /api/v1/sales/call-lists/{id}/voicemail`) drops a recorded message into the
   rep's own call, when the list allows it.
4. **Outcome** (`POST /api/v1/sales/call-list-members/{id}/outcome`) saves the attempt: connected,
   wrong number and not interested finish the person; the others bring them back after the retry
   wait.
5. **Skip** (`POST /api/v1/sales/call-list-members/{id}/skip`) passes over a claimed person with a
   reason.

The dialer screen for a list is `/xrm/sales/dialer/{list id}`, in English and Arabic.

## Metrics

The team calling metrics (`packs/sales/changesets/0013`, re-stated by `0022`) are stored queries:
calls per person per day, connect rate per person per week, talk time per person per day, outcomes
per list, and meetings booked per person per week, over the last 90 days. A call counts for the
person who made it (`call_attempt.owner_ref`).

## For agents

Three tools, none of which dials: `sales.call_list.build` drafts a list from a description for a
person to fill and activate, `sales.call_list.order` reorders a list's waiting people by points
score or deal risk, and `sales.call.draft_notes` drafts notes for an attempt from its recording's
transcript. The first two are confirmed by a person first; see `docs/agents.md`.
