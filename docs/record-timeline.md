# Record timeline

Every record has a timeline: what happened to it and around it, newest first. It is in the record's
Activity panel, and `GET /api/v1/{entity}/{id}/timeline` serves it.

## What it shows

| Kind | Comes from |
|---|---|
| `audit_event` | The record's changes. |
| `state_transition` | Changes of the record's state field, when the entity has a state model. |
| `communication`, `note`, `activity` | Emails, calls, notes and tasks attached to the record. A captured email linked to several records shows on each of them. |
| `decision` | Decisions linked to the record. |
| `approval` | Approval requests about the record: the action, its status and step, never the payload. |
| `flow_run` | Flow runs started for the record: the flow and how the run stands. |
| `agent_run` | One entry per agent session that changed the record: the actions it ran and how many changes it made. |

Every entry also says:

- who made it (`actor`), and whether that was a person, an agent, a flow or the system
  (`actor_kind`);
- the agent session or flow run it came from (`run_id`);
- which record it belongs to (`source_record`).

## Who sees what

You see a record's timeline only if you may read the record. Then each part follows its own rules:

- Changes, approvals and runs are shown to anyone who may read the record.
- A sensitive field is never named unless you hold its read grant, and its values are never shown.
- A note, email, task or decision shows only if you may read it in its own right.

## Related records

A deployment can show related records' entries on a record's timeline. For example, an account
can show its contacts' emails and notes. The setting `records.timeline_roll_in` lists, per
entity, the child entities and the lookup that ties them to it:

```json
{ "account": [ { "entity": "contact", "via": "account_id" } ] }
```

Only children you may read are included, with each child's own rules, and at most the newest 200
per relationship. An entry reached through two records shows once. Add `related=false` to the
request to see the record's own entries only. The ticket timeline always shows the ticket alone.

## Filters

| Parameter | Effect |
|---|---|
| `kinds` | A comma-separated list of kinds. |
| `actor` | Entries made by this user, or by an agent or flow acting for them. |
| `channel` | Communications on this channel only (other kinds are left out). |
| `from`, `to` | Entries at or after `from` and before `to`. |
| `q` | Words to find in the entries' text, up to 200 characters. |
| `pinned_only` | Only the pinned entries. |

The filters run inside every source, so paging with `next_cursor` stays exact.

## Pinned entries

If you may update the record, you can pin an entry with
`PUT /api/v1/{entity}/{id}/timeline/pins/{kind}/{source_id}` and unpin it with `DELETE` on the
same path. Pinned entries show at the top for everyone who opens the record, up to 50 per record.

A pin only names the entry. Each reader still sees it only if they may see it.

## In the panel

The panel shows:

- the pinned entries on top;
- a "no contact for N days" marker wherever calls and emails stop for 14 days or more;
- buttons to add a note, log a call or add a task;
- Reply on an email;
- an "N new" button when the record or its notes, tasks or emails change while it is open.

With AI on, a short summary of the timeline sits at the top. It is made from the entries you may
see, and it cites them; click a citation to jump to its entry.

## Export

`GET /api/v1/{entity}/{id}/timeline/export` returns up to 2,000 entries as CSV, filtered by kind.
The export applies the same permissions as the timeline.
