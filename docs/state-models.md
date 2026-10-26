# State models: actions and automatic transitions

A state model governs one choice field of an entity (its state field): the states a record moves
through and the transitions allowed between them. Models and transitions are administered at
`/api/v1/admin/state-models` and travel in bundles and changesets. A record moves with
`POST /api/v1/{entity}/{id}/transition`, or with an ordinary update of the state field; both go
through the same checks (the transition's `required_privilege`, its `guard_expression`, its approval
plan, the entity's rules).

## Transition actions

A transition's `exit_actions` and `entry_actions` name actions (built-in ids or published
`custom.<name>` actions). After a transition commits, they run in order (exit actions first) as the
person who made the change, through the action gate, with the arguments
`{entity, record_id, from_state, to_state}`. A failure retries and then lands in the dead letters.

## Automatic transitions

A transition with an `auto_condition` happens by itself: when a record sits in the transition's
`from_state` and the condition holds, the record moves to `to_state`.

```http
POST /api/v1/admin/state-models/{model}/transitions
{ "from_state": "sent", "to_state": "overdue", "name": "Overdue",
  "auto_condition": "due_date < today()" }
```

The condition is an attome-rules expression over the record's fields that gives yes or no; one that
does not compile is refused when the transition is saved. Two passes look for records to move:

- every minute, the records created, changed or restored since the last pass (from the change feed,
  consumer `attome-state/auto-transitions`), so a condition on the record's own fields fires soon
  after the write;
- daily, every record in the `from_state` of an automatic transition (up to 50,000 per transition per
  run, the rest the next day), for conditions that become true with time alone, such as an invoice
  whose due date passed.

When several automatic transitions leave the same state, the first in display order whose condition
holds wins. The move is an ordinary update made by the policy actor with an administrator's
privileges: the guard, approval plan, rules, change feed and audit apply, and the record's history
says which automatic transition moved it. A move a guard or rule refuses is logged and tried again
on the next pass. After an automatic move, the minute pass does not check that record again, so two
automatic transitions whose conditions both hold move a record at most once a day.
