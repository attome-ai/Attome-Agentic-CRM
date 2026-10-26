# Sales sequences

A sequence is a series of outreach steps (emails, tasks, waits) that a contact moves through one at a
time, and leaves as soon as they answer. It is an ordinary workflow of kind `sequence`: its steps are
ordinary workflow nodes, and it is built, versioned and published like any other flow.

## Making a sequence

Create the workflow with the kind set:

```http
POST /api/v1/workflow/definitions
{ "logicalname": "intro-sequence", "name": "Introduction", "kind": "sequence" }
```

`kind` is `flow` (the default), `journey`, `nurture` or `sequence`, and cannot be changed afterwards.
Then add a version with its graph and publish it. The graph's `settings.sequence.exit_on` says what
ends a contact's sequence:

```json
{
  "nodes": [ ... ],
  "edges": [ ... ],
  "settings": { "sequence": { "exit_on": ["reply", "meeting", "stage_change"] } }
}
```

| Exit | When |
|---|---|
| `reply` | An inbound message (`communication` with `direction` `inbound`) is filed on the contact, on the message itself or through a mail link. |
| `meeting` | A `meeting` activity is recorded on the contact. |
| `stage_change` | A deal (`opportunity`) at the contact's account changes `stage`. |

Leave `exit_on` out to use all three. An unknown name is refused when contacts are enrolled.

A changeset does not yet carry a workflow's kind. In each deployment, create the sequence through
the API with `kind` set.

## Sending window

Put a `sequence.send_window` step before each step that reaches the contact. It waits until the
contact's sending window opens, in the contact's own time zone:

```json
{ "id": "window", "type": "sequence.send_window", "config": { "start": "09:00", "end": "17:00", "days": [7, 1, 2, 3, 4] } }
```

`days` are weekdays from 1 (Monday) to 7 (Sunday). Every part is optional; the default is 09:00 to
17:00, Sunday to Thursday. The contact's time zone is their `time_zone` field when the contact entity
has one, else the zone of their `country_code` from the regions pack, else the deployment's
`app.time_zone`.

## Enrolling contacts

```http
POST /api/v1/workflow/sequences/intro-sequence/enrolments
{ "contact_ids": ["…", "…"] }
```

The caller needs `contact.update`. Up to 1,000 contacts at a time; each one gets one run of the
published version. The answer counts the contacts enrolled, those skipped because they are already
active in this sequence, and those that are not live contacts.

## Leaving

Every minute, the exit sweep reads the change feed (consumer `attome-workflow/sequence-exits`) and
marks the enrolment of each contact who answered as `exited`, with the reason. Before its next step,
the contact's run sees that and ends, so a contact waiting between steps is never sent the next one.

An enrolment whose run finished on its own becomes `completed`. A run that failed or was cancelled
leaves its enrolment `stopped`, with the run's status as the reason. Enrolments are kept in
`workflow_sequence_enrolment`.
