# Marketing journeys

A journey is a workflow of kind `journey` that takes people (contacts or leads) through messages,
waits and decisions, one run per person. Its marketing settings live on a `marketing_journey` record
that names the workflow (`workflow_definition_logicalname`); its status (`draft`, `live`, `paused`)
moves only through the journey engine.

## How people enter

A live journey takes people from its `entry_sources`, a list of:

- `{"type": "segment_entered", "list_id"}`: someone joins a marketing list;
- `{"type": "event", "event_name", "entity"?, "filter"?}`: a named event (`form.submitted`,
  `email.clicked`, `record.created`, `record.changed`, ...), optionally on one entity, whose record
  passes a rule `filter`;
- `{"type": "date", "entity", "attribute", "offset_days", "calendar", "time"?}`: people whose date plus
  the offset is today, in the Gregorian or the Hijri calendar;
- `{"type": "list_at", "list_id", "at"}`: a list's members, once, at a set time;
- `{"type": "api"}`: enrolled through the API.

`POST /api/v1/marketing/journeys/{id}/enrolments` enrols up to 1,000 people by hand (only people the
caller may read; `is_test` for test runs, which a draft journey also takes).

Every entry goes through the same admission: never someone already in the journey; then the journey's
re-entry rule (`never`, `after_exit`, or `after_cool_off` with `cool_off_days`); then the daily entry
cap. Test runs never count toward the cap and never block a real run.

## While a person is in a journey

Before every step the person's record is checked against the journey's `exit_condition` (the run ends,
the enrolment is `exited`) and `goal_condition` (the goal is recorded once; the run ends there only
when `goal_exits` is set).

Steps the marketing engine adds to the workflow:

- **Messages:** `marketing.send_email` sends a saved email design for a consent purpose, optionally at
  the person's best hour. Before any message the rules are read in order: consent for the purpose and
  channel, the suppression list, the sunset policy, quiet hours and weekend days
  (`marketing.journey_quiet_hours`), the working calendar (`marketing.journey_calendar_ref`) and the
  weekly cap (`marketing.weekly_message_cap`, 3 by default, shared with campaigns). A blocked step is
  recorded with its reason and either skipped or retried a day later (`on_blocked`). A replayed step
  never sends twice.
- **Control:** wait for working time or a Hijri month, check engagement with an earlier send, split the
  audience. Waiting for a duration, a date or an event uses the workflow's own wait nodes.
- **Actions:** add to or remove from a static list, add to a campaign.

## Publishing a new version

When a new version is published, people already in the journey either finish on the version they
started (`finish_on_old`) or move to the new one where they wait (`move_matching`). Only a waiting run
whose waiting nodes exist in the new version, and which has already passed every node the new version
puts before them, moves; everyone else finishes on the old version.

## Watching a journey

- `GET /api/v1/marketing/journeys/{id}/counts`: per node, how many entered, wait there, passed, were
  blocked and left there, with the goal conversion. Counts are recomputed every 30 seconds for versions
  with recent runs.
- `GET /api/v1/marketing/journeys/{id}/people/{person_id}/path`: one person's runs, the nodes in order,
  the blocks with their reasons and how each run ended.
- `DELETE /api/v1/marketing/journeys/{id}/enrolments/{enrolment_id}` takes a person out: the enrolment
  ends as `removed` and the run is cancelled.

- `POST /api/v1/marketing/journeys/{id}/pause` stops a live journey: it takes no one new and every run
  in it pauses where it is, whatever its next step; `POST .../resume` makes it live again and the runs go
  on where they stopped.

Reading needs `marketing_journey.read`; enrolling, removing, pausing and resuming need
`marketing_journey.update`.

## Erasure

Erasing a person (a data subject request, a direct erasure, or a replayed one) also deletes their
journey enrolments, blocks and message log, and cancels their running journeys, in the same transaction.

## Not built yet

Publishing with a version choice and simulation have no journey routes yet; publish through the
workflow routes.
