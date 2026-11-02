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
- **Nurture:** `marketing.nurture_run` (`purpose`, optionally `program_id`; otherwise the nurture
  programme whose journey this is) puts the person in the programme on the track that fits them and
  waits there. Every minute the drip sends each person the next email of their track, by position,
  that they have neither seen (opened or clicked from another send of the same saved design) nor been
  sent by the programme, through the same rules, one per the programme's `cadence_days`. When the
  person leaves the programme (handed to sales, a customer leaving an acquisition programme, a retired
  programme), the step completes and the journey goes on. Only email content is sent.
  A programme hands a person to sales when their score on its points model (`handoff_score_model`)
  rises to `handoff_threshold`: once per rise, with a summary of what they saw, their
  `lifecycle_stage` set to `sales_qualified`, a lead assigned by the assignment rules, a due time
  from `sla_business_hours` on the working calendar, and the owner notified.

Every step a module contributes, with the JSON Schema of its settings, is listed by
`GET /api/v1/workflow/step-handlers`; an engine adds one through `WorkflowStepHandler`
(`config_schema` and `available` describe it to the editor).

## Publishing a new version

`GET /api/v1/marketing/journeys/{id}/versions/{version_id}/preview` shows, before publishing, how many
people wait at each node, whether the new version keeps it and how many a move would move. When a new
version is published, people already in the journey either finish on the version they
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

## Simulating and publishing

`POST /api/v1/marketing/journeys/{id}/simulate` runs the newest published version for up to 20 sample
people, each person's record as the trigger, and returns every step of each run without waiting,
sending or writing anything. `POST /api/v1/marketing/journeys/{id}/publish` with `{"version_id", "version_mode"}` publishes a draft
(the workflow's own publish checks run), places the people already in the journey (`finish_on_old` or
`move_matching`, as above) and makes a draft journey live. When the journey names a `publish_role`, only
its holders (and administrators) may publish.

## Starter journeys

The marketing pack ships seven starter journeys as flow templates (`flow_template` objects of app
`marketing`): welcome, onboarding, event reminder, abandoned form, re-engagement, renewal reminder and
post-purchase feedback. Each asks for its email designs and consent purpose (and has default waits),
and becomes a draft through `POST /api/v1/admin/model/flow_template/{id}/instantiate`, saved as the
journey's draft version. Nothing is live until someone publishes it.

It also ships five nurture programme journeys (new subscriber, content download, webinar attendee, lost
deal, recycled lead): a trigger and the nurture step, for a programme whose `journey_ref` is the journey
made from one. The pack's changeset 0016 adds two stored queries, leads and contacts per lifecycle stage.

## In the workflow editor

A journey is edited on the workflow canvas. Its picker lists the marketing steps under "Steps from
modules", each with a settings form built from its schema. For a journey the canvas also shows each
step's live counts (read every ten seconds), replays one person's path step by step, and on Publish asks
what happens to the people already in it, showing the preview. In Arabic the canvas runs right to left,
node types are named in Arabic, and a wait shows its Hijri date.

## Agent tools

`journey.draft` drafts a journey's graph from a description and returns it with a diff against the
current draft and the call that saves it as a draft; nothing is saved or published, and a draft may use
only waits, branches and registered marketing steps. `journey.explain_person` explains one person's path;
`journey.suggest` names the step most people leave at and the most common block reasons. No agent tool
publishes a journey or enrols anyone.

