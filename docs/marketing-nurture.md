# Marketing nurture

A nurture programme keeps sending a person the next useful email until they are ready for sales,
then hands them over. Programmes, their tracks and their content are records of the marketing pack
(`marketing_nurture_program`, `marketing_nurture_track`, `marketing_nurture_content`), edited on their
generic forms. A programme runs inside a journey: its journey's `marketing.nurture_run` step puts each
person in the programme (see [journeys](marketing-journeys.md)).

## Setting up a programme

1. Make the programme's journey from a starter template (`nurture-new-subscriber`,
   `nurture-content-download`, `nurture-webinar-attendee`, `nurture-lost-deal`, `nurture-recycled-lead`,
   in the marketing pack) or by hand: a trigger and a `marketing.nurture_run` step naming the consent
   purpose.
2. Create the programme with that journey as `journey_ref`, an `audience_list_ref` if the journey
   enrols from a list, and `cadence_days` (7 by default).
3. Add tracks: each names a `lifecycle_stage` (or `any`), an optional `interest` and a `language`
   (`ar`, `en` or `any`). A person goes to the track that fits them best: the exact stage before `any`,
   the exact interest before none, the exact language before `any`.
4. Add each track's content in `position` order: `content_kind` `email` with the saved email design's
   id as `content_ref`. Article and event items are kept but not sent.
5. Set the programme's `status` to `active`. A draft or paused programme holds its people a day at a
   time; a retired one lets them go.

## The drip

Every minute the drip sends each due person the first email of their track they have neither seen
(opened or clicked from any send of the same saved design) nor been sent by this programme, through
the journey rules (consent for the purpose, suppression, sunset, quiet hours, the weekly cap). The
next one is due after `cadence_days`. With nothing left to send, the person stays in the programme
for content added later.

The drip is driven by a scheduler inside one journey step rather than by repeating graph nodes, so
a programme of any length is one step in its journey, a person's place survives a new journey
version, and a send can never be repeated by replaying the graph.

**Switches, all off by default:**

- `tracks_enabled`: people move between tracks as their stage, interest or language changes; what
  they have seen still counts. With `acquisition_only`, a person who becomes a customer leaves.
- `pause_enabled`: while sales works a person (an active sales sequence, a meeting about them in the
  last 14 days, or an open hand-off), their drip holds a day at a time.
- `recycling_enabled`: a hand-off sales returns starts the person's nurture again on its wake-up
  date.
- `sla_enabled`: a hand-off not decided within `sla_business_hours` (8 by default, on the working
  calendar) becomes overdue and the assignee's manager is told.
- `agent_suggestions_enabled`: the agent tools below may read the programme.

## Hand-off to sales

A programme names a points model (`handoff_score_model`, its id) and a score (`handoff_threshold`).
When a nurtured person's score rises to it they are handed off once (a score that stays high does not
hand them off again; falling below and rising again does): the hand-off records the score and the
content they saw most recently, their `lifecycle_stage` becomes `sales_qualified`, a lead is assigned
by the lead assignment rules, the hand-off is due after the SLA hours, and the owner is notified.

On a lead's or contact's form, the **Nurture** tab shows the pending hand-off with Accept and Return
(a reason and a wake-up date), then the person's programmes, the content they saw and their past
hand-offs. Only the assignee, their manager or an administrator may decide.

Routes (shapes in `openapi.json`):

- `POST /api/v1/marketing/handoffs/{id}/accept`, `POST /api/v1/marketing/handoffs/{id}/return`
- `GET /api/v1/marketing/handoffs`: your hand-offs, or with `marketing_nurture_program.read` every
  hand-off of a person you may read.
- `GET /api/v1/marketing/people/{person_id}/nurture-history`
- `GET /api/v1/marketing/nurture/programs/{id}/stats`: people by state and track, conversion to a
  hand-off by track, the content most often seen before a hand-off, and the SLA over 90 days.

## Agent tools

Where a programme has `agent_suggestions_enabled`: `nurture.suggest_content`,
`nurture.draft_summary` and `nurture.find_stalls`, all read-only. No tool creates or decides a
hand-off. See [agents](agents.md).
