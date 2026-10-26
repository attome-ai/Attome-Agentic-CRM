# Workforce management

Planning how many people a contact centre or service desk needs, building their shifts, publishing
them, and adjusting the day as it happens. The module is `workforce` (engine crate
`attome-workforce`, records from the `workforce` pack); everything here is off until the module is
licensed and the pack is applied.

## The records

- **Planning group** (`wfm_planning_group`): a team planned together: its channel (voice, chat,
  email, cases), its service target (for live channels, the share of contacts answered within a time;
  for deferred work, the backlog target), its average handling time, shrinkage, and whether intraday
  management is on (`intraday_enabled`).
- **Members** (`wfm_group_member`): who is in the group, and the shift templates and rule set each
  person may work.
- **Forecast** (`wfm_forecast_interval`): the expected volume per interval (15 or 30 minutes) for the
  group.
- **Shift templates** and **rule sets**: the shifts people can work, and the rules a week must keep:
  hours per day and per week, rest between shifts, night shifts, days off, and a shorter Ramadan day
  for people on the Ramadan pattern.
- **Schedules** (`wfm_schedule`) and their **assignments**: who works which shift on which day,
  draft until published.
- **Offers** (`wfm_offer`): intraday overtime or time off, proposed, sent, open and taken.
- **Swaps** and **preferences**: staff giving a shift to a colleague, and the days and start times
  they prefer.

Leave comes from `resource_availability`, the same records the rest of the platform books against.

## How many people each interval needs

The staffing requirement is computed, never typed in. A live channel (voice, chat) uses Erlang C
against its service target: the fewest agents that answer the target share of contacts within the
target time at the forecast volume and handling time. Deferred work (email, cases) uses the workload
over the backlog target. Shrinkage (breaks, training, absence) is added on top.

## Building and publishing a schedule

`POST /api/v1/workforce/groups/{id}/schedules/build` (`{from, to}`) queues a build and answers `202`
with its run id. The build reads the group's forecast, templates, members and their leave, turns each
day's forecast into a requirement and solves it. The solver gives each free person the shift that
covers the most unmet need, then improves the result by moving people between allowed shifts while
that lowers the cost. Under-staffing costs more than over-staffing, because a short interval misses
the service target while an extra person only costs money. Every person's week is then checked against
their rules. The result is a draft schedule with its coverage per interval.

`GET /api/v1/workforce/schedules?group_id=` lists schedules; `GET /api/v1/workforce/schedules/{id}`
shows one with its assignments and coverage. `PATCH /api/v1/workforce/assignments/{id}` (with
`If-Match`) moves an assignment or gives it to someone else. A move that breaks the person's rules is
refused with the rules it breaks, and a change to a published schedule needs a reason and tells the
person.

**What-if** (`POST /api/v1/workforce/schedules/{id}/what-if`) recomputes a schedule's requirement,
coverage and service level in memory with a changed forecast, targets or headcount; nothing is
written. **Hiring plan** (`GET /api/v1/workforce/groups/{id}/hiring-plan?months=6`) turns the stored
forecast into full-time equivalents per month.

## Staff self-service

- `GET /api/v1/workforce/me/schedule?from&to`: my own shifts on published schedules.
- `PUT /api/v1/workforce/me/preferences`: my preferred days and start times.
- `POST /api/v1/workforce/swaps`: give one of my shifts to a colleague in the same group. When the
  colleague's week still keeps their rules and coverage does not drop, the swap applies at once;
  otherwise it waits for a planner.
- A leave request shows its effect on coverage before it is approved.

## During the day

For a group with intraday management on, every 15 minutes the `workforce_intraday` job compares the
volume so far with the forecast. Until stored actuals exist, the volume is the service tickets on the
group's channel. The job scales the rest of the day's forecast by that trend (bounded between half and
three times) and recomputes what each remaining interval needs. For a run of intervals short by more
than one person it proposes an overtime offer; for a run that is over, time off.
`POST /api/v1/workforce/offers/{id}/send` tells the people who could take an offer, and
`POST /api/v1/workforce/offers/{id}/accept` lets the first of them take it, adding or trimming their
shift. Both are audited.

## Agents

The AI agent tools `workforce.coverage`, `workforce.explain_gap`, `workforce.my_next_day_off` and
`workforce.propose_fix` read the same figures. They never change a published schedule:
`propose_fix` lists the free people who could cover each short interval, for a planner to apply.

## Adherence

Each minute, every person whose presence is known gets one row: what the published schedule said
(`work`, `break`, `meal`, `training` or `off`), what they were doing, and whether that fits. Being
logged in and available fits `work`; not working fits a break or time off. A few minutes either side
of a scheduled change still count (`workforce.adherence_tolerance_minutes`, 3 by default). Minute
rows are kept 35 days.

Each night, yesterday's rows become each person's day: adherence (minutes that fit over minutes
seen) and conformance (minutes working over minutes scheduled to work).

- `GET /api/v1/workforce/adherence/live?group=` shows a planning group's people over the last five
  minutes, to a holder of `wfm_adherence.read` who is a member of that group.
- `GET /api/v1/workforce/me/adherence` shows the caller's own last 31 days.

Presence comes from a presence source; until the platform's presence events exist, a deployment
plugs one in, and nothing is written without one.

## Not built yet

The workforce KPIs and their default dashboard, the planner screens (group setup, schedule grid with
coverage chart, swaps queue, intraday proposals) and the staff mobile views come later. Until then the
routes above are the interface.
