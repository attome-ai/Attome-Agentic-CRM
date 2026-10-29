# Metrics: building, computing and targets

A metric is a definition (`dashboard_metric_definition`) whose values are kept as snapshots, one per
period. A snapshot is never changed: a recomputation is a new row. This page covers building a
metric from its parts, periods and dimensions, status bands, the order metrics are computed in,
versions, backfill, targets spread over a dimension, who sees what, scorecards, and the agent
actions that draft metrics and commentary.

## Building a metric from its parts

`POST /api/v1/metrics/{id}/builder` describes the metric instead of writing SQL. It needs the
metric's update privilege.

| Part | Meaning |
|---|---|
| `entity_logicalname` | The records counted or measured. |
| `aggregate` | `count`, `sum`, `avg`, `median`, `min` or `max`. |
| `measure_attribute` | The number aggregated (not needed for `count`). |
| `date_attribute` | The date that places a record in the metric's period. |
| `filters` | Conditions on attributes (`attribute`, `op`, `value`). |
| `dimension_attributes` | Up to three attributes to break the value down by. |

The builder writes the metric's stored query and points the metric at it; building again republishes
the same query. Sensitive attributes and a non-numeric measure (other than for `count`) are refused.

## Periods

A metric's `period` is `day`, `week`, `month`, `quarter` or `year`. Its `calendar_kind` decides how
periods are cut: Gregorian by default, or `hijri` for Umm al-Qura months and years (a Hijri metric
has no day, week or quarter periods). `week_start` (`sat`, `sun` or `mon`) sets where a week begins.
A snapshot's `period_start` is the first day of its period on the metric's own calendar, for a
computed value, a scheduled one and a backfilled one alike.

## Dimensions

A metric with `dimension_attributes` keeps, beside its total, one snapshot per member of each
dimension (at most 1,000 members). `GET /api/v1/metrics/{id}/snapshots?dimension_attribute=` lists
them. A member of a lookup dimension is a record, and is shown only to people who may read it (see
"Who sees what").

## Status bands

Each value is judged against its period's target: `on_track`, `at_risk` or `off_track` (and
`failed` when it could not be computed). With `threshold_warn` and `threshold_crit` on the target,
those decide; otherwise `at_risk_tolerance` does: meeting the target is on track, missing it by up to
that percent of the target is at risk, and missing it by more is off track. A member is judged
against its own target when it has one, else the total's. `direction` says whether higher or lower
is better.

## Computing

`POST /api/v1/metrics/{id}/compute` computes one metric for its current period.
`POST /api/v1/metrics/{id}/compute-tree` computes the metric and everything it is built from: its
children (metrics whose `parent_ref` names it) and the metrics its formula reads, transitively. A
metric is always computed after its inputs, so a formula reads the snapshots of the same run. The
answer lists each metric's outcome: `computed`, `skipped` (a snapshot for the period existed) or
`failed` with the reason. One failure does not stop the rest. A cycle is refused with `422` naming
the metrics in it.

## Versions

The fields that define a metric (its source, query, formula, period, filters, dimensions, calendar
and the like) are fingerprinted with each snapshot. A snapshot computed under a different
fingerprint starts the next `definition_version`, so a chart never joins values measured two ways
without saying so; `definition_version` on the metric is a floor an administrator may raise. A new
version withdraws the metric's certification.

## Backfilling past periods

`POST /api/v1/metrics/{id}/backfill` with `{from, to}` queues a job that computes the metric for
each period from the one containing `from` up to `to`, stopping before the current period (the
schedule computes that one). The answer is `202` with the range and `queued: false` when a backfill
of the metric is already queued. A range over ten years is refused with `422`. The job computes
twelve periods a run, oldest first, and queues itself for the rest.

Each value is a new snapshot with `is_backfill: true`. A period that already has a snapshot that did
not fail is left alone, so running a backfill again, or over a range that overlaps, never adds a
second value.

Only two kinds of metric can be backfilled:

- **A metric built from its parts**: its records are placed in periods by its date field and
  aggregated as the metric service principal. Filters read the records' values now, so a filter on
  a field that changes over time, such as a status, counts records as they are today. A metric with
  dimensions gets its total, not its members.
- **A formula metric**: computed from its inputs' snapshots for the same period, so backfill the
  inputs first. A period whose inputs have no value is left empty.

Any other query metric measures the current period only, and a manual metric has nothing to
compute; both are refused with `422`.

The scheduled sweep computes query and formula metrics in the same order. When the definitions form
a cycle, it computes query metrics only and logs the cycle.

## Cascading targets

A target belongs to a metric and a period. `POST /api/v1/metrics/{id}/targets/spread` sets the
period's total and spreads it to the members of one of the metric's dimensions:

```json
{ "period_start": "2026-07-01T00:00:00Z", "total": 1000, "method": "share",
  "dimension_attribute": "region", "shares": { "central": 0.5, "east": 0.3, "west": 0.2 } }
```

- `share` uses the given shares, which must add up to 1 (within 0.001).
- `last_year` uses each member's actual for the same period a year earlier.

Children are rounded to cents, and the last one takes the remainder, so they always add up to the
total. Each child names its parent (`parent_target_ref`). Spreading again updates the same targets
rather than adding new ones. A second spread of the same metric and period while one runs gets
`409`. It needs `attome_metric.set_target`, and it writes a `Configuration` audit event.

## Who sees what

- A metric whose `visible_role_keys` names roles (a list of role names) is listed, and its values
  read, only by people holding one of those roles, and by administrators; to anyone else it does
  not exist. Its totals are company-wide values, so name the roles that may see them.
- A breakdown by a lookup (an owner, an account) shows a member only to people who may read that
  record. A member value that cannot be read as record ids, or a metric whose entity is unknown,
  is shown to administrators only.
- Entering a value by hand (`actual` on `/compute`) needs `attome_metric.enter_value`.
- Certifying needs `attome_metric.certify`: `POST /api/v1/metrics/{id}/certify` with
  `{certified: true}` or `false` is the only way to set `certified` and `certified_at`, which the
  record API refuses; a new metric starts uncertified. A value computed under a new definition
  version withdraws the certification.

## Scorecards, freshness and comments

`GET /api/v1/metrics/scorecards/{id}` reads a scorecard (as the caller, with the record's own
access checks) and, for each of its metrics the caller may see, the newest stored total: its
period, value and status, that period's target, and its freshness (`computed_at`, `is_stale` when
it is older than twice the metric's period or missing, `failed` when it carries an error). Nothing
is computed on read.

`GET /api/v1/metrics` also gives each metric's `certified`, `steward_ref`, `review_due`,
`definition_version`, `glossary_term_ref` and `used_in` (how many scorecards show it; dashboards
are not counted). `GET /api/v1/metrics/{id}/comments` lists the comments on a metric the caller
may read, newest first, optionally for one `period_start`.

## Agent actions

`metric.draft_definition` turns a sentence into a builder spec, checked against the deployment's
entities, and saves nothing. `metric.draft_commentary` drafts a period's commentary from the stored
values and returns the `record.create` call that would save it as a comment. Neither can certify,
set a target or name a steward.
