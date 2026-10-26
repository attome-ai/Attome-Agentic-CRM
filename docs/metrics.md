# Metrics: building, computing and targets

A metric is a definition (`dashboard_metric_definition`) whose values are kept as snapshots, one per
period. A snapshot is never changed: a recomputation is a new row. This page covers building a
metric from its parts, the order metrics are computed in, and targets spread over a dimension.

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

## Computing

`POST /api/v1/metrics/{id}/compute` computes one metric for its current period.
`POST /api/v1/metrics/{id}/compute-tree` computes the metric and everything it is built from: its
children (metrics whose `parent_ref` names it) and the metrics its formula reads, transitively. A
metric is always computed after its inputs, so a formula reads the snapshots of the same run. The
answer lists each metric's outcome: `computed`, `skipped` (a snapshot for the period existed) or
`failed` with the reason. One failure does not stop the rest. A cycle is refused with `422` naming
the metrics in it.

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
