# Dashboard drill-down and explain

For builders and integrators: what a dashboard number is made of and how a person gets from the
number to the records behind it. Every route here reads as the caller, so record and field security
apply, and none of them writes anything. The dashboard read privilege (`attome_dashboard.read`) is
needed for all of them.

## The records behind a number

`POST /api/v1/attome-dashboard/{id}/widgets/{widget_id}/records` lists the records behind a
widget's value or one of its buckets (`bucket_key`, `series_key`, exactly as the data route returned
them). It uses the same definition, parameters, cross-filters, timezone and record scope as the
number, pages by keyset (`after_id`, `page_size` up to 200) and gives an exact `total`.

- **Chart widgets** over one entity drill exactly, including widgets over a stored query or a view
  of one entity, where the clicked bucket's grouping values become filters on the query.
- **Governed metric widgets** list the records the metric's definition counts now, with
  `metric_parity` beside the period's snapshot value. Metrics without a definition built from
  parts are explain-only.
- **`aggregate_only`** on a widget's config turns its record list off (422, code
  `aggregate_only`); the explanation still works. A KPI drill says `some_records_hidden` when the
  viewer reads less of the entity than the metric counts, never how many.

Every answer carries:

| Field | Meaning |
|---|---|
| `applied_filters` | Each filter with its origin: the definition, a parameter, a cross-filter, or a built-in such as the current user. |
| `parity` | Whether the listed total equals the widget's number: `matches`, the `value`, the `listed_total`, and a `reason`: `equal`, `data_changed_since_computed`, `rounding`, `currency_converted_at_other_date` or `not_comparable` (a sum or average is not a count of the records). |
| `drill_through` | Where a click on this bucket goes, when the widget has one (below). |
| `trails` | One per listed record: its `timeline_url`, the `last_change_audit_id` of the newest change to a field the widget filters on, and the `agent_run_id` when an agent made that change. |

## Drilling down a level

A chart widget's config may list `drill_levels`: an ordered list of `{attribute, grain}`, the grain
`year`, `quarter`, `month`, `week`, `day`, `hijri_month` or `hijri_year` for a date field and absent
for any other field:

```json
"drill_levels": [
  { "attribute": "close_date", "grain": "year" },
  { "attribute": "close_date", "grain": "quarter" },
  { "attribute": "owner_ref" }
]
```

`POST .../widgets/{widget_id}/drill-down` with `path` (the bucket keys clicked so far) returns the
next level's buckets under them, each with its value, and a `breadcrumb` back. `additive` says
whether the children add up to the parent: true for a count or a sum, false for an average, a
distinct count, a minimum, a maximum or a median. Past the last level is a 422. Publishing blocks a
malformed list.

## Drill-through

A widget's `drill_through` sends a click elsewhere:

```json
"drill_through": {
  "target_kind": "dashboard",
  "target_dashboard_id": "…", "target_page_id": "…",
  "param_map": { "region": "status" }
}
```

`target_kind` is `dashboard` (with `target_dashboard_id` and optionally `target_page_id`) or `route`
(with `route`, an application path such as `/xrm/entity/account/list`). `param_map` maps each target
parameter to the clicked attribute whose value it takes. The records answer carries the resolved
target and values; the target applies its own access checks when it opens. Publishing blocks a
missing target dashboard or a route that does not start with `/`, and warns about a parameter the
target page does not declare.

## Comparing two periods

`POST .../widgets/{widget_id}/compare` with `period_a` and `period_b` (each `{from, to}`, `from`
included and `to` not) works on a chart grouped by a date. It lists the records in period B and not
in A (`entered`), in A and not in B (`left`), paged by id, and, for records in both, the newest
change of the measured field from the field history (`changed`). A period with more than 5,000
records is a 422 `too_large`.

## Explaining a number

`POST .../widgets/{widget_id}/explain` says how the number was calculated: the measures, the
filters with their origins, the grouping, the timezone, the caller's record scope and, for a
governed metric, the metric, its target and its lineage. It also gives the number in words,
`definition_en` and `definition_ar` ("Total Amount of Deals where Status is won, by Owner"), the
`measure_basis` (the date field and grain), and for a metric `computed_at` and `lineage_url`
(`/api/v1/metrics/{id}/lineage`). `glossary_term_id` and `currency` are part of the answer but stay
empty for now: glossary terms link to entities, not measures, and amounts carry no currency code yet.

The agent action `dashboard.explain_number` restates the explanation in plain words in the
person's language, citing each filter, and changes nothing.

## On screen

Clicking a value opens the records drawer: the filters as chips, a parity banner when the totals
differ, the hidden-records note, the records with load more and export, a "changed by an agent"
mark, **Drill down** when the widget has drill levels (with a breadcrumb), **Open details** when it
has a drill-through, and a **Compare periods** tab for a chart grouped by a date. **How was this
calculated?** opens the explanation, starting with the number in words. Both are in English and
Arabic, right to left in Arabic, and take the full width on a phone.
