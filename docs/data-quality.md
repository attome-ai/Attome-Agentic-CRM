# Data quality

Attome measures the quality of data already stored: six dimensions per entity, rules that
measure without blocking a save, targets, issues with owners and due dates, bulk fixes with
undo, daily snapshots and alerts. Checks that refuse a save are validation rules, not
quality rules; duplicates come from the duplicate rules ([Duplicate rules](duplicates.md)).
The screen is **Administration → Data → Quality** (`/xrm/admin/data/quality`).

## Dimensions

Each dimension is a pass rate over checks, 0 to 100.

| Dimension | One check per | Fails when |
|---|---|---|
| `completeness` | record and required attribute | the value is empty |
| `uniqueness` | record | the record is in an open duplicate pair |
| `validity` | record and enabled validity rule | the rule's condition does not hold |
| `consistency` | record and enabled consistency rule | the rule's condition does not hold |
| `timeliness` | record | it changed longer ago than the target's `timeliness_days` |
| `accuracy` | verified value | not measured yet: there is no verification source |

A dimension with nothing to check scores 100; one that is not measured (timeliness without
`timeliness_days`, accuracy) does not count. `overall` is the measured dimensions weighted by
the target's `dimension_weights` (1 each when unset). Validity, consistency and timeliness are
measured over the 1,000 newest live records of the entity.

## Rules

A quality rule is a condition in the rule language ([Rule language](rule-language.md)),
evaluated by the same evaluator as every other rule, with a dimension (`validity` or
`consistency`), a severity and a weight. It only measures: a record that fails it is saved
as usual and counted. Consistency rules compare a record's own attributes
(`end_date >= start_date`).

## Targets

One target per entity sets the dimension weights, the threshold (0 to 100, default 70), the
timeliness age in days, whether each record gets its own score (`record_scoring`, off by
default) and how many days an issue has (`issue_sla_days`, default 7).

## When scores change

- **As records change.** Every minute the incremental sweep reads the change feed, rescores
  the changed records (when record scoring is on) and recomputes the entity's dimensions.
  Nothing joins a record's save.
- **When the rules change.** A change to an entity's rules, weights, threshold, timeliness
  target, required attributes or record scoring rescans all its records in batches of 500,
  one background job per batch; a restart resumes where it stopped.
- **Daily.** A snapshot of every entity's scores is kept for the trend, entities with a
  timeliness target are rescored (their scores age without changes), and alerts are sent.

A record score is its share of passed checks (one per required attribute, one per enabled
rule) with a finding for each failed one.

## Issues

A failing check opens an issue on the record and attribute. A new issue goes to the steward of
the entity's data domain, else the record's owner, and is due `issue_sla_days` after it was
found. Its owner (or an administrator) moves it through `open`, `in_progress`, `fixed`,
`accepted` (a reason is required) and `resolved`. How many issues one run opens is capped by
the settings `quality.max_issues_per_run` (2,000) and `quality.max_issues_per_entity`.

People with `metadata.read` see the issues of the entities they may read, and only on records
they may read; the list's total counts the same records as its page, so a partial reader never
learns how many issues the whole entity has.

Issues have columns for the channel, import and person a bad value came from, and the alerts
and the agent tools group by them, but nothing fills them yet.

## Fixes

A fix runs one transform over chosen records: `trim_spaces`, `title_case`,
`digits_to_western` or `phone_e164` (the country from `core.country`, else Saudi Arabia). The
preview counts the records it would change and shows samples before and after; applying it is
one bulk edit, with row versions, the approval threshold and an undo list, and it clears the
fixed records from the validation clean-up queue. Filling a value from a trusted source is not
built.

## Alerts

After the daily snapshot an entity below its threshold, or whose overall score fell more than
`quality.drop_alert_points` (default 10) since yesterday, is reported once that day. The
message names the main source of its open issues. It goes to the domain's stewards, else the
entity's owners, else holders of the compliance administration area, else the longest-standing
full administrator; never to every administrator.

## Agent tools

`quality.explain_drop` lists each dimension's change between two days, biggest fall first, with
the sources and attributes holding the most open issues. `quality.record_score` returns one
record's score and findings against the threshold. `quality.propose_rules` drafts validity
rules from the newest profile (an attribute filled in at least 99% of rows, a number never
negative) and writes nothing.

## Arabic checks

`attome_api::quality_arabic` has the built-in checks (mixed scripts in one word, an English
name without the Arabic one, mixed Western and Arabic-Indic digits, a Hijri year stored as a
Gregorian date or the reverse), each with English and Arabic messages. They are not yet run
by the scoring.

## Routes

All under `/api/v1/admin/data/quality`:

| Route | Does |
|---|---|
| `GET /scores`, `GET /scores/history` | Latest scores; the trend of completeness and uniqueness. |
| `GET /issues` | The issue queue, filtered by entity, dimension, status or owner. |
| `PATCH /issues/{id}` | Change an issue's status (owner or administrator). |
| `POST /issues/{id}/resolve` | Resolve an issue. |
| `GET`, `POST /rules`; `PATCH`, `DELETE /rules/{id}` | Quality rules (`PATCH` needs `row_version`). |
| `GET /targets`; `PUT`, `DELETE /targets/{entity}` | Targets. |
| `POST /fixes/preview`, `POST /fixes/apply` | Bulk fixes. |

Every rule and target change writes a configuration security event.
