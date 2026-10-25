# Rule language functions

Business rules, formulas, workflow conditions and filters share one expression language
(`attome-rules`). A stored expression records the language version it was written in, so it keeps
its meaning as the language grows: V1 text compiles under V1 only, and a V2 function used in V1 text
is an unknown function. V2 accepts every V1 expression unchanged.

## V1

`if`, `coalesce`, `len`, `lower`, `upper`, `trim`, `contains`, `startswith`, `date_add`,
`date_diff`, `today`, `now`, `round`, `min`, `max`, `in`, `is_null`; the operators
`+ - * / %`, comparisons, `and`, `or`, `not`; field references `field` and one-hop
`lookup_field.target_field`; list literals `[a, b]`.

## Added in V2

| Function | Result |
|---|---|
| `endswith(text, suffix)` | Whether `text` ends with `suffix`. |
| `normalize_ar(text)` | Arabic folded for comparison: alef forms to bare alef, alef maqsura to ya, taa marbuta to ha, diacritics and tatweel removed. `normalize_ar("أحمد") == normalize_ar("احمد")` is true. |
| `concat(text, ...)` | The texts joined. |
| `substr(text, start, length)` | Characters from `start` (0-based); a range outside the text gives what is inside it, possibly empty. |
| `replace(text, from, to)` | Every `from` replaced by `to`; an empty `from` changes nothing. |
| `abs(n)`, `floor(n)`, `ceil(n)` | As named. |
| `power(n, k)` | `n` to a whole power `k` from 0 to 10. |
| `clamp(n, low, high)` | `n` kept between `low` and `high`. |
| `round_currency(amount, code)` | Rounded to the currency's minor units (3 for KWD, BHD, OMR, JOD and IQD; 0 for JPY; 2 for most others). |
| `convert(amount, from, to)` | Converted through the rates the caller supplies on the evaluation context (each rate is the value of one unit in the base currency). A code the ISO table does not know is `rules.currency.unknown`; a missing rate is `rules.currency.no_rate`. |
| `minor_units(code)` | The currency's number of decimal places. |
| `matches(text, pattern)` | Whether the whole text matches the pattern. The pattern must be a text literal (`rules.regex.not_literal` otherwise); it is compiled once when the rule is saved, under a size limit (`rules.regex.invalid` when it is too large or does not compile), and runs in linear time, so no pattern can hang the server. |
| `sum(list)`, `avg(list)` | Total and mean of a list of numbers; nulls are skipped, and `avg` of none is null. |
| `count(list)` | The number of elements. |
| `first(list)` | The first element, or null. |
| `any(list, x => condition)`, `all(list, x => condition)` | Whether the condition holds for some, or every, element. |
| `filter(list, x => condition)` | The elements for which it holds. |
| `map(list, x => value)` | The value for each element. |
| `hijri_year(date)`, `hijri_month(date)`, `hijri_day(date)` | The Umm al-Qura date in the context's zone; outside 1356 to 1500 AH is `rules.hijri.out_of_range`. |
| `hijri_date(year, month, day)` | The start of that Hijri day in the context's zone. |
| `add_workdays(date, n)` | The same time of day `n` working days later (negative: earlier), on the business calendar the caller supplies. |
| `workdays_between(a, b)` | The working days after `a` up to and including `b` (negative when `b` is earlier). |
| `is_working(date)` | Whether the date is a working day of the calendar. |
| `to_zone(date, zone)` | The same instant, with an IANA zone checked (`rules.context.unknown_timezone` otherwise). |
| `prev(field)` | The field's value before this write: the stored value on an update, null on a create. The argument is a field of this record. |
| `changed(field)` | Whether this write changes the field: on an update, whether it differs from the stored value; on a create, whether it has a value. |

The working-day functions count on the business calendar the caller puts in the context; without
one they fail with `rules.calendar.missing` (never counting calendar days instead), and a calendar
with no working days in reach fails with `rules.calendar.no_working_time`.

`prev` and `changed` read the stored row when the caller puts it on the context (business-rule
values on an update do); elsewhere every write counts as a create.

Text results respect the string-length budget and number results must be finite, as for every
function.

## Related lists and lambdas (V2)

A caller can give a rule a related list, such as an order's lines: `Schema::with_related_list("lines",
fields)` and `Context::with_related_list("lines", rows)`. The list functions read it, and
`x => ...` (a lambda) names each element: `sum(map(lines, l => l.qty * l.price)) > 1000`,
`any(lines, l => l.qty == 0)`. A lambda is only the second argument of `any`, `all`, `filter` or
`map` (anywhere else it is a parse error), lambdas nest at most two deep
(`rules.budget.lambda_depth`), and every element visited costs an evaluation step, so a long list
cannot escape the step budget. The language loads no rows itself: the caller supplies them.

## User functions (V2)

A deployment can define its own functions: a name, typed parameters, a result type and a V2
expression over those parameters only (no record fields). `FunctionLibrary::build` checks them:
a name is a lowercase letter then letters, digits or `_`, never a built-in name
(`rules.function.invalid`); at most 200 functions of up to 8 parameters; a function may call
built-ins and other user functions, but never itself, directly or through others
(`rules.function.recursive`). A rule compiled with the library (`compile_with_library`) calls
them like built-ins, its arguments checked against the parameters, and the steps a function takes
count against the calling rule's budget.

## Decision tables

A decision table lists rows of conditions on named inputs and a result: each cell is a V2
condition on its input, read as `it` (`it >= 100 and it < 500`, `it == "gold"`,
`in(it, ["a", "b"])`), or empty for any value; each result is a V2 expression over the inputs.
`First` answers the first matching row (null when none matches); `All` answers every matching
row's result as a list. `check()` reports number ranges no row covers, pairs of rows that can both
match, and cells of any other form as unchecked, never guessing about those. A table has at most
500 rows and 10 inputs (`rules.budget.table_size`).

## Paths (V2)

V1 reads a field (`amount`) or one hop (`account.tier`). V2 also reads a path of two or three hops,
`deal.account.owner.region`; four hops or more is `rules.lookup.multi_hop`, as is any path in V1.
The language loads nothing itself: the caller declares each path's type
(`Schema::with_path`, or `with_optional_path` for one that may be empty), asks the compiled rule
which paths it reads (`Compiled::paths()`), checks the person may read every hop, and supplies the
values (`Context::with_path`). An unloaded path is `rules.field.unknown`, or null when declared
optional.

