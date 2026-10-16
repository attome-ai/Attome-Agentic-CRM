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

Text results respect the string-length budget and number results must be finite, as for every
function.
