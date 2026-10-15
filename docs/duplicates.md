# Duplicate rules

A duplicate rule tells Attome when two records of one entity are probably the same
party or thing. Rules are managed under `/api/v1/admin/data/match-rules`; every save,
import and scan uses the same rules.

## A rule

| Setting | Meaning |
|---|---|
| `fields` | The fields compared, each with a `comparator` and a `weight` (above 0). |
| `threshold` | 0 to 1. A pair is a match when the weighted share of matching fields reaches it. |
| `on_save` | What saving a matching record does (below). Default `off`. |
| `scan_schedule` | `hourly`, `daily` or `weekly` full scans; absent, scans run on demand. |
| `auto_merge` | Offer a four-eyes merge request for low-risk pairs. |

The score is `Σ weight × matched / Σ weight`, over the fields with a value on both
sides; a field empty on either side gives no evidence.

## Comparators

| Comparator | Compares |
|---|---|
| `exact` | The text as stored. |
| `normalized` | Trimmed, lowercased, spaces collapsed. |
| `trigram` | Similarity at or above `min_similarity` (0.3 by default). Sweep only. |
| `phone` | The international number: `0501234567`, `+966 50 123 4567` and `00966501234567` meet. A phone field names `default_country` (`SA` or `966`). |
| `email` | The address, lowercased. |
| `id` | National ids and registration numbers without spaces, dashes or dots; Arabic-Indic digits read as ASCII. |
| `name` | Arabic letters folded (alef forms, taa marbuta, diacritics), titles dropped (Mr, Dr, السيد, الشيخ…), `عبد الله` joined, word order ignored. |
| `phonetic` | A transliteration skeleton, so `عبدالله`, `Abdullah` and `Abd Allah` meet. |

The five key comparators (`phone`, `email`, `id`, `name`, `phonetic`) store each
record's key in `match_key`, so a check is an index lookup.

## On save

| `on_save` | A create, update, upsert, bulk row or import row that matches |
|---|---|
| `off` | Saves. The sweep may still flag the pair later. |
| `warn` | Saves; the response lists the matches in `duplicate_warnings`. |
| `allow_with_reason` | Refused unless the request sends `Attome-Duplicate-Reason`; the reason is kept in the audit. Bulk and import rows carry no reason, so they are refused. |
| `block` | Refused with `409 duplicate_detected`. |

Matches the caller cannot read are never shown; they are counted (`hidden`).
`POST /api/v1/data/duplicates/check` runs the same check without saving.

## Finding pairs

- The **sweep** scores every created, updated or restored record against its peers.
- A **scan** (`POST /api/v1/admin/data/match-rules/{id}/scan`, on saving a rule, or
  on its schedule) scores every live record, 500 at a time, and resumes after a
  restart.
- **Rule preview** (`POST /api/v1/admin/data/match-rules/preview`) counts the pairs a
  draft rule would flag in 5,000 records, without saving anything.
- **Explain** (`GET /api/v1/admin/data/duplicates/{id}/explain`) shows each field's
  score and both records' keys.
- A pair a steward **dismisses** is not suggested again.

## Merging

`POST /api/v1/{entity}/{id}/merge` merges `duplicate_id` into the record at `id`:
fields the survivor lacks are filled from the duplicate (survivorship rules decide
conflicts), related records move to the survivor, and external ids are kept.
`POST /api/v1/{entity}/{id}/merge/preview` shows what would move and change first.

The **merge mode** per entity (`merge_setting`):

- `soft_delete` (default): the merged record is deleted.
- `keep_merged`: it stays, and reading it returns `merged_into`.

Each merge is logged. `POST /api/v1/{entity}/merges/{merge_id}/undo` undoes it as
one unit — the survivor's values, the merged record and every moved row — once, and
only while the survivor is unchanged since the merge (otherwise `409`). Undo needs
update and delete on the entity.

## Agents

Agents use `duplicates.check`, `duplicates.list`, `duplicates.merge` (a person
approves first) and `duplicates.propose_rules` (a draft with its preview; a person
saves it). A flow can branch on "if a duplicate exists" (`duplicate_check` node).
