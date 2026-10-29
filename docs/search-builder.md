# Search for builders

How a deployment's search finds records, and the settings that shape it. Every route here needs an
administrator; search itself only ever shows a person the records they may read.

## What is searched

Each entity is searched by its record title (its primary name attribute) and the text of its other
searchable attributes. `GET /api/v1/admin/search/entities/{entity}` shows an entity's settings and
`PUT` the same path replaces them (send `If-Match` with the `row_version` you read, `"0"` the first
time):

| Setting | Meaning |
|---|---|
| `enabled` | Whether the entity is searched at all (default yes). |
| `max_age_days` | Leave out records not changed for this many days (default: none). |
| `boost` | How much the entity's results weigh against others (default 1). |
| `attributes` | Each attribute's `mode` and `weight` (0 to 10): `key` (matched exactly in its normalised form, as well as being text), `text` (full text) or `off` (not searched). |
| `document_embedding`, `image_embedding` | Meaning search over documents and images; off by default. Image search is not built yet (A25-T6): the switch is stored and does nothing. |

Without a setting, a phone, email, identity number, code or reference attribute is a `key` and
every other searchable attribute is `text`. A phone is kept in its international form, so `0501234567`
finds `+966501234567` when the deployment's `core.default_country` is `SA`.

## Arabic and English

Arabic is normalised before it is indexed and searched (hamza forms, taa marbuta, alef maqsura,
diacritics and tatweel), so a spelling variant finds the record. A record's title is also found
from its spelling in the other script: `Abdullah`, `Abdallah` and `Abd Allah` find `عبدالله`, and
`Mohammed` finds `محمد` (A25-T12). The title's words are kept as transliteration skeletons, the
consonants of the name in Latin letters; a skeleton under four letters (`Ali`) is left out, since it
would match too many names. A query of one name, or one name written as two words, is looked up
this way. Records indexed before this change gain their keys when they are next indexed (any change
to them, or a search backfill).

## Synonyms, stop words and pins

| Route | What it does |
|---|---|
| `GET`/`POST /api/v1/admin/search/synonyms`, `DELETE .../{id}` | Groups of words searched as one (`invoice`, `bill`, `فاتورة`). |
| `GET`/`POST /api/v1/admin/search/stopwords`, `DELETE .../{word}` | Words left out of queries. |
| `GET`/`POST /api/v1/admin/search/pins`, `DELETE .../{id}` | A record placed at a position for a query. A pin shows only to people who may read its record. |

## Counts and what people cannot see

Totals and facet counts are counted over the records the person may read, never over the whole
index: a count never reveals that hidden records match.

## Size, quality and status

`GET /api/v1/admin/search/size` gives the index size per entity, `.../quality` the queries that found
nothing or were abandoned, and `.../status` whether indexing keeps up with changes.
