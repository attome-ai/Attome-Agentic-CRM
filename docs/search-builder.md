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
| `document_embedding`, `image_embedding` | Meaning search over the files attached to the entity's records, and over images; off by default. With `document_embedding` on, the passages of attached files are embedded and `POST /api/v1/search/similar` can return them. With `image_embedding` on and an image-text model configured, the image files of documents attached to the entity's records are embedded for image search (below). |

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

## Searching by meaning

The setting `search.semantic_entities` names entities whose records a full search also finds by
meaning; it is empty, and the feature off, by default. With an embedding model configured and
semantic search switched on, each of their records' indexed text (title, subtitle and indexed
fields) is embedded in the background, and a full search adds the records nearest the query to
the exact, prefix and word matches, ranked together. A changed record is embedded again. The
nearest 400 are taken before what the person may see is applied, so someone who sees little may
get fewer such matches; word matches are unaffected. Without a model, or when the query cannot be
embedded within two seconds, search works as before.

## Attached files

A file attached to a record (an `attome_document`: uploaded to the Documents library or to a file
field) is found by its text once its upload scan clears it: PDF, Word (`.docx`), Excel (`.xlsx`),
email (`.eml`) and plain text. A PDF that stores its text as glyph ids (many Arabic PDFs) yields
none and is found by its name only. A search result for a file names, in `page`, the PDF page the
query matches best, so the file can open there. A file shows only to someone who can read the
record it is attached to. A file uploaded to a field labelled sensitive (a confirmed Personal,
Financial, Health or Secret label) or encrypted is never indexed, split into passages or embedded.

`POST /api/v1/search/similar` takes one of `record` (`{entity, id}`; for a file, `attome_document`
and its id), `text` (up to 4,000 characters) or `image`, and returns the nearest passages the person
may read: records' long fields and, for entities with `document_embedding` on, their files' text,
each with its record, its source and its page. It needs the embedding model and semantic search,
like searching by meaning; without them it answers 503 `feature_unavailable`. Timeline items
(notes, communications) are not among its results.

### Images

Image search uses an image-text model that puts images and short texts in one space: SigLIP 2
(Apache-2.0, multilingual, Arabic included; V2-D1429), served inside the deployment by an
OpenAI-compatible server that takes a `modality`, such as Infinity, and named in
`inference.image_embedding`:

```json
"image_embedding": { "base_url": "http://127.0.0.1:7997/v1", "model": "google/siglip2-base-patch16-224" }
```

For entities with `image_embedding` on, the search indexer embeds each PNG, JPEG, WebP or GIF of at
most 5 MB that is a document attached to one of their records (migration 0346); a file on a field
labelled sensitive is never sent to the model. `/search/similar` then finds images with an `image`
(base64 or a `data:` URL), with `images: true` and a `text` describing them ("a cracked pump
housing"), or with `images: true` and a document's `record`. Each result names the document
(`source_id`, its name as `text`) under the record it is attached to, and only images whose record
the person may read are returned. Without the model an image search answers 503.

## Counts and what people cannot see

Totals and facet counts are counted over the records the person may read, never over the whole
index: a count never reveals that hidden records match.

## Size, quality and status

`GET /api/v1/admin/search/size` gives the index size per entity, `.../quality` the queries that found
nothing or were abandoned, and `.../status` whether indexing keeps up with changes.
