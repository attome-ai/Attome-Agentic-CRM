# Data profiling

A profile describes what an entity's data actually looks like: how full each attribute is,
how many distinct values it has, its ranges and common values, the shapes its text takes,
Arabic-specific measures, and values that look like personal data. Profiles feed the data
catalogue, the field badges on the entity editor, quality rule proposals and drift alerts.
The newest profile shows on the data catalogue's entity page.

## Running a profile

`POST /api/v1/admin/data/profile` (administrators) queues a profile of one entity; the job
reads every attribute in one streamed scan with a 120-second statement limit. A table over
100,000 rows is sampled (`TABLESAMPLE SYSTEM`, aimed at 100,000 rows) unless the request asks
for `full_scan`; a sampled profile says how many rows it read. The row count is always exact.

A staged import can be profiled before it is committed: `POST /api/v1/data/profile:file`
`{import_job_id}` (the import's creator or an administrator, with `metadata.read` and read
access to its entity) profiles up to 100,000 of its staged rows with the same statistics and
masking.

Profiles can also run on a schedule: the setting `data_profile.schedule` maps an entity to a
cron expression in the deployment's time zone (empty by default). Completed and failed
profiles older than `data_profile.retention_days` (365) are deleted.

## What a profile holds

For every attribute: rows, nulls and their share, blanks, the distinct count (exact up to
100,000 values, then marked as a lower bound) and the ten most common values. Numbers add
minimum, maximum, mean, median, the 5th, 25th, 75th and 95th percentiles, a ten-bucket
histogram and outliers outside the interquartile range; dates add the earliest and latest;
text adds length statistics and the shortest and longest values.

Text attributes also get **shapes**: Western and Arabic-Indic digits become `9`, Latin
letters `A`, Arabic letters `ع`, and diacritics are dropped, so `0501234567` and `٠٥٠١٢٣٤٥٦٧`
are both `9999999999`. The ten commonest shapes are kept with their share, and, when the
attribute declares a format (`options.pattern`), the share of values matching it. The Arabic
measures count Arabic, Latin and mixed-script values, Eastern and Western digits, values with
diacritics, date-like values that read as Hijri or Gregorian, and, for name attributes, how
many parts the names have.

## Sensitive data stays masked

An attribute labelled sensitive (or classified above `general`) keeps only shapes: its common
values, minimum and maximum appear as shapes, never as values. Reading profiles needs
`metadata.read`; a person who is not an administrator sees only profiles of entities they may
read, and no statistics at all for a sensitive attribute they hold no field-read grant on
(its name does not appear either).

## Personal data found in plain attributes

Every text attribute with no label is checked for Saudi national IDs and iqama numbers (with
their checksum), IBANs (mod 97), phone numbers and email addresses. When more than 5% of an
attribute's non-blank values match, the profile opens a label proposal (`personal`) with the
counts only, never a value. Nothing is labelled automatically: a builder labels the attribute
or the proposal is resolved when a later profile stops finding it.
`GET /api/v1/admin/data/label-proposals` lists them.

## Drift

When a profile completes it is compared with the entity's previous one, attribute by
attribute: a null share up 10 points or more, a most common value the previous profile did
not list, or a changed top shape. Drift is stored on the profile and sent once per run to the
administrators. A failed drift check never fails the profile; file profiles are not compared.

## Agent tools

`profile.summary` returns the masked statistics of an entity's newest profile (counts and
fill rates for every readable attribute, ranges only for attributes that are neither
sensitive nor masked, never top values or examples). `profile.explain` adds a short
model-written explanation of that summary, within the AI budget.

## Routes

| Route | Who | Does |
|---|---|---|
| `POST /api/v1/admin/data/profile` | administrators | Profile an entity. |
| `GET /api/v1/admin/data/profile`, `GET /api/v1/admin/data/profile/{id}` | `metadata.read` | List and read profiles. |
| `POST /api/v1/data/profile:file` | the import's creator or an administrator | Profile a staged import. |
| `GET /api/v1/admin/data/label-proposals` | administrators | Personal-data label proposals. |
