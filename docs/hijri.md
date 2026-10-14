# Hijri calendar

Attome stores every date as a Gregorian date and can show, enter, group and number dates in the
Umm al-Qura Hijri calendar, the official calendar of Saudi Arabia.

## The table

Umm al-Qura is a published table, not a formula: each month has 29 or 30 days as the table says.
Attome embeds it for 1356 to 1500 AH (13 March 1937 to 16 November 2077):

- `attome_calendar::hijri` in the server: `to_hijri`, `from_hijri`, `month_bounds`, `year_bounds`
  and month names in Arabic and English.
- The `hijri_month` table (migration 0021) for grouping in SQL: one row per month with its
  Gregorian first day and the day after its last.
- `web/projects/base/src/lib/hijri.ts` in the browser.

All three hold the same rows. Browsers' own `islamic-umalqura` calendar (ICU) is not used for
dates: it agrees with the published calendar only for 1420 to 1450 AH and differs by a day
elsewhere (1 Muharram 1400 was 20 November 1979; ICU says the 21st).

## Moon-sighting corrections

When a month starts on a different day than the table says, an administrator records it:

```http
PUT /api/v1/admin/hijri-months/1447/10
{"gregorian_start": "2026-03-21", "reason": "Supreme Court announcement"}
```

The month may move by one day at most, and it and the month before must stay 29 or 30 days long.
The change is audited (Configuration) and every node uses it within 20 seconds.
`GET /api/v1/admin/hijri-months?year=1447` lists a year as this deployment counts it.

## Where Hijri dates appear

| Where | How |
|---|---|
| Showing dates | Each person chooses `core.calendar` (gregorian, hijri, both) and `core.digits` (latn, arab) in Settings; an organization or the deployment can set the default. |
| A date attribute | Its `display_calendar` option (gregorian, hijri, both) wins over the person's choice. |
| Entering dates | A date field shown in Hijri also offers Hijri day, month and year entry; the value saved is the Gregorian date. |
| Reports and dashboards | Group a date by `hijri_month` or `hijri_year`; buckets are labelled `1447-09` and `1447`. |
| Autonumbers | `{hyyyy}`, `{hmm}` and `{hdd}` in a format, for example `INV-{hyyyy}-{####}`. |
| Holidays | A calendar holiday takes `hijri_date` instead of `holiday_date`; `POST /api/v1/admin/calendars/{id}/holidays/hijri-recurring` adds one holiday per Hijri year (up to 30), such as Eid al-Fitr on 1 Shawwal. |

## Limits

- Dates outside 1356 to 1500 AH have no Hijri form: autonumber tokens render zeros, the browser
  falls back to its own calendar for display, and Hijri entry refuses them.
- Years after 1450 AH are the table's prediction; corrections are expected as they are announced.
