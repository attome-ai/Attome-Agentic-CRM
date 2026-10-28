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

## Holidays on the Hijri calendar

`attome_calendar::rules::HolidayRule::Hijri { month, day, span_days }` names a holiday by its Hijri
date (Eid al-Fitr is month 10, day 1, three days). `rules::expand(rule, year)` gives the Gregorian
dates it closes in that year, expanding every Hijri year that overlaps it, so a rule can close two
stretches in one Gregorian year (1 Ramadan fell on 5 January and 26 December 2030) or none. A
`rules::Season` between two rules (Ramadan's first and last day) sets per-weekday hours, expanded
into one exception per working date with `rules::expand_season`.


## Country holiday packs

`GET /api/v1/admin/calendars/packs` lists the official holiday packs the server carries, and
`POST /api/v1/admin/calendars/packs/{code}/apply` applies one (administrators). Applying creates the
country's calendar, or finds the active calendar with that `country_code`, and writes the pack's
holiday rules through the same code as the holiday-rule route. A calendar that already exists keeps
its name, working days and hours, and only rules that differ are written, so a second apply
changes nothing. Inside an open changeset the apply is recorded as calendar and rule writes.

| Code | Country | Holidays | Source |
|---|---|---|---|
| `sa` | Saudi Arabia | Eid al-Fitr (4 days from the day after 29 Ramadan), Eid al-Adha (4 days from Arafat), Founding Day (22 February), National Day (23 September) | [HRSD](https://www.hrsd.gov.sa/en/knowledge-centre/articles/322); Founding Day by royal order |
| `ae` | United Arab Emirates | New Year, Eid al-Fitr (1 to 3 Shawwal, plus 30 Ramadan when there is one), Arafat Day, Eid al-Adha (10 to 12 Dhu al-Hijjah), Hijri New Year, the Prophet's Birthday, National Day (2 and 3 December) | Cabinet Resolution 27 of 2024, on [u.ae](https://u.ae/information-and-services/public-holidays-and-religious-affairs/public-holidays) |
| `om` | Oman | Eid al-Fitr (29 Ramadan to 3 Shawwal), Eid al-Adha (9 to 12 Dhu al-Hijjah), Hijri New Year, the Prophet's Birthday, Isra and Mi'raj, National Day (18 and 19 November), Accession Day (11 January) | [Royal Decree 88/2022](https://decree.om/2022/rd20220088/) |

The Eids (and Arafat Day) wait for the moon sighting: confirm the real first day with
`POST /api/v1/calendar-sightings` when it is announced. A pack's working hours, 08:00 to 16:00 on
the country's working days, are a starting point and not an official figure; change them on the
calendar. Ramadan hours are not in a pack, because the labour laws cap the hours of Muslim workers
without setting clock times; add a season for the hours your organisation keeps. Holidays a
government announces for one year only (extra Eid days, a moved National Day) are added as holidays
on the calendar. Kuwait, Qatar and Bahrain have no pack yet: no official text with their holiday
spans could be reached to cite.

Every December the yearly review sends each active administrator the expected first days of next
year's Hijri holidays on every calendar, to confirm or correct as the announcements come. It runs
once a year (the year is recorded in `calendar_review_notice`), in the default calendar's time zone.
