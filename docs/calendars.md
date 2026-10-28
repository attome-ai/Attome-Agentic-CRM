# Business calendars

A business calendar says when work happens: its time zone, working days and hours, holidays and
exceptions. SLA clocks, due dates and business-time calculations count on it. Calendars are
metadata, changed through the admin API (`/api/v1/admin/calendars`) or the calendar manager
(the admin console's Calendars screen), in English or Arabic.

## What a calendar holds

- **Holidays and exceptions.** A holiday is a day off; an exception changes one date's hours.
- **Holiday rules.** A rule produces a holiday every year: a fixed Gregorian date, a weekday of a
  month, or a Hijri date (Umm al-Qura). `GET /api/v1/admin/calendars/{id}/holiday-rules/expanded`
  shows the dates a calendar's rules give for a year, in both calendars.
- **Seasons.** Working hours for part of the year, such as Ramadan or summer hours, by Gregorian
  or Hijri dates (`/api/v1/admin/calendars/{id}/seasons`).
- **Inheritance.** A calendar may name a parent; it takes the parent's holidays, rules and seasons
  and adds or overrides its own. A chain is at most three levels deep and never loops.
- **Versions.** Every change makes a new version, and an SLA clock records the version it was
  measured on, so a later change does not move an old deadline.

## Hijri dates and moon sightings

Hijri dates use the Umm al-Qura table, the one converter the platform has. A Hijri holiday that
waits for the moon sighting starts on its expected day until an administrator confirms the
announced start (`POST /api/v1/calendar-sightings`, at most three days from the expected one);
every calendar using the rule then moves the holiday. `GET /api/v1/calendar-sightings?year=` lists
the sightings expected in a year. Recurring Hijri holidays can also be written as RFC 7529
recurrences (`RSCALE=ISLAMIC-UMALQURA`).

## Country packs

`GET /api/v1/admin/calendars/packs` lists the official holiday packs (Saudi Arabia, the UAE and
Oman), each holiday citing the government text it comes from, and
`POST /api/v1/admin/calendars/packs/{code}/apply` creates or updates that country's calendar.
Working hours in a pack are a starting point (08:00 to 16:00); a re-applied pack leaves the hours
a deployment set. Every year a reminder asks an administrator to review the next year's Hijri
dates.

## Holiday feeds

A calendar can take holidays from an iCal feed (`POST /api/v1/calendar-feeds` with an `https`
URL on a public address; `GET /api/v1/calendar-feeds` lists them). A daily job fetches each feed,
reads its all-day events and keeps them in step; a holiday entered by hand or from a pack on the
same day is never overwritten.

## Who works to which calendar

A person's business time counts on their own calendar, else their team's, else the organization
default, with their leave on top. `PUT /api/v1/calendar-assignments/{subject_type}/{subject_id}`
(`user` or `team`) sets one.

## Calculations and agents

`POST /api/v1/calendars/{id}/calculate` adds business time to an instant (`add`), counts the
business time between two (`between`), finds the next working moment (`next`) or says whether an
instant is working time (`is_working`). An agent may read holidays
(`calendar.list_holidays`) and propose one (`calendar.propose_holiday`); an administrator
approves the proposal before it changes the calendar.
