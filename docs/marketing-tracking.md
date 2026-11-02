# Website tracking

First-party tracking of visits to your own websites: which pages people read, where they came from,
and, once a visitor becomes a known contact or lead, their visits on that person's record. Everything is
served and stored by your deployment; nothing is sent elsewhere unless you configure a company lookup
provider. It belongs to the marketing pack.

## What is on, what is off

Every part has its own feature flag, all off by default, in this order:

| Flag | What it switches on |
|---|---|
| `marketing.tracking` | the script, collection, sessions, the tracking screen |
| `marketing.tracking_identify` | linking a visitor's sessions to the contact or lead they become |
| `marketing.tracking_company` | looking up the likely company of a visit (also needs the site's `company_recognition` and a provider) |
| `marketing.tracking_custom_events` | `window.attome.track(type, payload)` in the script |
| `marketing.tracking_alerts` | page-view alerts that start flows |

`marketing.tracking_external_sites` is registered too, but nothing reads it yet: a site's `domains` decide
where the script may report from.

## Setting up a site

1. Turn on `marketing.tracking`.
2. Add a **tracked site** (`marketing_tracked_site`; the tracking screen's "Tracked sites" link opens the list):
   its `name`, a `site_key`, its `domains` (the only origins whose batches are accepted), and optionally
   `excluded_paths`, `key_pages` (paths that matter, one per line), `office_networks` (addresses whose
   visits are dropped), `retention_days` (395 by default) and `enabled`.
3. Open **Marketing, Website tracking**, pick the site and copy the embed code onto every page, before
   `</body>`:

   ```html
   <script async src="https://<your deployment>/api/v1/track/script.js?site=<site key>"></script>
   ```

The script sends nothing until the visitor grants the analytics consent category (the consent banner's
`window.attomeConsent`, and it starts when the banner fires `attome:consent`), stays anonymous under
Global Privacy Control, keeps a first-party visitor cookie (`atm_vid`, 13 months) and a 30-minute session
cookie (`atm_sid`), never fingerprints a browser and loads nothing from anywhere else. A site that is
unknown or disabled, or a deployment with tracking off, gets the same 404 for the script.

## Collection

The script batches page views, page leaves and custom events to `POST /api/v1/track/collect`. The route
writes nothing itself: it checks the batch and queues a job. It accepts at most 30 batches a minute from
one visitor and 600 from one address, only from the site's domains, and answers 204 to every refusal but
the rate limit, so it reveals nothing about your sites. The client address is cut before anything else
sees it (IPv4 to its /24, IPv6 to its /48); the country comes only from a trusted edge's header.

The job drops the whole batch when the visitor is a crawler, a signed-in staff member, or inside an office
network, then writes the events (`marketing_web_event`, partitioned by month) and the session
(`marketing_web_session`: landing page, referrer, UTM values and click ids of its first page view). A
batch written twice changes nothing the second time.

## Known visitors

With `marketing.tracking_identify` on, when a visitor becomes known (a form, a tracked email click, a
portal sign-in, a chat) and has consented to marketing, their sessions are linked to the contact or lead
and the person's first and latest touch (source, medium, campaign, landing page) are written. Each
identified session that has been idle for 30 minutes becomes one **visit summary** on the person's
timeline: pages viewed, minutes on the site, key pages reached, source and campaign.

With `marketing.tracking_alerts` on, a **watched page** (`marketing_watched_page`: a site, a URL pattern
with `*`, an audience) starts the flows whose trigger is `web.page_viewed` when a known visitor views it,
once per session and page.

## Likely company

With `marketing.tracking_company` on, the site's `company_recognition` on and an integration connection
named `ip_company`, each session's truncated address is sent to that provider
(`GET {base_url}/{ip}`, answering `company.name` and `company.domain`, or top-level `name` and `domain`)
and the answer is kept on the session as `likely_company`, with `likely_account_ref` when exactly one
account has that `email_domain`. Answers are cached for 24 hours per address. It is never put on a
person: a network is not a named visitor.

## The tracking screen

**Marketing, Website tracking** (`marketing_tracked_site.read`) shows, per site, the embed code, visits
over 7, 30 or 90 days with how many were by known people and the top sources, landing pages and
campaigns, and who is on the site now (the last five minutes).

- `GET /api/v1/marketing/tracking/report?site=&days=`
- `GET /api/v1/marketing/tracking/live?site=`

## Retention and erasure

Each night, page views older than a site's `retention_days` become daily totals
(`marketing_web_daily`: views and sessions per day, page and campaign, with no person in them), whole
months of events are dropped once past the longest retention of any site, and sessions past their site's
retention are deleted. A site with a shorter retention than another keeps its raw events until the month
passes the longer one.

Erasing a contact or lead removes their sessions, every other session of the same visitor, those
sessions' events and their visit summaries.

While tracking is on and the privacy pack is installed, a draft records-of-processing entry named
"Website tracking" is created once for your privacy owner to review and complete.
