# The operations status page

Attome has two status pages. This one is the deployment's own operations view: what is working
right now for the people who use this deployment, driven by the capability probes the server
already runs. The other is the service module's public status page (`GET /api/v1/status`, the ITSM
pack's status records, with subscribers and a static copy), which an organisation keeps for its own
customers; this page does not replace it, and its public incidents will be published there (not
built yet).

Everything here is part of the `ops` module, which is off on a single server by default (V2-D100).
Turn the module on in Module Management first.

## What people see

- Every signed-in user sees the status bar at the top of the shell: the worst open incident, or
  maintenance starting within 24 hours, in their language. It is read once a minute while the tab is
  visible and can be dismissed; a new notice shows again.
- `GET /api/v1/ops/status` answers each component (sign-in, records, search, email, AI, portal,
  integrations) with its state, the open incidents and the maintenance not yet over. Internal
  incidents, internal maintenance and non-public components are shown only to holders of `ops.read`
  and to administrators.

A component's state comes from its capability probe (`ops_status_component.capability`): available
is operational, unavailable is down, and a probe that is switched off or not yet run is unknown.
Records is operational whenever the database answers. An open incident that lists a component makes
it at least as bad as the incident's impact (major: down; partial or degraded: degraded). The answer
is computed at most every 15 seconds on each server.

## Who does what

| Privilege | Role (attome-ops bundle) | May |
|---|---|---|
| `ops.read` | Operations, Auditor | see internal items, open and change incident drafts |
| `ops.incident.publish` | Operations | publish incident updates, plan, change and cancel maintenance |

Give the people who run incidents the Operations role. No AI action publishes: the `ops.status` and
`ops.draft_incident_update` actions read the status and suggest text, and a person publishes it.

## Running an incident

Open **Operations, Incidents** (`/xrm/ops/incidents`).

1. Create a draft: an English title (Arabic optional on the draft), the impact and the affected
   components. A draft is seen only by `ops.read` holders and is not on the status bar.
2. Publish updates. Each needs the text in English and in Arabic. The first update publishes the
   incident; its stage (investigating, identified, monitoring, resolved) moves the incident, and
   `note` adds text without moving it. Resolved closes the incident.
3. A published update is never edited. To fix one, use **Correct** on it: that publishes a new
   update naming the one it corrects, shown right after it.

Every change is in the audit log (`ops.incident_created`, `ops.incident_changed`,
`ops.incident_update_published`).

## Automatic drafts

With the setting `ops.status_watch` on (Settings, Operations), a job checks the components every
minute. A component down for three minutes gets one internal draft incident (titled in both
languages, impact major, marked automatic) unless an open incident already lists it. The time it
went down is kept in the database, so a restart does not reset the count.

`ops.status_auto_publish_minutes` (0, off, by default) publishes such a draft with an investigating
update in both languages once it is that many minutes old. Leave it at 0 if a person should always
decide what users read.

## Planned maintenance

Open **Operations, Maintenance** (`/xrm/ops/maintenance`). A window needs titles in both languages,
a start in the future and an end after it; choose whether everyone or only operations sees it.
Windows can be changed until they end and cancelled; each change is audited. The status bar
announces a window from 24 hours before it starts. `GET /api/v1/ops/maintenance?from=&to=` lists the
windows in a range (any signed-in user; internal windows for `ops.read`) and is what SLA reports
leave out.

## A copy hosted elsewhere

So customers can read the status while the deployment itself is down, a copy of the public status
can live outside it. Every minute (with the status watch job; `ops.status_watch` need not be on),
the public status is rendered as three files: `index.html` in English, `ar/index.html` in Arabic
(right to left) and `status.json`, with dates in Gregorian and Hijri. Only what anyone may read
goes in: public components, public incidents with their published updates, public maintenance.
When it changed since the last copy:

- `ops.status.bucket` (endpoint, region, bucket, optional folder) set: the three files are written
  to that bucket with `Cache-Control: max-age=60`. Its keys come from the JSON file named by
  `ops.status.bucket_credentials_file` (`{"access_key": "...", "secret_key": "..."}`), which stays
  on the server and out of the database. Point a static website or CDN at the bucket.
- `ops.status.webhook_url` set: `status.json` is POSTed there (public addresses only, 10-second
  timeout, three tries), for a status tool of your own.

A target that fails is logged (`status page: the hosted copy was not updated`) and tried again the
next minute.

## Not built yet

- Subscriptions (email, webhook, RSS) and the 24-hour and 1-hour maintenance reminders.
- Publishing public incidents and maintenance to the public status page.
